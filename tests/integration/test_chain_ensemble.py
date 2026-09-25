"""Цепочка с ансамблем (US3): прогон, сводка по экспертам, повторяемость, отказ при битом эксперте,
выбор модели в CLI. Детектор 002 через ту же цепочку работает как раньше."""

import json
import shutil
from pathlib import Path

import polars as pl
import pytest
import yaml

from mlsiem import cli
from mlsiem.detect.artifact import DetectorLoadError
from mlsiem.soc import store
from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.soc.run import run_chain

REPO = Path(__file__).parents[2]


@pytest.fixture
def soc_cfg(tmp_path):
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    return parse_soc_config(
        {**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs")}
    )


def _run(cfg, model, data):
    return run_chain("split:unsw_time/test", cfg, model_dir=model, data_dir=data)


def _state(cfg, run_id):
    conn = store.connect(cfg.db)
    try:
        inc = conn.execute(
            "SELECT src_ip, attack_class, first_seen_ms, n_alerts, severity, targets "
            "FROM incidents WHERE run_id = ? ORDER BY src_ip, attack_class, first_seen_ms",
            (run_id,),
        ).fetchall()
        acts = conn.execute(
            "SELECT i.src_ip, i.attack_class, i.first_seen_ms, a.action_type, a.target, a.rule_id "
            "FROM actions a JOIN incidents i ON i.incident_id = a.incident_id WHERE i.run_id = ? "
            "ORDER BY 1, 2, 3",
            (run_id,),
        ).fetchall()
        alerts = conn.execute(
            "SELECT flow_uid, predicted_class, attack_score, fired_experts, experts, explanation "
            "FROM alerts WHERE run_id = ? ORDER BY flow_uid",
            (run_id,),
        ).fetchall()
        return [tuple(r) for r in inc], [tuple(r) for r in acts], [tuple(r) for r in alerts]
    finally:
        conn.close()


def test_run_with_ensemble(soc_cfg, synthetic_split, tiny_ensemble):
    s = _run(soc_cfg, tiny_ensemble, synthetic_split)
    card = json.loads((tiny_ensemble / "ensemble_card.json").read_text(encoding="utf-8"))
    assert s.detector_version == card["ensemble_version"]
    assert s.model.startswith("ансамбль") and "stack_logreg" in s.model
    assert s.direction_mode == "auto" and s.n_reversed == 0

    conn = store.connect(soc_cfg.db)
    run = store.get_run(conn, s.run_id)
    summary = run["summary"]
    for key in (
        "model",
        "experts",
        "experts_meta",
        "alerts_by_expert",
        "n_reversed",
        "direction_mode",
    ):
        assert key in summary
    assert run["detector_version"] == card["ensemble_version"]
    assert summary["model"] == {
        "kind": "ensemble",
        "version": card["ensemble_version"],
        "selected": "ensemble:stack_logreg",
        "experts": {e["name"]: e["version"] for e in card["experts"]},
    }
    assert set(summary["experts_meta"]) == {"classifier", "anomaly"}
    # алерт двух экспертов учтён у обоих: сумма по экспертам ≥ числа алертов с экспертами
    by = summary["alerts_by_expert"]
    assert set(by) <= {"classifier", "anomaly", "meta_only"}
    n_with = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE run_id = ? AND fired_experts != ''", (s.run_id,)
    ).fetchone()[0]
    assert by.get("classifier", 0) + by.get("anomaly", 0) >= n_with
    assert by.get("meta_only", 0) == s.n_alerts - n_with
    null_experts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE run_id = ? AND experts IS NULL", (s.run_id,)
    ).fetchone()[0]
    assert null_experts == 0
    conn.close()

    v = pl.read_parquet(soc_cfg.runs_dir / s.run_id / "verdicts.parquet")
    assert {"e_classifier_score", "e_anomaly_fired", "reversed"} <= set(v.columns)
    assert "explanation" not in v.columns


def test_repeat_same_result(soc_cfg, synthetic_split, tiny_ensemble):
    a = _run(soc_cfg, tiny_ensemble, synthetic_split)
    b = _run(soc_cfg, tiny_ensemble, synthetic_split)
    assert a.run_id != b.run_id
    assert _state(soc_cfg, a.run_id) == _state(soc_cfg, b.run_id)
    va = pl.read_parquet(soc_cfg.runs_dir / a.run_id / "verdicts.parquet")
    vb = pl.read_parquet(soc_cfg.runs_dir / b.run_id / "verdicts.parquet")
    assert va.equals(vb)


def test_broken_expert_refused_before_processing(soc_cfg, synthetic_split, tiny_ensemble, tmp_path):
    card = json.loads((tiny_ensemble / "ensemble_card.json").read_text(encoding="utf-8"))
    ens = tmp_path / "ens"
    shutil.copytree(tiny_ensemble, ens)
    anomaly = next(e for e in card["experts"] if e["name"] == "anomaly")
    broken = tmp_path / "anomaly"
    shutil.copytree(anomaly["path"], broken)
    (broken / "model.joblib").unlink()
    anomaly["path"] = broken.as_posix()
    (ens / "ensemble_card.json").write_text(json.dumps(card), encoding="utf-8")
    with pytest.raises(DetectorLoadError, match="anomaly"):
        _run(soc_cfg, ens, synthetic_split)
    assert not Path(soc_cfg.runs_dir).exists() or not any(Path(soc_cfg.runs_dir).iterdir())
    if Path(soc_cfg.db).exists():
        conn = store.connect(soc_cfg.db)
        store.init_db(conn)
        assert store.list_runs(conn) == []
        conn.close()


def test_detector_still_works(soc_cfg, synthetic_split, tiny_detector):
    s = _run(soc_cfg, tiny_detector, synthetic_split)
    assert s.model.startswith("детектор")
    assert s.alerts_by_expert == {"classifier": s.n_alerts}
    conn = store.connect(soc_cfg.db)
    assert store.get_run(conn, s.run_id)["model"]["kind"] == "detector"
    conn.close()


# ---------------------------------------------------------------- CLI (T043)


def _cli_config(soc_cfg, tmp_path) -> Path:
    raw = dict(soc_cfg.raw)
    raw.update(db=str(soc_cfg.db), runs_dir=str(soc_cfg.runs_dir))
    path = tmp_path / "soc.yaml"
    path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    return path


def _soc_run(cfg_path, data, *extra):
    return cli.main(
        [
            "soc",
            "--config",
            str(cfg_path),
            "run",
            "--split",
            "unsw_time",
            "--part",
            "test",
            "--data-dir",
            str(data),
            *extra,
        ]
    )


def test_cli_model_and_alias(
    soc_cfg, synthetic_split, tiny_ensemble, tiny_detector, tmp_path, capsys
):
    cfg_path = _cli_config(soc_cfg, tmp_path)
    assert _soc_run(cfg_path, synthetic_split, "--model", str(tiny_ensemble)) == 0
    out = capsys.readouterr().out
    assert "модель: ансамбль" in out
    assert "алертов по экспертам" in out and "ответных потоков" in out
    assert _soc_run(cfg_path, synthetic_split, "--detector", str(tiny_detector)) == 0
    assert "модель: детектор" in capsys.readouterr().out


def test_cli_default_model(
    soc_cfg, synthetic_split, tiny_ensemble, tiny_detector, tmp_path, monkeypatch, capsys
):
    cfg_path = _cli_config(soc_cfg, tmp_path)
    monkeypatch.setattr(cli, "DEFAULT_ENSEMBLE", tmp_path / "no_ensemble")
    monkeypatch.setattr(cli, "DEFAULT_DETECTOR", tiny_detector)
    assert _soc_run(cfg_path, synthetic_split) == 0
    cap = capsys.readouterr()
    assert "Ансамбль не обучен" in cap.err and "модель: детектор" in cap.out
    monkeypatch.setattr(cli, "DEFAULT_ENSEMBLE", tiny_ensemble)
    assert _soc_run(cfg_path, synthetic_split) == 0
    cap = capsys.readouterr()
    assert "модель: ансамбль" in cap.out and "Ансамбль не обучен" not in cap.err
