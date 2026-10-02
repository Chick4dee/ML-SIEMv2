"""Эксперт окон в пакетном прогоне (фича 007, US3, R12, SC-008).

Модель окон — `tiny_windows` (lgbm на синтетике, `accepted: false`), поэтому интеграция
проверяется режимом `force`, как `force_variant` в 004; режим auto с непринятой моделью
обязан дать ровно то же, что прогон без эксперта окон.
"""

import json
import shutil
from pathlib import Path

import polars as pl
import pytest
import yaml

from mlsiem.cli import main
from mlsiem.soc import store
from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.soc.run import run_chain

REPO = Path(__file__).parents[2]


def _cfg(tmp_path, **windows):
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    w = {**raw["windows"], **windows}
    return parse_soc_config(
        {**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs"), "windows": w}
    )


def _run(cfg, tiny_detector, synthetic_split, mode, model):
    return run_chain(
        "split:unsw_time/test",
        cfg,
        model_dir=tiny_detector,
        data_dir=synthetic_split,
        windows_mode=mode,
        windows_model=model,
    )


def _incident_sigs(cfg, run_id):
    conn = store.connect(cfg.db)
    try:
        rows = conn.execute(
            "SELECT src_ip, attack_class, first_seen_ms, last_seen_ms, n_alerts, severity "
            "FROM incidents WHERE run_id = ? ORDER BY 1, 2, 3",
            (run_id,),
        ).fetchall()
        return [tuple(r) for r in rows]
    finally:
        conn.close()


def test_force_adds_window_alerts(tmp_path, tiny_detector, tiny_windows, synthetic_split):
    cfg = _cfg(tmp_path)
    s = _run(cfg, tiny_detector, synthetic_split, "force", tiny_windows)
    wp = s.run_dir / "windows.parquet"
    assert wp.exists()
    wv = pl.read_parquet(wp)
    assert {"window_id", "attack_score", "is_alert", "predicted_class", "true_label"} <= set(
        wv.columns
    )
    sec = s.windows
    assert sec["enabled"] and sec["mode"] == "force" and not sec["accepted"]
    assert sec["n_windows"] == wv.height and sec["n_window_alerts"] == int(wv["is_alert"].sum())
    assert sec["n_window_alerts"] > 0
    assert "принудительно" in s.windows_line
    conn = store.connect(cfg.db)
    try:
        run = store.get_run(conn, s.run_id)
        assert run["summary"]["windows"]["n_window_alerts"] == sec["n_window_alerts"]
        rows = conn.execute(
            "SELECT * FROM alerts WHERE run_id = ? AND alert_kind = 'window'", (s.run_id,)
        ).fetchall()
        assert len(rows) == sec["n_window_alerts"]
        a = store.alert_row(rows[0])
        assert a["flow_uid"].startswith("w-") and a["src_port"] is None and a["protocol"] is None
        assert a["fired_experts"] == ["windows"] and a["experts"]["windows"]["fired"]
        info = a["window_info"]
        assert info["window_id"] == a["flow_uid"] and len(info["top_flows"]) <= 20
        assert len(info["top_features"]) <= 5 and info["kind"] == "lgbm"
        assert a["src_ip"] == a["attacker_ip"] and a["dst_ip"] == info["targets"][0]["ip"]
        # Алерты окон сгруппированы вместе с алертами потоков: инцидентов с обоими видами > 0
        mixed = conn.execute(
            "SELECT COUNT(*) FROM (SELECT incident_id FROM alerts WHERE run_id = ? "
            "GROUP BY incident_id HAVING COUNT(DISTINCT alert_kind) = 2)",
            (s.run_id,),
        ).fetchone()[0]
        assert mixed > 0
    finally:
        conn.close()


def test_auto_not_accepted_same_as_without(tmp_path, tiny_detector, tiny_windows, synthetic_split):
    """SC-008: непринятая модель в auto — те же инциденты, что при off; алертов окон нет."""
    cfg = _cfg(tmp_path)
    auto = _run(cfg, tiny_detector, synthetic_split, "auto", tiny_windows)
    off = _run(cfg, tiny_detector, synthetic_split, "off", tiny_windows)
    assert not auto.windows["enabled"] and "не принят" in auto.windows["reason"]
    assert _incident_sigs(cfg, auto.run_id) == _incident_sigs(cfg, off.run_id)
    assert not (auto.run_dir / "windows.parquet").exists()


def test_accepted_model_is_enabled_in_auto(tmp_path, tiny_detector, tiny_windows, synthetic_split):
    model = tmp_path / "accepted"
    shutil.copytree(tiny_windows, model)
    card = json.loads((model / "window_card.json").read_text(encoding="utf-8"))
    card["decision"]["accepted"] = True
    (model / "window_card.json").write_text(json.dumps(card), encoding="utf-8")
    s = _run(_cfg(tmp_path), tiny_detector, synthetic_split, "auto", model)
    assert s.windows["enabled"] and s.windows["accepted"]
    assert "принудительно" not in s.windows_line


@pytest.mark.parametrize(
    ("override", "match"),
    [({"length_ms": 30000}, "30000"), ({"direction": "as_is"}, "направления")],
)
def test_mismatch_refused_nothing_written(
    tmp_path, tiny_detector, tiny_windows, synthetic_split, override, match
):
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    if "length_ms" in override:
        raw = {**raw, "windows": {**raw["windows"], "length_ms": override["length_ms"]}}
    else:
        raw = {**raw, "grouping": {**raw["grouping"], "direction": override["direction"]}}
    raw = {**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs")}
    path = tmp_path / "soc.yaml"
    path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    code = main(
        [
            "soc",
            "--config",
            str(path),
            "run",
            "--split",
            "unsw_time",
            "--part",
            "test",
            "--data-dir",
            str(synthetic_split),
            "--model",
            str(tiny_detector),
            "--windows",
            "force",
            "--windows-model",
            str(tiny_windows),
        ]
    )
    assert code == 1
    assert not (tmp_path / "soc.db").exists() or not store.list_runs(
        store.connect(tmp_path / "soc.db")
    )
    assert not (tmp_path / "runs").exists() or not any((tmp_path / "runs").iterdir())


def test_cli_prints_windows_line(tmp_path, tiny_detector, tiny_windows, synthetic_split, capsys):
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    raw = {**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs")}
    path = tmp_path / "soc.yaml"
    path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    code = main(
        [
            "soc",
            "--config",
            str(path),
            "run",
            "--split",
            "unsw_time",
            "--part",
            "test",
            "--data-dir",
            str(synthetic_split),
            "--model",
            str(tiny_detector),
            "--windows",
            "force",
            "--windows-model",
            str(tiny_windows),
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "алертов окон" in out and "эксперт окон lgbm" in out
