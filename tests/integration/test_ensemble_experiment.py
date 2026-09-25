"""Эксперимент 004 целиком на синтетике: файлы, поля, воспроизводимость, ловушка на test, CLI.

Маленький конфиг (мало деревьев, крошечная подвыборка нормы, 3 блока OOF) — тест идёт
секунды, а код тот же, что в бою.
"""

import json

import numpy as np
import pytest
import yaml

from fixtures.small_configs import small_ensemble_raw
from mlsiem.cli import main
from mlsiem.detect import ensemble as ens
from mlsiem.detect.artifact import load_detector
from mlsiem.detect.config import parse_ensemble_config
from mlsiem.detect.ensemble import run_ensemble_experiment

VARIANTS = ["classifier", "any_fired", "mean_score", "stack_logreg"]


def _run(root, detector, data, name):
    cfg = parse_ensemble_config(small_ensemble_raw(detector, root / name))
    exp = run_ensemble_experiment(
        cfg, data_dir=data, reports_dir=root / name / "reports", mlflow_dir=root / "ml"
    )
    return exp, root / name


@pytest.fixture(scope="module")
def two_runs(synthetic_split, tiny_detector, tmp_path_factory):
    root = tmp_path_factory.mktemp("ens_exp")
    return [_run(root, tiny_detector, synthetic_split, f"r{i}") for i in range(2)]


def _essence(exp):
    """Всё, что обязано совпасть при повторе (без времени и id runs MLflow)."""
    return (
        exp["ensemble_version"],
        [(v["name"], v["threshold"], v["val"], v["test"]) for v in exp["variants"]],
        exp["hidden_class"],
        exp["selection"],
        [
            (c["name"], c["threshold"], c["val"], c["test"])
            for c in exp["experts"]["anomaly"]["candidates"]
        ],
    )


def test_files(two_runs):
    exp, out = two_runs[0]
    for f in ("ensemble_card.json", "experiment.json"):
        assert (out / "ensemble" / f).exists()
    for f in ("model.joblib", "calibration.npy", "expert_card.json"):
        assert (out / "experts" / "anomaly" / f).exists()
    report = (out / "reports" / "ensemble_experiment.md").read_text(encoding="utf-8")
    for section in (
        "## Варианты",
        "## PR-AUC по классам",
        "## Скрытый класс",
        "## Выбор",
        "## Детектор аномалий: кандидаты",
        "## Аудит артефактов",
        "## Схема данных",
    ):
        assert section in report


def test_variants_table(two_runs, tiny_detector):
    exp, _ = two_runs[0]
    assert [v["name"] for v in exp["variants"]] == VARIANTS
    det = load_detector(tiny_detector)
    for v in exp["variants"]:
        for part in ("val", "test"):
            assert 0 <= v[part]["macro_pr_auc"] <= 1
            assert set(v[part]["per_class"]) == set(det.classes)
            assert "pr_auc_binary" in v[part]
    # FR-002: классификатор тот же — его метрики равны метрикам карточки 002
    clf = exp["variants"][0]
    for part in ("val", "test"):
        assert clf[part]["macro_pr_auc"] == pytest.approx(det.card["metrics"][part]["macro_pr_auc"])
        assert clf[part]["per_class"] == pytest.approx(det.card["metrics"][part]["per_class"])
    assert clf["threshold"] == det.threshold


def test_scheme_selection_unreliable(two_runs):
    exp, out = two_runs[0]
    card = json.loads((out / "ensemble" / "ensemble_card.json").read_text(encoding="utf-8"))
    for key in ("experts", "meta", "test", "threshold", "selection"):
        assert key in card["data_scheme"]
    assert "train" in card["data_scheme"]["experts"]
    assert "out-of-fold" in card["data_scheme"]["meta"]
    assert exp["selection"]["condition"] in ("macro_gain", "unknown_gain", "none")
    assert card["selection"]["condition"] == exp["selection"]["condition"]
    assert card["selected"] == exp["selection"]["selected"]
    assert card["selection"]["forced"] is False
    # на синтетике каждого класса атак в val меньше 50 — все помечены «ненадёжен»
    assert exp["unreliable_classes"]["val"]
    assert {e["name"] for e in card["experts"]} == {"classifier", "anomaly"}


def test_reproducible(two_runs):
    (a, _), (b, _) = two_runs
    assert _essence(a) == _essence(b)


def test_test_labels_do_not_affect_choices(
    synthetic_split, tiny_detector, tmp_path, monkeypatch, two_runs
):
    """Ловушка: метки test заменены случайными — пороги и выбор обязаны остаться прежними."""
    real = ens.load_part

    def shuffled(split, part, **kw):
        p = real(split, part, **kw)
        if part == "test":
            rng = np.random.default_rng(0)
            p.y = rng.choice(np.unique(p.y), size=len(p.y))
        return p

    monkeypatch.setattr(ens, "load_part", shuffled)
    exp, _ = _run(tmp_path, tiny_detector, synthetic_split, "trap")
    ref, _ = two_runs[0]
    assert exp["selection"]["selected"] == ref["selection"]["selected"]
    assert [v["threshold"] for v in exp["variants"]] == [v["threshold"] for v in ref["variants"]]
    assert [h["classifier_threshold"] for h in exp["hidden_class"]] == [
        h["classifier_threshold"] for h in ref["hidden_class"]
    ]
    an, an_ref = exp["experts"]["anomaly"], ref["experts"]["anomaly"]
    assert an["winner"] == an_ref["winner"]
    assert [c["threshold"] for c in an["candidates"]] == [
        c["threshold"] for c in an_ref["candidates"]
    ]


# ---------------------------------------------------------------- US2 (T037)


def test_anomaly_section_and_audit(two_runs):
    exp, out = two_runs[0]
    an = exp["experts"]["anomaly"]
    assert [c["name"] for c in an["candidates"]] == ["iforest", "autoencoder"]
    for c in an["candidates"]:
        for part in ("val", "test"):
            assert "pr_auc_binary" in c[part] and "benign_above_threshold" in c[part]
        # бюджет ложных срабатываний на норме val соблюдён
        assert c["val"]["benign_above_threshold"] <= 0.02
    assert an["winner"] in ("iforest", "autoencoder")
    card = json.loads(
        (out / "experts" / "anomaly" / "expert_card.json").read_text(encoding="utf-8")
    )
    assert card["candidate"] == an["winner"]
    audit = card["audit"]
    assert {"probe_top", "flagged_features", "permutation", "text"} <= set(audit)
    assert exp["audit"]["anomaly"] == audit
    assert "by_expert" in exp["audit"]["meta"]


# ---------------------------------------------------------------- CLI (T022)


def _cli(tmp_path, data, raw, capsys):
    cfg_path = tmp_path / "ensemble.yaml"
    cfg_path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    code = main(
        [
            "detect",
            "--data-dir",
            str(data),
            "ensemble",
            "--config",
            str(cfg_path),
            "--reports-dir",
            str(tmp_path / "reports"),
            "--mlflow-dir",
            str(tmp_path),
        ]
    )
    return code, capsys.readouterr()


def test_cli_ok(synthetic_split, tiny_detector, tmp_path, capsys):
    code, out = _cli(tmp_path, synthetic_split, small_ensemble_raw(tiny_detector, tmp_path), capsys)
    assert code == 0
    for text in ("stack_logreg", "any_fired", "Скрытый класс", "exploits", "Выбрано:", "условие"):
        assert text in out.out


def test_cli_no_classifier(synthetic_split, tmp_path, capsys):
    raw = small_ensemble_raw(tmp_path / "nope", tmp_path)
    code, out = _cli(tmp_path, synthetic_split, raw, capsys)
    assert code == 1
    assert "detect train" in out.err
    assert not (tmp_path / "ensemble").exists()


def test_cli_bad_config(synthetic_split, tiny_detector, tmp_path, capsys):
    raw = small_ensemble_raw(tiny_detector, tmp_path)
    raw["meta"]["folds"] = 1
    code, out = _cli(tmp_path, synthetic_split, raw, capsys)
    assert code == 1
    assert "folds" in out.err
