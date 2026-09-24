"""Эксперимент целиком на синтетике: файлы, поля, воспроизводимость, MLflow (US1, SC-002)."""

import json

import pytest

from mlsiem.detect.artifact import load_detector
from mlsiem.detect.config import parse_detect_config
from mlsiem.detect.experiment import run_experiment


def small_config(output) -> dict:
    """Конфиг как в репозитории, но с маленькими моделями — чтобы тест шёл секунды."""
    return {
        "split": "unsw_time",
        "transfer_split": "unsw_cross_day",
        "seed": 42,
        "selection": {"metric": "macro_pr_auc_val", "min_gain": 0.01},
        "candidates": {
            "logreg": {"C": 1.0, "max_iter": 300, "class_weight": "balanced"},
            "lgbm": {
                "n_estimators": 30,
                "learning_rate": 0.1,
                "num_leaves": 15,
                "class_weight": "balanced",
            },
        },
        "output": str(output),
    }


def _metrics_only(exp: dict) -> list:
    """Всё, что должно совпасть при повторе (без времени обучения и id runs MLflow)."""
    return [(c["name"], c["threshold"], c["val"], c["test"]) for c in exp["candidates"]] + [
        exp["prior_baseline"],
        exp["winner"],
        exp["transfer"],
        exp["detector_version"],
    ]


@pytest.fixture(scope="module")
def two_runs(synthetic_split, tmp_path_factory):
    root = tmp_path_factory.mktemp("experiment")
    runs = []
    for i in range(2):
        cfg = parse_detect_config(small_config(root / f"detector{i}"))
        exp = run_experiment(
            cfg, data_dir=synthetic_split, reports_dir=root / f"reports{i}", mlflow_dir=root / "ml"
        )
        runs.append((exp, root / f"detector{i}", root / f"reports{i}"))
    return root, runs


def test_files_created(two_runs):
    _, runs = two_runs
    _, out, reports = runs[0]
    for name in ("model.joblib", "model_card.json", "experiment.json"):
        assert (out / name).exists()
    report = (reports / "detector_experiment.md").read_text(encoding="utf-8")
    assert "logreg" in report and "lgbm" in report and "prior" in report
    assert "Победитель" in report


def test_experiment_json_fields(two_runs):
    _, runs = two_runs
    exp = json.loads((runs[0][1] / "experiment.json").read_text(encoding="utf-8"))
    assert [c["name"] for c in exp["candidates"]] == ["logreg", "lgbm"]
    for c in exp["candidates"]:
        for part in ("val", "test"):
            assert 0 <= c[part]["macro_pr_auc"] <= 1
            assert set(c[part]["per_class"]) == set(c["classes"])
    assert exp["prior_baseline"]["test"]["macro_pr_auc"] > 0
    assert exp["selection_rule"]["min_gain"] == 0.01
    assert exp["winner"] in ("logreg", "lgbm")
    assert set(exp["classes_without_examples"]) == {"val", "test", "transfer_test"}
    # На синтетике со сдвинутыми признаками детектор обязан обгонять угадывание
    win = next(c for c in exp["candidates"] if c["name"] == exp["winner"])
    assert win["test"]["macro_pr_auc"] > exp["prior_baseline"]["test"]["macro_pr_auc"]


def test_model_card(two_runs):
    _, runs = two_runs
    det = load_detector(runs[0][1])
    card = det.card
    assert card["metrics"]["transfer_test"]["split"] == "unsw_cross_day"
    assert "macro_pr_auc" in card["metrics"]["transfer_test"]
    assert card["data"]["split_hash"] and card["data"]["input_hashes"]
    assert card["seed"] == 42
    assert "lightgbm" in card["libraries"]
    assert card["mlflow_run_id"]
    assert 0 < det.threshold <= 1


def test_reproducible(two_runs):
    _, runs = two_runs
    assert _metrics_only(runs[0][0]) == _metrics_only(runs[1][0])


def test_mlflow_runs(two_runs):
    import mlflow

    root, runs = two_runs
    mlflow.set_tracking_uri("sqlite:///" + (root / "ml" / "mlflow.db").resolve().as_posix())
    found = mlflow.search_runs(experiment_names=["detector"], output_format="list")
    assert len(found) == 4  # 2 кандидата × 2 запуска
    run = next(r for r in found if r.info.run_id == runs[0][0]["candidates"][1]["mlflow_run_id"])
    assert run.data.params["candidate"] == "lgbm"
    assert run.data.params["seed"] == "42"
    assert "val_macro_pr_auc" in run.data.metrics
    assert "test_macro_pr_auc" in run.data.metrics
    assert run.data.tags["split_hash"] == runs[0][0]["data"]["split_hash"]
    assert run.data.tags["schema_version"]
