"""Эксперимент на реальных данных 001 (SC-001). Долго: минуты на обучение обоих кандидатов."""

from pathlib import Path

import pytest

from mlsiem.data.schema import SCHEMA

REPO = Path(__file__).parents[2]
DATA = REPO / "data"


@pytest.mark.slow
def test_experiment_real(tmp_path):
    from mlsiem.detect.config import load_detect_config, parse_detect_config
    from mlsiem.detect.experiment import run_experiment

    if not (DATA / "splits" / "unsw_time.parquet").exists():
        pytest.skip("нет данных 001: сначала `uv run mlsiem data all`")
    raw = load_detect_config(REPO / "configs" / "detect.yaml").raw
    cfg = parse_detect_config({**raw, "output": str(tmp_path / "detector")})
    exp = run_experiment(cfg, data_dir=DATA, reports_dir=tmp_path, mlflow_dir=tmp_path)

    win = next(c for c in exp["candidates"] if c["name"] == exp["winner"])
    base = next(c for c in exp["candidates"] if c["name"] == "logreg")
    # Победитель лучше угадывания по доле классов и не хуже бейзлайна на test
    assert win["test"]["macro_pr_auc"] > exp["prior_baseline"]["test"]["macro_pr_auc"]
    assert win["test"]["macro_pr_auc"] >= base["test"]["macro_pr_auc"] - 0.01
    # В модель не попало ни одно поле identity/time/dpi
    import json

    card = json.loads((tmp_path / "detector" / "model_card.json").read_text(encoding="utf-8"))
    forbidden = {c for g in ("identity", "time", "dpi", "label") for c in SCHEMA.columns_of(g)}
    assert not forbidden & set(card["features"])
    assert card["features"] == SCHEMA.feature_columns()
