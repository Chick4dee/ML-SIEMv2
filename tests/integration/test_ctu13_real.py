"""Медленный тест на настоящем сценарии CTU-13 №7 (запуск: `uv run pytest -m slow`)."""

from pathlib import Path

import pytest

from mlsiem.data.config import load_config
from mlsiem.data.pipeline import run_flows

REPO = Path(__file__).parents[2]


@pytest.mark.slow
def test_ctu13_scenario_7(tmp_path):
    cfg = load_config(REPO / "configs" / "data.yaml")
    if not (cfg.ctu13.root / "7").is_dir():
        pytest.skip("датасет CTU-13 недоступен")
    summary = run_flows(cfg, "ctu13", only=["ctu13_07"], data_dir=tmp_path)
    row = next(r for r in summary.rows if r["capture_id"] == "ctu13_07")
    assert row["status"] == "done"
    assert row["n_flows"] == 51
    assert row["match_rate"] >= 0.85
