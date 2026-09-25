"""Реальный ансамбль на полных данных (`-m slow`): карточки и прогон test (SC-002–SC-004).

Нужны артефакты `uv run mlsiem detect ensemble` (models/ensemble, models/experts/anomaly) и
данные 001. Тест не переобучает модели — он проверяет то, что лежит в models/.
"""

import json
import time
from pathlib import Path

import polars as pl
import pytest

from mlsiem.data.schema import SCHEMA
from mlsiem.soc import store
from mlsiem.soc.config import load_soc_config, parse_soc_config

REPO = Path(__file__).parents[2]
ENSEMBLE = REPO / "models" / "ensemble"
ANOMALY = REPO / "models" / "experts" / "anomaly"


def _need_artifacts():
    if not (ENSEMBLE / "ensemble_card.json").exists():
        pytest.skip("нет ансамбля: сначала `uv run mlsiem detect ensemble`")


@pytest.mark.slow
def test_cards_valid():
    _need_artifacts()
    from mlsiem.detect.anomaly import load_anomaly_expert
    from mlsiem.detect.ensemble import load_model

    card = json.loads((ENSEMBLE / "ensemble_card.json").read_text(encoding="utf-8"))
    assert card["selection"]["condition"] in ("macro_gain", "unknown_gain", "none")
    assert card["selection"]["forced"] is False
    expert = load_anomaly_expert(ANOMALY)
    assert expert.card["train"]["benign_only"] is True
    assert set(expert.features) <= set(SCHEMA.feature_columns())
    # бюджет ложных срабатываний на норме val соблюдён (FR-003)
    assert expert.card["metrics"]["val"]["benign_above_threshold"] <= expert.card["anomaly_fpr"]
    model = load_model(ENSEMBLE)
    assert model.version == card["ensemble_version"]
    exp = json.loads((ENSEMBLE / "experiment.json").read_text(encoding="utf-8"))
    clf = exp["variants"][0]
    # FR-002: классификатор тот же, что в 002
    det = json.loads((REPO / "models" / "detector" / "model_card.json").read_text("utf-8"))
    assert clf["val"]["macro_pr_auc"] == pytest.approx(det["metrics"]["val"]["macro_pr_auc"])
    assert clf["test"]["macro_pr_auc"] == pytest.approx(det["metrics"]["test"]["macro_pr_auc"])


@pytest.mark.slow
def test_run_real_with_ensemble(tmp_path):
    _need_artifacts()
    from mlsiem.soc.run import run_chain

    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    cfg = parse_soc_config(
        {**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs")}
    )
    started = time.perf_counter()
    s1 = run_chain("split:unsw_time/test", cfg, model_dir=ENSEMBLE, data_dir=REPO / "data")
    seconds = time.perf_counter() - started
    assert seconds <= 15 * 60, f"прогон шёл {seconds:.0f} с — дольше 15 минут (SC-004)"

    # SC-002: норма test, ставшая алертом ТОЛЬКО из-за детектора аномалий, ≤ 1%
    v1 = pl.read_parquet(cfg.runs_dir / s1.run_id / "verdicts.parquet")
    if "e_anomaly_fired" in v1.columns:
        benign = v1.filter(pl.col("true_label") == "benign")
        only_a = benign.filter(
            pl.col("is_alert") & pl.col("e_anomaly_fired") & ~pl.col("e_classifier_fired")
        )
        assert only_a.height / benign.height <= 0.01

    # SC-003: повтор — те же вердикты и инциденты
    s2 = run_chain("split:unsw_time/test", cfg, model_dir=ENSEMBLE, data_dir=REPO / "data")
    v2 = pl.read_parquet(cfg.runs_dir / s2.run_id / "verdicts.parquet")
    assert v1.equals(v2)
    conn = store.connect(cfg.db)
    q = (
        "SELECT src_ip, attack_class, first_seen_ms, n_alerts, severity FROM incidents "
        "WHERE run_id = ? ORDER BY src_ip, attack_class, first_seen_ms"
    )
    assert conn.execute(q, (s1.run_id,)).fetchall() == conn.execute(q, (s2.run_id,)).fetchall()
    conn.close()
