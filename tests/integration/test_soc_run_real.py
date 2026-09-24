"""Прогон полного test `unsw_time` реальным детектором (SC-002, SC-003, SC-004)."""

import time
from pathlib import Path

import psutil
import pytest

from mlsiem.soc import store
from mlsiem.soc.config import load_soc_config, parse_soc_config

REPO = Path(__file__).parents[2]
DETECTOR = REPO / "models" / "detector"


def _peak_rss_gb() -> float:
    info = psutil.Process().memory_info()
    # На Windows есть настоящий пик рабочего набора; на других ОС — текущий RSS как оценка
    return getattr(info, "peak_wset", info.rss) / 1024**3


@pytest.mark.slow
def test_run_real_test_part(tmp_path):
    from mlsiem.soc.run import run_chain

    if not (DETECTOR / "model.joblib").exists():
        pytest.skip("нет детектора: сначала `uv run mlsiem detect train`")
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    cfg = parse_soc_config(
        {**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs")}
    )

    started = time.perf_counter()
    s1 = run_chain("split:unsw_time/test", cfg, detector_dir=DETECTOR, data_dir=REPO / "data")
    seconds = time.perf_counter() - started
    assert seconds <= 15 * 60, f"прогон шёл {seconds:.0f} с — дольше 15 минут (SC-003)"
    assert _peak_rss_gb() <= 16, "пик памяти больше 16 ГБ (SC-003)"

    # SC-004: инцидентов минимум в 10 раз меньше алертов, каждый алерт ровно в одном инциденте
    assert s1.n_incidents * 10 <= s1.n_alerts
    conn = store.connect(cfg.db)
    in_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE run_id = ?", (s1.run_id,)
    ).fetchone()[0]
    in_incidents = conn.execute(
        "SELECT SUM(n_alerts) FROM incidents WHERE run_id = ?", (s1.run_id,)
    ).fetchone()[0]
    assert in_alerts == in_incidents == s1.n_alerts

    # SC-002: повтор — те же вердикты и инциденты
    s2 = run_chain("split:unsw_time/test", cfg, detector_dir=DETECTOR, data_dir=REPO / "data")
    import polars as pl

    v1 = pl.read_parquet(cfg.runs_dir / s1.run_id / "verdicts.parquet")
    v2 = pl.read_parquet(cfg.runs_dir / s2.run_id / "verdicts.parquet")
    assert v1.equals(v2)
    q = (
        "SELECT src_ip, attack_class, first_seen_ms, n_alerts, severity FROM incidents "
        "WHERE run_id = ? ORDER BY src_ip, attack_class, first_seen_ms"
    )
    assert conn.execute(q, (s1.run_id,)).fetchall() == conn.execute(q, (s2.run_id,)).fetchall()
    conn.close()
