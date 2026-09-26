"""Показатели потока (US5, FR-022, research R11): окно задержек, скорость, отставание, хранение."""

from pathlib import Path

import pytest

from mlsiem.soc import store
from mlsiem.stream.broker import MemoryBroker, MemoryCluster, TopicSpec
from mlsiem.stream.config import load_stream_config
from mlsiem.stream.stats import StatsWindow, lag_messages, percentile, status_report


class Clock:
    def __init__(self, t=1_000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_percentile_nearest_rank():
    assert percentile([], 50) is None
    assert percentile([5], 95) == 5
    vals = list(range(1, 101))
    assert percentile(vals, 50) == 50 and percentile(vals, 95) == 95


def test_window_latency_rate_and_expiry():
    clock = Clock()
    w = StatsWindow(clock=clock, window_s=60)
    w.add(processed=100, latencies_ms=[100.0] * 19 + [900.0], late=2, last_sent_at_ms=999_500)
    clock.t += 10
    w.add(processed=100, latencies_ms=[200.0] * 20, rejected=1)
    snap = w.snapshot(lag_messages=7)
    assert snap["processed"] == 200
    assert snap["rate_per_s"] == pytest.approx(200 / 10)
    assert snap["latency_p50_ms"] == 200.0 and snap["latency_p95_ms"] == 200.0
    assert snap["lag_messages"] == 7
    assert snap["lag_seconds"] == pytest.approx(1010 - 999.5)
    assert (snap["rejected"], snap["late"]) == (1, 2)
    # Через минуту первая пачка выпадает из окна
    clock.t += 55
    snap = w.snapshot()
    assert snap["processed"] == 100 and snap["latency_p95_ms"] == 200.0


def test_lag_messages():
    assert lag_messages({0: 100, 1: 50}, {0: 90}) == 60
    assert lag_messages({0: 10}, {0: 20}) == 0


def test_stats_kept_one_day(tmp_path):
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    run = store.create_session(conn, "replay:x:1", model_version="m", summary={})
    with store.transaction(conn):
        store.write_stats(
            conn, [{"run_id": run["run_id"], "processed": 1}], at="2026-09-01T00:00:00.000Z"
        )
    with store.transaction(conn):
        store.write_stats(
            conn, [{"run_id": run["run_id"], "processed": 2}], at="2026-09-02T00:00:01.000Z"
        )
    rows = conn.execute("SELECT processed FROM stream_stats").fetchall()
    assert [r[0] for r in rows] == [2]
    assert store.latest_stats(conn, run["run_id"])["processed"] == 2


def test_status_report(tmp_path):
    cfg = load_stream_config(Path(__file__).parents[2] / "configs" / "stream.yaml")
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    run = store.create_session(conn, "replay:x:1", model_version="m", summary={})
    cluster = MemoryCluster()
    b = MemoryBroker(cluster)
    b.ensure_topics([TopicSpec(cfg.topics.flows, 1, 1)])
    for _ in range(10):
        b.produce(cfg.topics.flows, "k", b"x", {})
    store.append_batch(conn, [], offsets={(cfg.topics.flows, 0): 4}, sessions={run["run_id"]: {}})

    rep = status_report(conn, cfg, lambda: MemoryBroker(cluster), now=1000.0)
    assert rep["broker"]["reachable"] is True
    assert rep["consumer"]["alive"] is False
    assert rep["lag_messages"] == 6
    (s,) = rep["sessions"]
    assert s["run_id"] == run["run_id"] and s["status"] == "running" and s["lag_messages"] == 6

    store.acquire_lease(conn, "host:1", 30, now=1000.0)
    cluster.down = True
    rep = status_report(conn, cfg, lambda: MemoryBroker(cluster, vm_name="vm"), now=1005.0)
    assert rep["broker"]["reachable"] is False and "Start-VM vm" in rep["broker"]["error"]
    assert rep["consumer"] == {
        "alive": True,
        "holder": "host:1",
        "renewed_at": rep["consumer"]["renewed_at"],
    }
    # Потребитель умер — аренда истекла
    rep = status_report(conn, cfg, None, now=1100.0)
    assert rep["consumer"]["alive"] is False and rep["broker"]["reachable"] is None
