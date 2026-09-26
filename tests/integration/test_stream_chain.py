"""Онлайн-цепочка целиком на брокере-заглушке (US3, SC-004): проигрыватель → потребитель →
SQLite, и сравнение с пакетным `soc run` того же входа той же моделью — «эквивалентно»."""

import shutil

import polars as pl
import pytest

from fixtures.stream_helpers import (
    make_cluster,
    make_soc_cfg,
    make_stream_cfg,
    replay_split,
    run_consumer,
)
from mlsiem.soc import store
from mlsiem.soc.run import run_chain
from mlsiem.stream.compare import compare, session_verdicts
from mlsiem.stream.messages import decode_flows

SRC = "replay:unsw_time/test:20260925T101500"


@pytest.fixture
def cfgs(tmp_path):
    return make_stream_cfg(batch_max_messages=500), make_soc_cfg(tmp_path)


@pytest.mark.parametrize("model_fixture", ["tiny_ensemble", "tiny_detector"])
def test_stream_equals_batch(cfgs, synthetic_split, model_fixture, request):
    model_dir = request.getfixturevalue(model_fixture)
    stream_cfg, soc_cfg = cfgs
    cluster = make_cluster(stream_cfg)
    sent = replay_split(cluster, stream_cfg, synthetic_split, SRC)

    summary = run_consumer(cluster, stream_cfg, soc_cfg, model_dir)
    assert summary.processed == sent.total
    assert summary.batches > 1

    conn = store.connect(soc_cfg.db)
    run = store.session_by_source(conn, SRC)
    assert run["mode"] == "stream" and run["status"] == "completed"
    assert run["run_id"] == store.session_run_id(SRC)
    assert run["n_flows"] == sent.total
    assert run["summary"]["stream"]["end_received"] is True
    parts = list((soc_cfg.runs_dir / run["run_id"] / "verdicts").glob("part-*.parquet"))
    assert len(parts) == summary.batches
    assert session_verdicts(soc_cfg.runs_dir, run["run_id"]).height == sent.total

    batch = run_chain(
        "split:unsw_time/test", soc_cfg, model_dir=model_dir, data_dir=synthetic_split
    )
    report = compare(conn, soc_cfg.runs_dir, run["run_id"], batch.run_id)
    assert report["equivalent"], report["divergences"][:5]
    assert report["verdicts"]["matched"] == sent.total
    assert report["incidents"]["session"] == report["incidents"]["batch"] == batch.n_incidents
    assert report["incidents"]["matched"] == batch.n_incidents
    assert report["actions"]["matched"] == batch.n_incidents
    # аудит сеанса: run_loaded один раз, предложения — по одному на инцидент
    audit = store.list_audit(conn, {"run_id": run["run_id"]}, limit=10_000)[1]
    events = [e["event"] for e in audit]
    assert events.count("run_loaded") == 1
    assert events.count("action_proposed") >= batch.n_incidents


def test_two_sources_interleaved(cfgs, synthetic_split, tiny_detector):
    """Два источника вперемешку в одном топике → два сеанса без смешения."""
    stream_cfg, soc_cfg = cfgs
    cluster = make_cluster(stream_cfg)
    from mlsiem.stream.broker import MemoryBroker
    from mlsiem.stream.replay import load_split_source, replay

    a = load_split_source("unsw_time", "test", data_dir=synthetic_split, limit=300)
    b = load_split_source("unsw_time", "val", data_dir=synthetic_split, limit=200)
    # Перемешиваем: по кусочку от каждого источника
    other = make_cluster(stream_cfg)
    replay(a, MemoryBroker(other), stream_cfg.topics.flows, source_id="replay:a:1", speed=None)
    replay(b, MemoryBroker(other), stream_cfg.topics.flows, source_id="replay:b:1", speed=None)
    msgs_a = [
        m for m in MemoryBroker(other).messages(stream_cfg.topics.flows) if m.key == "replay:a:1"
    ]
    msgs_b = [
        m for m in MemoryBroker(other).messages(stream_cfg.topics.flows) if m.key == "replay:b:1"
    ]
    broker = MemoryBroker(cluster)
    for i in range(max(len(msgs_a), len(msgs_b))):
        for msgs in (msgs_a, msgs_b):
            if i < len(msgs):
                broker.produce(stream_cfg.topics.flows, msgs[i].key, msgs[i].value, msgs[i].headers)

    run_consumer(cluster, stream_cfg, soc_cfg, tiny_detector)
    conn = store.connect(soc_cfg.db)
    ra = store.session_by_source(conn, "replay:a:1")
    rb = store.session_by_source(conn, "replay:b:1")
    assert (ra["n_flows"], rb["n_flows"]) == (300, 200)
    assert ra["status"] == rb["status"] == "completed"
    uids_a = set(a.flows["flow_uid"].to_list())
    got_a = {
        r[0] for r in conn.execute("SELECT flow_uid FROM alerts WHERE run_id = ?", (ra["run_id"],))
    }
    assert got_a <= uids_a


def test_model_checked_before_first_poll(cfgs, synthetic_split, tiny_ensemble, tmp_path):
    """Битый эксперт → отказ до чтения: топик не тронут, позиции не сдвинуты."""
    stream_cfg, soc_cfg = cfgs
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC, limit=50)
    broken = tmp_path / "broken_ensemble"
    shutil.copytree(tiny_ensemble, broken)
    card = broken / "ensemble_card.json"
    card.write_text("{не json", encoding="utf-8")

    from mlsiem.detect.artifact import DetectorLoadError
    from mlsiem.stream.broker import MemoryBroker

    polled = []

    class Spy(MemoryBroker):
        def poll_batch(self, *a, **kw):
            polled.append(1)
            return super().poll_batch(*a, **kw)

    with pytest.raises(DetectorLoadError):
        run_consumer(cluster, stream_cfg, soc_cfg, broken, broker=Spy(cluster))
    assert polled == []
    assert cluster.group_offsets.get(stream_cfg.consumer.group, {}) == {}
    if soc_cfg.db.exists():
        conn = store.connect(soc_cfg.db)
        store.init_db(conn)
        assert store.load_offsets(conn) == {}


def test_label_never_reaches_model_features(cfgs, synthetic_split, tiny_detector):
    """Метка едет в сообщении, но в вердиктах она — только true_label (FR-007)."""
    stream_cfg, soc_cfg = cfgs
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC, limit=100)
    run_consumer(cluster, stream_cfg, soc_cfg, tiny_detector)
    conn = store.connect(soc_cfg.db)
    v = session_verdicts(soc_cfg.runs_dir, store.session_run_id(SRC))
    assert "true_label" in v.columns and "label" not in v.columns
    frame, _, _ = decode_flows(
        __import__("mlsiem.stream.broker", fromlist=["MemoryBroker"])
        .MemoryBroker(cluster)
        .messages(stream_cfg.topics.flows)
    )
    assert frame["label"].null_count() == 0
    assert isinstance(v, pl.DataFrame) and conn is not None
