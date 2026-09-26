"""Единственный потребитель (FR-019) и отвергнутые сообщения (FR-006, SC-006)."""

import orjson
import pytest

from fixtures.stream_helpers import (
    make_cluster,
    make_soc_cfg,
    make_stream_cfg,
    replay_split,
    replay_with_inserts,
    run_consumer,
)
from mlsiem.data.schema import SCHEMA
from mlsiem.soc import store
from mlsiem.stream.broker import MemoryBroker
from mlsiem.stream.consumer import Consumer, LeaseLost
from mlsiem.stream.messages import H_KIND, H_SCHEMA, H_SOURCE, REASONS, encode_flow

SRC = "replay:unsw_time/test:20260925T130000"


def test_second_consumer_refused_while_lease_alive(tmp_path, synthetic_split, tiny_detector):
    stream_cfg, soc_cfg = make_stream_cfg(), make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    first = Consumer(
        stream_cfg,
        soc_cfg,
        broker=MemoryBroker(cluster),
        model_dir=tiny_detector,
        clock=lambda: 1000.0,
        holder="host-a:111",
    )
    first.start()
    with pytest.raises(store.LeaseHeld, match="уже работает потребитель host-a:111 с"):
        run_consumer(
            cluster, stream_cfg, soc_cfg, tiny_detector, clock=lambda: 1010.0, holder="host-b:2"
        )
    first.stop()


def test_expired_lease_taken_over_first_stops(tmp_path, synthetic_split, tiny_detector):
    stream_cfg, soc_cfg = make_stream_cfg(batch_max_messages=50), make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC, limit=100)
    now = {"t": 1000.0}
    first = Consumer(
        stream_cfg,
        soc_cfg,
        broker=MemoryBroker(cluster),
        model_dir=tiny_detector,
        clock=lambda: now["t"],
        holder="host-a:1",
    )
    first.start()
    # Первый «завис» дольше аренды — второй её забирает и работает
    now["t"] += stream_cfg.consumer.lease_ttl_s + 1
    second = Consumer(
        stream_cfg,
        soc_cfg,
        broker=MemoryBroker(cluster),
        model_dir=tiny_detector,
        clock=lambda: now["t"],
        holder="host-b:2",
    )
    second.start()
    # Первый проснулся: при продлении обнаруживает потерю и останавливается без записи
    with pytest.raises(LeaseLost):
        first.run(once=True)
    conn = store.connect(soc_cfg.db)
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    assert store.lease_info(conn, 30, now=now["t"])["holder"] == "host-b:2"
    summary = second.run(once=True)
    second.stop()
    assert summary.processed == 100


def _bad_messages(flow_row) -> list[tuple[bytes, dict]]:
    headers = {H_KIND: "flow", H_SCHEMA: SCHEMA.version, H_SOURCE: SRC}
    _, good, _ = encode_flow(flow_row, SRC, 0, 1)
    body = orjson.loads(good)
    missing = {**body, "fields": {k: v for k, v in body["fields"].items() if k != "protocol"}}
    major = {**body, "schema_version": "2.0.0"}
    bad_type = {**body, "fields": {**body["fields"], "bidirectional_packets": "x"}}
    return [
        (b"{broken", headers),
        (orjson.dumps(missing), headers),
        (orjson.dumps(major), headers),
        (orjson.dumps(bad_type), headers),
        (good, {**headers, H_SOURCE: "replay:чужой"}),
    ]


def test_rejected_go_to_topic_and_consumer_continues(tmp_path, synthetic_split, tiny_detector):
    from mlsiem.stream.replay import load_split_source

    stream_cfg, soc_cfg = make_stream_cfg(batch_max_messages=40), make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    flow_row = load_split_source("unsw_time", "test", data_dir=synthetic_split, limit=1).flows.row(
        0, named=True
    )
    # Битые сообщения вклиниваются в поток до отметки end
    bad = [(SRC, value, headers) for value, headers in _bad_messages(flow_row)]
    total = replay_with_inserts(cluster, stream_cfg, synthetic_split, SRC, bad, limit=60)
    b = MemoryBroker(cluster)

    summary = run_consumer(cluster, stream_cfg, soc_cfg, tiny_detector)
    assert summary.rejected == 5
    assert summary.processed == total
    rejected = b.messages(stream_cfg.topics.rejected)
    assert len(rejected) == 5
    reasons = [orjson.loads(m.value)["reason"].split(":")[0] for m in rejected]
    assert sorted(reasons) == sorted(REASONS)
    first = orjson.loads(rejected[0].value)
    assert first["value"] == "{broken" and first["topic"] == stream_cfg.topics.flows
    conn = store.connect(soc_cfg.db)
    run = store.session_by_source(conn, SRC)
    # Сообщение с чужим источником в заголовке сеансу не приписывается: чей оно — неизвестно
    assert run["summary"]["stream"]["n_rejected"] == 4
    assert run["status"] == "completed"
