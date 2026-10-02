"""Буфер отправки сенсора и учёт потерь (фича 006, US2, research R10, SC-006).

Брокер недоступен ≤ буфера → 0 потерь, всё досылается после восстановления. Переполнение
буфера или перегрузка захвата → потери считаются и сеанс помечается «с потерями». Всё на
MemoryBroker 005, без ВМ.
"""

from pathlib import Path

import pytest

from mlsiem.stream.broker import BrokerUnavailable, MemoryBroker, MemoryCluster, topic_specs
from mlsiem.stream.config import load_stream_config
from mlsiem.stream.messages import FEATURE_FIELDS, H_KIND, KIND_FLOW
from mlsiem.stream.sensor import SensorSink

REPO = Path(__file__).parents[2]


@pytest.fixture(scope="module")
def cfg():
    return load_stream_config(REPO / "configs" / "stream.yaml")


@pytest.fixture
def cluster(cfg):
    c = MemoryCluster()
    for s in topic_specs(cfg):
        c.add_topic(s.name, s.partitions, s.retention_ms)
    return c


def _row(i: int) -> dict:
    """Минимальный поток: все поля схемы, уникальный по времени и адресам стенда."""
    row = dict.fromkeys(FEATURE_FIELDS, 0)
    row.update(
        src_ip="10.88.0.30",
        dst_ip="10.88.0.20",
        src_port=40000 + i,
        dst_port=80,
        protocol=6,
        bidirectional_first_seen_ms=1_000 + i,
        bidirectional_last_seen_ms=1_100 + i,
        bidirectional_packets=3,
    )
    return row


class FlakyBroker(MemoryBroker):
    """MemoryBroker, который можно «уронить»: produce бросает BrokerUnavailable, пока down."""

    def __init__(self, cluster, **kw):
        super().__init__(cluster, **kw)
        self.down = False

    def produce(self, topic, key, value, headers):
        if self.down:
            raise BrokerUnavailable("брокер недоступен (тест)")
        super().produce(topic, key, value, headers)


def test_no_loss_when_broker_recovers(cfg, cluster):
    broker = FlakyBroker(cluster)
    sink = SensorSink(broker, cfg.topics.flows, buffer_flows=100)
    for i in range(10):
        sink.feed(_row(i))  # брокер жив
    broker.down = True
    for i in range(10, 40):  # 30 потоков в буфер (< 100) — потерь быть не должно
        sink.feed(_row(i))
    assert sink.counters.flows_dropped == 0
    assert sink.buffer_fill == pytest.approx(30 / 100)
    broker.down = False
    assert sink.end() == 0  # всё досылается
    msgs = [
        m
        for m in MemoryBroker(cluster).messages(cfg.topics.flows)
        if m.headers[H_KIND] == KIND_FLOW
    ]
    assert len(msgs) == 40
    assert not sink.counters.lossy


def test_overflow_counts_loss_and_marks_lossy(cfg, cluster):
    broker = FlakyBroker(cluster)
    sink = SensorSink(broker, cfg.topics.flows, buffer_flows=5)
    broker.down = True
    for i in range(12):  # в буфер влезет 5, остальные 7 — потеряны
        sink.feed(_row(i))
    assert sink.counters.flows_dropped == 7
    assert sink.buffer_fill == 1.0
    assert sink.counters.lossy
    # Принятые потоки не вытесняются: досылаются ровно 5 первых
    broker.down = False
    sink.flush()
    msgs = [
        m
        for m in MemoryBroker(cluster).messages(cfg.topics.flows)
        if m.headers[H_KIND] == KIND_FLOW
    ]
    assert len(msgs) == 5


def test_packet_drops_mark_lossy(cfg, cluster):
    sink = SensorSink(MemoryBroker(cluster), cfg.topics.flows)
    sink.feed(_row(0))
    assert not sink.counters.lossy
    sink.record_packet_drops(12)  # libpcap/nfstream не успел
    assert sink.counters.packets_dropped == 12 and sink.counters.lossy


def test_seq_monotone_and_source_id(cfg, cluster):
    sink = SensorSink(MemoryBroker(cluster), cfg.topics.flows, source_id="sensor:live")
    for i in range(3):
        sink.feed(_row(i))
    sink.end()
    import orjson

    flows = [
        orjson.loads(m.value)
        for m in MemoryBroker(cluster).messages(cfg.topics.flows)
        if m.headers[H_KIND] == KIND_FLOW
    ]
    assert [f["seq"] for f in flows] == [0, 1, 2]
    assert all(f["source_id"] == "sensor:live" for f in flows)
