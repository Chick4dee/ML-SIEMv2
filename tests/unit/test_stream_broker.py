"""Брокер-заглушка `MemoryBroker`: ведёт себя как Kafka там, где от этого зависят гарантии.

На ней стоят все быстрые тесты потока, поэтому её поведение закреплено отдельно: порядок в
партиции ключа, позиции группы меняются только подтверждением, повторная доставка после
«сбоя», `seek` для старта с позиции из SQLite, «выключенная машина».
"""

import inspect

import pytest

from mlsiem.stream.broker import (
    Broker,
    BrokerUnavailable,
    KafkaBroker,
    MemoryBroker,
    MemoryCluster,
    TopicSpec,
)

T = "mlsiem.flows"


@pytest.fixture
def broker() -> MemoryBroker:
    b = MemoryBroker(MemoryCluster(), vm_name="mlsiem-broker")
    b.ensure_topics([TopicSpec(T, 3, 1000), TopicSpec("mlsiem.flows.rejected", 1, 1000)])
    return b


def _send(b, n, key="src-a", start=0):
    for i in range(start, start + n):
        b.produce(T, key, f"m{i}".encode(), {"mlsiem-kind": "flow"})


def test_order_within_key_partition(broker):
    _send(broker, 5, key="src-a")
    _send(broker, 3, key="src-b")
    c = broker.client()
    c.subscribe([T])
    got = c.poll_batch(100, 10)
    a = [m.value for m in got if m.key == "src-a"]
    assert a == [f"m{i}".encode() for i in range(5)]
    parts_a = {m.partition for m in got if m.key == "src-a"}
    assert len(parts_a) == 1
    assert got[0].headers == {"mlsiem-kind": "flow"}
    assert broker.delivered == 8


def test_batch_limit_and_positions(broker):
    _send(broker, 10)
    c = broker.client()
    c.subscribe([T])
    assert len(c.poll_batch(4, 10)) == 4
    assert len(c.poll_batch(4, 10)) == 4
    assert len(c.poll_batch(4, 10)) == 2
    assert c.poll_batch(4, 10) == []


def test_commit_and_crash_redelivers(broker):
    _send(broker, 6)
    c1 = broker.client()
    c1.subscribe([T])
    first = c1.poll_batch(3, 10)
    tp = (T, first[0].partition)
    c1.commit({tp: first[-1].offset + 1})
    c1.poll_batch(3, 10)  # прочитано, но не подтверждено
    c1.crash()
    with pytest.raises(RuntimeError):
        c1.poll_batch(1, 10)

    c2 = broker.client()
    c2.subscribe([T])
    again = c2.poll_batch(10, 10)
    assert [m.value for m in again] == [b"m3", b"m4", b"m5"]
    assert c2.committed(T) == {tp: 3}


def test_seek_before_and_after_subscribe(broker):
    _send(broker, 5)
    p = broker.messages(T)[0].partition
    c = broker.client()
    c.seek(T, p, 2)
    c.subscribe([T])
    assert [m.offset for m in c.poll_batch(10, 10)] == [2, 3, 4]
    c.seek(T, p, 1)
    assert [m.offset for m in c.poll_batch(10, 10)] == [1, 2, 3, 4]


def test_end_offsets_for_lag(broker):
    _send(broker, 4, key="a")
    ends = broker.end_offsets(T)
    assert sum(ends.values()) == 4 and len(ends) == 3


def test_topics_and_idempotent_ensure(broker):
    topics = broker.list_topics()
    assert topics[T] == {"partitions": 3, "retention_ms": 1000}
    assert broker.ensure_topics([TopicSpec(T, 3, 1000)]) == []
    assert broker.ensure_topics([TopicSpec("x", 1, 1)]) == ["x"]


def test_unknown_topic_refused(broker):
    with pytest.raises(ValueError, match="нет на брокере"):
        broker.produce("нет.такого", "k", b"v", {})


def test_down_is_unavailable(broker):
    broker.cluster.down = True
    with pytest.raises(BrokerUnavailable, match="Start-VM mlsiem-broker"):
        broker.ping()


def test_fail_after_produce(broker):
    broker.cluster.fail_after_produce = 2
    _send(broker, 2)
    with pytest.raises(BrokerUnavailable):
        _send(broker, 1, start=2)


def test_scan_reads_everything_without_moving_group(broker):
    _send(broker, 3)
    c = broker.client()
    c.subscribe([T])
    assert [m.value for m in c.scan(T)] == [b"m0", b"m1", b"m2"]
    assert len(c.poll_batch(10, 10)) == 3
    assert c.committed(T) == {}


def test_both_implement_interface():
    abstract = {
        name
        for name, member in inspect.getmembers(Broker)
        if getattr(member, "__isabstractmethod__", False)
    }
    assert abstract
    for impl in (KafkaBroker, MemoryBroker):
        assert not getattr(impl, "__abstractmethods__", set()), impl
        for name in abstract:
            assert name in impl.__dict__, f"{impl.__name__}.{name}"
