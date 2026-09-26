"""Проигрыватель разбиения (US2, research R6) на брокере-заглушке и подменённых часах.

Часы и сон подменены: `sleep` только сдвигает «время», поэтому темп ×N проверяется точно и
без реального ожидания.
"""

import orjson
import polars as pl
import pytest

from mlsiem.data.schema import SCHEMA
from mlsiem.stream.broker import MemoryBroker, MemoryCluster, TopicSpec
from mlsiem.stream.messages import decode_flows
from mlsiem.stream.replay import (
    ReplayError,
    ReplaySource,
    find_resume,
    load_split_source,
    new_source_id,
    replay,
)

T = "mlsiem.flows"
SRC = "replay:unsw_time/test:20260925T101500"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0
        self.slept: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.slept.append(s)
        self.now += s


@pytest.fixture
def broker() -> MemoryBroker:
    b = MemoryBroker(MemoryCluster())
    b.ensure_topics([TopicSpec(T, 1, 1000)])
    return b


@pytest.fixture(scope="module")
def source(synthetic_split) -> ReplaySource:
    return load_split_source("unsw_time", "test", data_dir=synthetic_split)


def _run(source, broker, speed=None, **kw):
    fc = kw.pop("fc", FakeClock())
    return (
        replay(source, broker, T, source_id=SRC, speed=speed, clock=fc.clock, sleep=fc.sleep, **kw),
        fc,
    )


def test_all_flows_in_time_order_then_end(source, broker):
    summary, _ = _run(source, broker)
    msgs = broker.messages(T)
    frame, rejected, ends = decode_flows(msgs)
    assert rejected == []
    assert frame.height == source.total == summary.sent
    assert frame["seq"].to_list() == list(range(source.total))
    order = frame.select("bidirectional_first_seen_ms", "flow_uid").rows()
    assert order == sorted(order)
    assert len(ends) == 1 and msgs[-1].headers["mlsiem-kind"] == "end"
    assert (ends[0].n_sent, ends[0].last_seq) == (source.total, source.total - 1)
    assert {m.key for m in msgs} == {SRC}
    # Метка — отдельным полем, как пришла из разбиения
    assert frame["label"].to_list() == source.flows["label"].to_list()


def test_same_flows_as_split_part(source, synthetic_split):
    from mlsiem.detect.dataset import scan_part

    want = scan_part("unsw_time", "test", data_dir=synthetic_split).collect()["flow_uid"]
    assert sorted(source.flows["flow_uid"].to_list()) == sorted(want.to_list())


def test_speed_60_sleeps_traffic_span(source, broker):
    summary, fc = _run(source, broker, speed=60)
    span_s = (
        source.flows["bidirectional_first_seen_ms"].max()
        - source.flows["bidirectional_first_seen_ms"].min()
    ) / 1000
    assert sum(fc.slept) == pytest.approx(span_s / 60, rel=0.01)
    assert min(fc.slept) >= 0.001
    assert summary.seconds == pytest.approx(span_s / 60, rel=0.01)


def test_max_speed_never_sleeps(source, broker):
    _, fc = _run(source, broker, speed=None)
    assert fc.slept == []


def test_lag_is_compensated(source, broker):
    """Отправка «тормозит»: график догоняется без пауз, итог по времени — тот же."""

    class SlowBroker(MemoryBroker):
        def produce(self, *a, **kw):
            super().produce(*a, **kw)
            fc.now += 0.05

    fc = FakeClock()
    slow = SlowBroker(broker.cluster)
    summary, _ = _run(source, slow, speed=60, fc=fc)
    span_s = (
        source.flows["bidirectional_first_seen_ms"].max()
        - source.flows["bidirectional_first_seen_ms"].min()
    ) / 1000
    assert summary.behind_s > 0
    assert summary.seconds >= span_s / 60


def test_limit(synthetic_split, broker):
    src = load_split_source("unsw_time", "test", data_dir=synthetic_split, limit=25)
    _run(src, broker)
    frame, _, ends = decode_flows(broker.messages(T))
    assert frame.height == 25 and ends[0].n_sent == 25


def test_progress_callback(source, broker):
    calls = []
    _run(source, broker, speed=60, on_progress=lambda *a: calls.append(a), progress_interval_s=1)
    assert calls
    sent, total, rate, behind = calls[-1]
    assert 0 < sent <= total == source.total and rate > 0


def test_incompatible_schema_refused_before_sending(source, broker):
    bad = ReplaySource(source.label, source.flows, "2.0.0", [])
    from mlsiem.stream.replay import _check_version

    with pytest.raises(ReplayError, match="мажорные"):
        _check_version(bad.schema_version, "потоков")
    with pytest.raises(ReplayError, match="нет версии"):
        _check_version(None, "потоков")


def test_split_without_version_refused(synthetic_split, tmp_path, monkeypatch):
    import mlsiem.stream.replay as rp

    monkeypatch.setattr(rp, "read_parquet_metadata", lambda f: {})
    with pytest.raises(ReplayError, match="нет версии схемы"):
        rp.load_split_source("unsw_time", "test", data_dir=synthetic_split)


def test_broker_lost_midway(source, broker):
    broker.cluster.fail_after_produce = 40
    with pytest.raises(ReplayError, match=f"Отправлено 40 из {source.total}.*--resume {SRC}"):
        _run(source, broker)


def test_resume_continues_after_last_delivered(source, broker):
    broker.cluster.fail_after_produce = 40
    with pytest.raises(ReplayError):
        _run(source, broker)
    broker.cluster.down = False
    broker.cluster.fail_after_produce = None
    fresh = broker.client()
    next_seq, ended = find_resume(fresh, T, SRC)
    assert (next_seq, ended) == (40, False)
    summary, _ = _run(source, fresh, first_seq=next_seq)
    frame, rejected, ends = decode_flows(broker.messages(T))
    assert frame["seq"].to_list() == list(range(source.total))
    assert frame["flow_uid"].n_unique() == source.total
    assert summary.sent == source.total - 40 and len(ends) == 1
    assert find_resume(fresh, T, SRC) == (source.total, True)


def test_source_id_format():
    from datetime import UTC, datetime

    sid = new_source_id("unsw_time/test", datetime(2026, 9, 25, 10, 15, tzinfo=UTC))
    assert sid == "replay:unsw_time/test:20260925T101500"


def test_schema_version_in_every_message(source, broker):
    _run(source, broker)
    for m in broker.messages(T)[:50]:
        assert m.headers["mlsiem-schema"] == SCHEMA.version
    body = orjson.loads(broker.messages(T)[0].value)
    assert body["schema_version"] == SCHEMA.version
    assert isinstance(pl.DataFrame, type)
