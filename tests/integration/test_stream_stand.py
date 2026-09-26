"""Тесты на настоящем брокере Kafka машины стенда (маркер `stand`, по умолчанию выключены).

Запуск: `uv run pytest -m stand` — после подъёма стенда (quickstart §2). Если брокер не
отвечает, тесты пропускаются с объяснением, а не падают: быстрые тесты гарантий доставки
идут на брокере-заглушке, здесь — только то, что заглушка подтвердить не может.
"""

import time
import uuid

import pytest

from fixtures.stream_helpers import make_soc_cfg, make_stream_cfg
from mlsiem.soc import store
from mlsiem.soc.run import run_chain
from mlsiem.stream.broker import BrokerUnavailable, KafkaBroker, TopicSpec, make_broker
from mlsiem.stream.compare import compare
from mlsiem.stream.consumer import consume
from mlsiem.stream.replay import load_split_source, replay

pytestmark = pytest.mark.stand


@pytest.fixture(scope="module")
def kafka_cfg():
    cfg = make_stream_cfg()
    b = make_broker(cfg, "test")
    try:
        b.ping()
    except BrokerUnavailable as exc:
        pytest.skip(f"стенд не поднят: {exc}")
    finally:
        b.close()
    return cfg


def _scratch_cfg(cfg):
    """Отдельные топики и группа на каждый прогон тестов — рабочий топик не трогаем."""
    import dataclasses

    tag = uuid.uuid4().hex[:8]
    topics = dataclasses.replace(
        cfg.topics, flows=f"mlsiem.test.{tag}", rejected=f"mlsiem.test.{tag}.rejected"
    )
    consumer = dataclasses.replace(cfg.consumer, group=f"mlsiem-test-{tag}")
    return dataclasses.replace(cfg, topics=topics, consumer=consumer)


def test_kafka_broker_basics(kafka_cfg):
    cfg = _scratch_cfg(kafka_cfg)
    b = make_broker(cfg, "test")
    assert isinstance(b, KafkaBroker)
    specs = [
        TopicSpec(cfg.topics.flows, 1, 3_600_000),
        TopicSpec(cfg.topics.rejected, 1, 3_600_000),
    ]
    assert sorted(b.ensure_topics(specs)) == sorted(s.name for s in specs)
    assert b.ensure_topics(specs) == []  # идемпотентно
    time.sleep(1)
    topics = b.list_topics()
    assert topics[cfg.topics.flows]["retention_ms"] == 3_600_000
    for i in range(10):
        b.produce(cfg.topics.flows, "k", f"m{i}".encode(), {"mlsiem-kind": "flow"})
    assert b.flush(30) == 0 and b.delivered == 10
    assert b.end_offsets(cfg.topics.flows) == {0: 10}
    b.seek(cfg.topics.flows, 0, 4)
    b.subscribe([cfg.topics.flows])
    got = []
    for _ in range(20):
        got += b.poll_batch(100, 1000)
        if len(got) >= 6:
            break
    assert [m.offset for m in got] == [4, 5, 6, 7, 8, 9]
    assert got[0].headers == {"mlsiem-kind": "flow"}
    b.commit({(cfg.topics.flows, 0): 10})
    assert b.committed(cfg.topics.flows) == {(cfg.topics.flows, 0): 10}
    assert [m.value for m in b.scan(cfg.topics.flows)][:2] == [b"m0", b"m1"]
    b.close()


def test_short_replay_equals_batch(kafka_cfg, tmp_path, synthetic_split, tiny_detector):
    cfg = _scratch_cfg(kafka_cfg)
    soc_cfg = make_soc_cfg(tmp_path)
    admin = make_broker(cfg, "test")
    admin.ensure_topics(
        [TopicSpec(cfg.topics.flows, 1, 3_600_000), TopicSpec(cfg.topics.rejected, 1, 3_600_000)]
    )
    src = f"replay:stand-test:{uuid.uuid4().hex[:8]}"
    source = load_split_source("unsw_time", "test", data_dir=synthetic_split, limit=500)
    replay(source, admin, cfg.topics.flows, source_id=src, speed=None)
    admin.close()

    consumer_broker = make_broker(cfg, "consumer")
    try:
        consume(cfg, soc_cfg, broker=consumer_broker, model_dir=tiny_detector, once=True)
    finally:
        consumer_broker.close()
    batch = run_chain(
        "split:unsw_time/test",
        soc_cfg,
        model_dir=tiny_detector,
        data_dir=synthetic_split,
        limit=500,
    )
    conn = store.connect(soc_cfg.db)
    rep = compare(conn, soc_cfg.runs_dir, store.session_run_id(src), batch.run_id)
    assert rep["equivalent"], rep["divergences"][:3]
