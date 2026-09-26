"""Перезапуск без потерь и без дублей (US4, SC-005, FR-015, FR-016) на брокере-заглушке.

Потребителя «роняют» в трёх точках — до записи в SQLite, между записью и подтверждением
брокеру, после подтверждения — и запускают снова (как после сбоя процесса: без остановки,
аренда просто истекает). Итог обязан совпасть с непрерывной обработкой того же входа.
"""

import sqlite3

import pytest

from fixtures.stream_helpers import (
    make_cluster,
    make_soc_cfg,
    make_stream_cfg,
    replay_split,
    replay_with_inserts,
    run_consumer,
)
from mlsiem.soc import store
from mlsiem.stream.broker import MemoryBroker
from mlsiem.stream.consumer import Consumer, StoreUnavailable

SRC = "replay:unsw_time/test:20260925T120000"
LIMIT = 900


class Crash(Exception):
    """«Процесс умер» в выбранной точке."""


def _state(soc_cfg) -> dict:
    conn = store.connect(soc_cfg.db)
    run_id = store.session_run_id(SRC)
    alerts = sorted(
        r[0] for r in conn.execute("SELECT flow_uid FROM alerts WHERE run_id = ?", (run_id,))
    )
    incidents = sorted(
        tuple(r)
        for r in conn.execute(
            "SELECT src_ip, attack_class, first_seen_ms, last_seen_ms, n_alerts, severity, "
            "targets FROM incidents WHERE run_id = ? AND merged_into IS NULL",
            (run_id,),
        )
    )
    actions = sorted(
        tuple(r)
        for r in conn.execute(
            "SELECT i.src_ip, i.attack_class, i.first_seen_ms, a.action_type, a.target, a.rule_id "
            "FROM actions a JOIN incidents i ON i.incident_id = a.incident_id "
            "WHERE i.run_id = ? AND i.merged_into IS NULL",
            (run_id,),
        )
    )
    seen = conn.execute(
        "SELECT COUNT(*), COUNT(DISTINCT flow_uid) FROM stream_seen WHERE run_id = ?", (run_id,)
    ).fetchone()
    run = store.get_run(conn, run_id)
    conn.close()
    return {
        "alerts": alerts,
        "incidents": incidents,
        "actions": actions,
        "seen": tuple(seen),
        "n_flows": run["n_flows"],
        "status": run["status"],
    }


@pytest.fixture(scope="module")
def reference(tmp_path_factory, synthetic_split, tiny_detector):
    """Непрерывная обработка того же входа — эталон."""
    tmp = tmp_path_factory.mktemp("ref")
    stream_cfg, soc_cfg = make_stream_cfg(batch_max_messages=100), make_soc_cfg(tmp)
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC, limit=LIMIT)
    run_consumer(cluster, stream_cfg, soc_cfg, tiny_detector)
    return _state(soc_cfg)


def _crashing_consumer(cluster, stream_cfg, soc_cfg, model, *, holder, now, point, after):
    """Потребитель, который «умирает» в точке `point` на пачке номер `after` (с 1)."""
    broker = MemoryBroker(cluster, group=stream_cfg.consumer.group)
    c = Consumer(
        stream_cfg,
        soc_cfg,
        broker=broker,
        model_dir=model,
        clock=lambda: now,
        holder=holder,
    )
    c.start()
    count = {"n": 0}
    real_write, real_commit = c._write, broker.commit

    def write(*a, **kw):
        count["n"] += 1
        if point == "before_commit" and count["n"] == after:
            raise Crash("до COMMIT SQLite")
        return real_write(*a, **kw)

    def commit(offsets):
        if point == "between" and count["n"] == after:
            raise Crash("между COMMIT и подтверждением брокеру")
        real_commit(offsets)
        if point == "after" and count["n"] == after:
            raise Crash("после подтверждения")

    c._write = write
    broker.commit = commit
    with pytest.raises(Crash):
        c.run(once=True)
    # Процесс умер: ни stop(), ни освобождения аренды, соединение просто брошено
    broker.crash()
    return c


def test_three_crashes_equal_continuous(tmp_path, synthetic_split, tiny_detector, reference):
    stream_cfg, soc_cfg = make_stream_cfg(batch_max_messages=100), make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    total = replay_split(cluster, stream_cfg, synthetic_split, SRC, limit=LIMIT).total
    ttl = stream_cfg.consumer.lease_ttl_s
    now = 1_000_000.0
    for i, (point, after) in enumerate((("before_commit", 2), ("between", 2), ("after", 2))):
        _crashing_consumer(
            cluster,
            stream_cfg,
            soc_cfg,
            tiny_detector,
            holder=f"host:{i}",
            now=now,
            point=point,
            after=after,
        )
        now += ttl + 1  # аренда упавшего истекла — следующий её заберёт
    run_consumer(
        cluster, stream_cfg, soc_cfg, tiny_detector, clock=lambda: now, holder="host:final"
    )
    got = _state(soc_cfg)
    assert got == reference
    assert got["seen"] == (total, total) and got["n_flows"] == total  # 0 дублей, 0 потерь
    assert got["status"] == "completed"


def test_producer_duplicates_do_not_change_result(tmp_path, synthetic_split, tiny_detector):
    stream_cfg, soc_cfg = make_stream_cfg(batch_max_messages=100), make_soc_cfg(tmp_path)
    # Эталон — без повторов
    ref_cluster = make_cluster(stream_cfg)
    replay_split(ref_cluster, stream_cfg, synthetic_split, SRC, limit=300)
    run_consumer(ref_cluster, stream_cfg, soc_cfg, tiny_detector)
    before = _state(soc_cfg)

    # Производитель переотправил первые 150 сообщений (например, после своего сбоя) — до end
    tmp = make_cluster(stream_cfg)
    replay_split(tmp, stream_cfg, synthetic_split, SRC, limit=300)
    dups = [
        (m.key, m.value, m.headers)
        for m in MemoryBroker(tmp).messages(stream_cfg.topics.flows)[:150]
    ]
    soc2 = make_soc_cfg(tmp_path / "dups")
    cluster = make_cluster(stream_cfg)
    total = replay_with_inserts(cluster, stream_cfg, synthetic_split, SRC, dups, limit=300)
    summary = run_consumer(cluster, stream_cfg, soc2, tiny_detector)
    assert summary.duplicates == 150 and summary.processed == total
    assert _state(soc2) == before

    # Повтор уже после завершения сеанса — сообщения пропускаются, ничего не меняется
    b = MemoryBroker(cluster)
    for key, value, headers in dups:
        b.produce(stream_cfg.topics.flows, key, value, headers)
    summary = run_consumer(cluster, stream_cfg, soc2, tiny_detector)
    assert summary.processed == 0
    assert _state(soc2) == before


def test_locked_store_no_commit_then_recovers(tmp_path, synthetic_split, tiny_detector):
    stream_cfg = make_stream_cfg(batch_max_messages=1000, db_retry_s=2)
    soc_cfg = make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC, limit=200)

    blocker = store.connect(soc_cfg.db)
    store.init_db(blocker)
    broker = MemoryBroker(cluster, group=stream_cfg.consumer.group)
    sleeps = []

    c = Consumer(
        stream_cfg,
        soc_cfg,
        broker=broker,
        model_dir=tiny_detector,
        sleep=sleeps.append,
        holder="host:1",
    )
    c.start()
    c.conn.execute("PRAGMA busy_timeout = 50")
    blocker.execute("BEGIN EXCLUSIVE")
    with pytest.raises(StoreUnavailable, match="недоступно"):
        c.run(once=True)
    assert sleeps and sum(sleeps) >= 2
    # Ничего не подтверждено брокеру и ничего не записано
    assert cluster.group_offsets.get(stream_cfg.consumer.group, {}) == {}
    blocker.execute("ROLLBACK")
    c.stop("тест")
    assert store.load_offsets(blocker) == {}

    # База освободилась — следующий запуск обрабатывает всё без потерь
    summary = run_consumer(cluster, stream_cfg, soc_cfg, tiny_detector)
    assert summary.processed == 200
    assert _state(soc_cfg)["seen"] == (200, 200)


def test_lock_released_during_retry(tmp_path, synthetic_split, tiny_detector):
    """База была занята пару повторов и освободилась — пачка записана в том же запуске."""
    stream_cfg = make_stream_cfg(batch_max_messages=1000, db_retry_s=60)
    soc_cfg = make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC, limit=100)
    blocker = store.connect(soc_cfg.db)
    store.init_db(blocker)

    def sleep(s):
        if len(calls) == 1:
            blocker.execute("ROLLBACK")
        calls.append(s)

    calls: list[float] = []
    c = Consumer(
        stream_cfg,
        soc_cfg,
        broker=MemoryBroker(cluster, group=stream_cfg.consumer.group),
        model_dir=tiny_detector,
        sleep=sleep,
        holder="host:1",
    )
    c.start()
    c.conn.execute("PRAGMA busy_timeout = 50")
    blocker.execute("BEGIN EXCLUSIVE")
    summary = c.run(once=True)
    c.stop("тест")
    assert len(calls) == 2
    assert summary.processed == 100
    assert isinstance(blocker, sqlite3.Connection)
