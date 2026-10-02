"""Эксперт окон в онлайн-цепочке на брокере-заглушке (фича 007, US3, R13, SC-006, FR-016).

Модель окон — `tiny_windows` в режиме `force`. Проверяется главное обещание: онлайн даёт те
же окна, вердикты окон, алерты окон и инциденты, что пакетный `soc run --windows force` того
же входа, — при пачках любого размера, перемешивании в пределах допустимого опоздания и
прерывании потребителя посреди потока.
"""

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
from mlsiem.stream.broker import MemoryBroker
from mlsiem.stream.compare import compare, session_windows
from mlsiem.stream.consumer import Consumer, ModelMismatch

SRC = "replay:unsw_time/test:20260926T200000"


def _batch(soc_cfg, synthetic_split, tiny_detector, tiny_windows):
    return run_chain(
        "split:unsw_time/test",
        soc_cfg,
        model_dir=tiny_detector,
        data_dir=synthetic_split,
        windows_mode="force",
        windows_model=tiny_windows,
    )


def _consume(cluster, stream_cfg, soc_cfg, tiny_detector, tiny_windows, **kw):
    return run_consumer(
        cluster,
        stream_cfg,
        soc_cfg,
        tiny_detector,
        windows_mode="force",
        windows_model=tiny_windows,
        **kw,
    )


def _check_equivalent(soc_cfg, batch):
    conn = store.connect(soc_cfg.db)
    try:
        run = store.session_by_source(conn, SRC)
        assert run["status"] == "completed"
        report = compare(conn, soc_cfg.runs_dir, run["run_id"], batch.run_id)
        assert report["equivalent"], report["divergences"][:5]
        w = report["windows"]
        assert w["matched"] == w["session"] == w["batch"] == batch.windows["n_windows"]
        assert report["incidents"]["matched"] == batch.n_incidents
        # окна сеанса все закрыты, открытых не осталось
        pending = conn.execute(
            "SELECT COUNT(*) FROM window_pending WHERE run_id = ?", (run["run_id"],)
        ).fetchone()[0]
        closed = conn.execute(
            "SELECT COUNT(*) FROM window_closed WHERE run_id = ?", (run["run_id"],)
        ).fetchone()[0]
        assert pending == 0 and closed == batch.windows["n_windows"]
        n_w = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE run_id = ? AND alert_kind = 'window'",
            (run["run_id"],),
        ).fetchone()[0]
        assert n_w == batch.windows["n_window_alerts"] > 0
        sec = run["summary"]["windows"]
        assert sec["n_windows"] == closed and sec["n_open_windows"] == 0
        assert sec["n_window_late_dropped"] == 0
        return run
    finally:
        conn.close()


@pytest.mark.parametrize("batch_size", [97, 5000])
def test_stream_equals_batch(tmp_path, synthetic_split, tiny_detector, tiny_windows, batch_size):
    stream_cfg = make_stream_cfg(batch_max_messages=batch_size)
    soc_cfg = make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    sent = replay_split(cluster, stream_cfg, synthetic_split, SRC)
    summary = _consume(cluster, stream_cfg, soc_cfg, tiny_detector, tiny_windows)
    assert summary.processed == sent.total
    batch = _batch(soc_cfg, synthetic_split, tiny_detector, tiny_windows)
    run = _check_equivalent(soc_cfg, batch)
    assert session_windows(soc_cfg.runs_dir, run["run_id"]).height == batch.windows["n_windows"]


def test_shuffled_within_lateness(tmp_path, synthetic_split, tiny_detector, tiny_windows):
    """Соседние сообщения поменяны местами (разница во времени — секунды, опоздание — 120 с):
    результат тот же, опоздавших в закрытое окно нет."""
    stream_cfg = make_stream_cfg(batch_max_messages=50)
    soc_cfg = make_soc_cfg(tmp_path)
    tmp = make_cluster(stream_cfg)
    replay_split(tmp, stream_cfg, synthetic_split, SRC)
    msgs = MemoryBroker(tmp).messages(stream_cfg.topics.flows)
    body, end = msgs[:-1], msgs[-1]
    for i in range(0, len(body) - 1, 2):
        body[i], body[i + 1] = body[i + 1], body[i]
    cluster = make_cluster(stream_cfg)
    out = MemoryBroker(cluster)
    for m in [*body, end]:
        out.produce(m.topic, m.key, m.value, m.headers)
    _consume(cluster, stream_cfg, soc_cfg, tiny_detector, tiny_windows)
    _check_equivalent(soc_cfg, _batch(soc_cfg, synthetic_split, tiny_detector, tiny_windows))


def test_interrupted_consumer_continues_windows(
    tmp_path, synthetic_split, tiny_detector, tiny_windows
):
    """Остановка посреди потока: открытые окна остаются в хранилище, перезапуск их
    продолжает — итог как у непрерывной обработки, дублей алертов окон нет."""
    stream_cfg = make_stream_cfg(batch_max_messages=60)
    soc_cfg = make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC)
    batches = {"n": 0}

    def stop_after_three():
        batches["n"] += 1
        return batches["n"] > 3

    _consume(cluster, stream_cfg, soc_cfg, tiny_detector, tiny_windows, stop=stop_after_three)
    conn = store.connect(soc_cfg.db)
    run = store.session_by_source(conn, SRC)
    assert run["status"] == "stopped"
    pending = conn.execute(
        "SELECT COUNT(*) FROM window_pending WHERE run_id = ?", (run["run_id"],)
    ).fetchone()[0]
    assert pending > 0  # окна не закрыты остановкой
    conn.close()
    _consume(cluster, stream_cfg, soc_cfg, tiny_detector, tiny_windows, holder="host:2")
    _check_equivalent(soc_cfg, _batch(soc_cfg, synthetic_split, tiny_detector, tiny_windows))


def test_crash_between_commit_and_ack(tmp_path, synthetic_split, tiny_detector, tiny_windows):
    """Сбой между записью пачки и подтверждением брокеру: пачка перечитается, окна не
    удвоятся (повторные потоки отсекает stream_seen, окна — первичный ключ)."""
    stream_cfg = make_stream_cfg(batch_max_messages=80)
    soc_cfg = make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC)
    broker = MemoryBroker(cluster, group=stream_cfg.consumer.group)
    c = Consumer(
        stream_cfg,
        soc_cfg,
        broker=broker,
        model_dir=tiny_detector,
        clock=lambda: 1_000_000.0,
        holder="host:1",
        windows_mode="force",
        windows_model=tiny_windows,
    )
    c.start()
    count = {"n": 0}
    real = broker.commit

    def commit(offsets):
        count["n"] += 1
        if count["n"] == 4:
            raise RuntimeError("процесс умер до подтверждения брокеру")
        real(offsets)

    broker.commit = commit
    with pytest.raises(RuntimeError):
        c.run(once=True)
    broker.crash()
    ttl = stream_cfg.consumer.lease_ttl_s
    _consume(
        cluster,
        stream_cfg,
        soc_cfg,
        tiny_detector,
        tiny_windows,
        clock=lambda: 1_000_000.0 + ttl + 1,
        holder="host:2",
    )
    _check_equivalent(soc_cfg, _batch(soc_cfg, synthetic_split, tiny_detector, tiny_windows))


def test_restart_with_other_window_expert_refused(
    tmp_path, synthetic_split, tiny_detector, tiny_windows
):
    stream_cfg = make_stream_cfg(batch_max_messages=60)
    soc_cfg = make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC)
    n = {"k": 0}

    def stop_soon():
        n["k"] += 1
        return n["k"] > 2

    # Сеанс начат БЕЗ эксперта окон …
    run_consumer(cluster, stream_cfg, soc_cfg, tiny_detector, windows_mode="off", stop=stop_soon)
    # … а продолжить его с экспертом окон нельзя
    with pytest.raises(ModelMismatch, match="эксперт"):
        _consume(cluster, stream_cfg, soc_cfg, tiny_detector, tiny_windows, holder="host:2")


def test_stream_close_closes_windows(tmp_path, synthetic_split, tiny_detector, tiny_windows):
    """`stream close` закрывает открытые окна: вердикты и алерты окон пишутся, как при end."""
    from mlsiem.stream.windows_online import close_session_windows

    stream_cfg = make_stream_cfg(batch_max_messages=60)
    soc_cfg = make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC)
    n = {"k": 0}

    def stop_soon():
        n["k"] += 1
        return n["k"] > 4

    _consume(cluster, stream_cfg, soc_cfg, tiny_detector, tiny_windows, stop=stop_soon)
    conn = store.connect(soc_cfg.db)
    run_id = store.session_run_id(SRC)
    open_before = conn.execute(
        "SELECT COUNT(DISTINCT window_id) FROM window_pending WHERE run_id = ?", (run_id,)
    ).fetchone()[0]
    assert open_before > 0
    closed = close_session_windows(conn, soc_cfg, run_id)
    assert closed["n_windows"] == open_before
    left = conn.execute(
        "SELECT COUNT(*) FROM window_pending WHERE run_id = ?", (run_id,)
    ).fetchone()[0]
    assert left == 0
    sec = store.get_run(conn, run_id)["summary"]["windows"]
    assert sec["n_open_windows"] == 0
    conn.close()
