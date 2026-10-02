"""Сборщик окон потребителя (фича 007, R13): закрытие по водяному знаку, опоздавшие,
отметка end, остановка без end, повторы. Работает прямо с SQLite, без брокера."""

import numpy as np
import polars as pl
import pytest

from mlsiem.detect import windows as W
from mlsiem.detect.windows_expert import load_window_expert
from mlsiem.soc import store
from mlsiem.stream.incremental import mark_late
from mlsiem.stream.windows_online import (
    WindowAssembler,
    apply_window_plan,
    due,
    encode_payload,
    frame_from_payloads,
    open_windows,
    payload_columns,
)

L = 60_000
LATE = 120_000
RUN = "stream-test"


@pytest.fixture(scope="module")
def expert(tiny_windows):
    return load_window_expert(tiny_windows, force=True)


@pytest.fixture(scope="module")
def flows(synthetic_flows):
    """Один атакующий-«сканер» и фон: потоки одного дня, по времени."""
    return next(iter(synthetic_flows.values())).sort([W.FIRST, "flow_uid"]).head(400)


def _verdicts(df):
    return df.select("flow_uid").with_columns(pl.lit(0.5).alias("attack_score"))


def _db(tmp_path):
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    return conn


def _step(conn, asm, part, watermark, close_all=False):
    plan = asm.plan(conn, RUN, part, _verdicts(part), watermark=watermark, close_all=close_all)
    with store.transaction(conn):
        apply_window_plan(conn, plan, store.now_iso())
    return plan


def _payload_rows(flows, has_label):
    """Потоки как их кладёт сборщик: стороны, скор потока и (если есть) метка."""
    from mlsiem.soc.direction import sides

    side = sides(flows, "auto").select(W.SIDE_COLUMNS)
    df = flows.join(side.select("flow_uid", "attacker_ip", "victim_ip", "reversed"), on="flow_uid")
    df = df.with_columns(pl.lit(0.1234567890123).alias("flow_score"))
    if not has_label:
        df = df.drop("label", strict=False)
    return df.select(payload_columns(has_label)).sort("flow_uid")


@pytest.mark.parametrize("has_label", [True, False])
def test_payload_array_round_trip_bit_exact(flows, has_label):
    """Массив значений возвращается тем же кадром: float64 до бита, метка — по длине."""
    df = _payload_rows(flows, has_label)
    back = frame_from_payloads([encode_payload(r) for r in df.iter_rows()])
    assert back.columns == df.columns
    assert ("label" in back.columns) is has_label
    for c in df.columns:
        a, b = df[c], back[c].cast(df[c].dtype)
        if a.dtype.is_float():
            assert np.array_equal(a.to_numpy().view(np.int64), b.to_numpy().view(np.int64)), (
                c
            )  # побитно, не «примерно»
        else:
            assert a.to_list() == b.to_list(), c


def test_payload_array_is_compact_and_old_dict_still_read(flows):
    """Массив заметно короче словаря (имена полей не повторяются в каждом потоке), а payload
    прежнего вида — словарь, оставшийся в открытых окнах старого сеанса, — читается так же."""
    import orjson

    df = _payload_rows(flows, True)
    arrays = [encode_payload(r) for r in df.iter_rows()]
    dicts = [orjson.dumps(r) for r in df.iter_rows(named=True)]
    assert sum(map(len, arrays)) < 0.6 * sum(map(len, dicts))
    assert frame_from_payloads(dicts).equals(frame_from_payloads(arrays))


def test_due_is_exact():
    starts = {"a": 0, "b": 60_000}
    # окно [0, 60 000) закрывается ровно при 60 000 ≤ watermark − 120 000
    assert due(starts, 179_999, L, LATE) == []
    assert due(starts, 180_000, L, LATE) == ["a"]
    assert due(starts, 240_000, L, LATE) == ["a", "b"]
    assert due(starts, None, L, LATE) == []


def test_windows_close_by_watermark_and_end(tmp_path, expert, flows):
    conn = _db(tmp_path)
    asm = WindowAssembler(expert, "auto", LATE)
    first = flows.head(200)
    wm = int(first[W.FIRST].max())
    plan = _step(conn, asm, first, wm)
    # закрыты ровно созревшие окна; остальные — открыты
    side = W.SIDE_COLUMNS
    from mlsiem.soc.direction import sides

    asg = W.assign_windows(first, sides(first, "auto").select(side), length_ms=L)
    starts = dict(zip(asg["window_id"], asg["window_start_ms"], strict=False))
    assert sorted(plan.close_ids) == due(starts, wm, L, LATE)
    assert set(open_windows(conn, RUN)) == set(starts) - set(plan.close_ids)
    # отметка end — закрыть всё
    last = _step(conn, asm, flows.slice(200), int(flows[W.FIRST].max()), close_all=True)
    assert open_windows(conn, RUN) == {}
    closed = conn.execute("SELECT COUNT(*) FROM window_closed WHERE run_id = ?", (RUN,)).fetchone()
    assert closed[0] == len(plan.close_ids) + len(last.close_ids)


def test_stop_without_end_keeps_pending(tmp_path, expert, flows):
    conn = _db(tmp_path)
    asm = WindowAssembler(expert, "auto", LATE)
    _step(conn, asm, flows.head(100), int(flows.head(100)[W.FIRST].max()))
    before = open_windows(conn, RUN)
    conn.close()
    conn = store.connect(tmp_path / "soc.db")  # «перезапуск»: состояние из хранилища
    assert open_windows(conn, RUN) == before and before


def test_flow_into_closed_window_dropped(tmp_path, expert, flows):
    conn = _db(tmp_path)
    asm = WindowAssembler(expert, "auto", LATE)
    first = flows.head(1)
    t0 = int(first[W.FIRST][0])
    _step(conn, asm, first, t0 + 10 * L, close_all=False)  # окно первого потока закрылось
    late = (
        flows.head(2)
        .tail(1)
        .with_columns(
            pl.lit(t0 + 1).alias(W.FIRST),
            pl.lit(first["src_ip"][0]).alias("src_ip"),
            pl.lit(first["dst_ip"][0]).alias("dst_ip"),
        )
    )
    plan = _step(conn, asm, late, t0 + 10 * L)
    assert len(plan.dropped) == 1 and plan.counters()["n_window_late_dropped"] == 1
    div = store.divergences(conn, RUN)
    assert div and div[0]["kind"] == "window_late_dropped"


def test_repeated_flow_not_added_twice(tmp_path, expert, flows):
    conn = _db(tmp_path)
    asm = WindowAssembler(expert, "auto", LATE)
    part = flows.head(30)
    _step(conn, asm, part, None)
    _step(conn, asm, part, None)  # повторная доставка (страховка к stream_seen)
    n = conn.execute("SELECT COUNT(*) FROM window_pending WHERE run_id = ?", (RUN,)).fetchone()[0]
    assert n == 30


@pytest.mark.parametrize("seed", range(5))
def test_non_late_flow_never_hits_closed_window(tmp_path, expert, flows, seed):
    """Property: при любом порядке прихода в пределах допустимого опоздания ни один не
    опоздавший поток не попадает в уже закрытое окно."""
    rng = np.random.default_rng(seed)
    df = flows.with_row_index("_i")
    t = df[W.FIRST].to_numpy()
    # перемешивание «с дрожью» не больше допустимого опоздания
    order = np.argsort(t + rng.integers(0, LATE // 2, size=len(t)), kind="stable")
    shuffled = df[order].drop("_i")
    flags, _ = mark_late(shuffled[W.FIRST].to_list(), None, LATE)
    assert not any(flags)
    conn = _db(tmp_path)
    asm = WindowAssembler(expert, "auto", LATE)
    wm = None
    dropped = 0
    for lo in range(0, shuffled.height, 37):
        part = shuffled.slice(lo, 37)
        m = int(part[W.FIRST].max())
        wm = m if wm is None else max(wm, m)
        dropped += len(_step(conn, asm, part, wm).dropped)
    assert dropped == 0
