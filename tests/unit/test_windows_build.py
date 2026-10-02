"""Построение окон (фича 007, R1, R9, SC-004): сетка от эпохи, детерминированный id, ключ —
атакующая сторона, окна не пересекают частей разбиения, сдвиги только по запросу."""

import polars as pl
import pytest

from mlsiem.detect import windows as W
from mlsiem.soc.direction import sides
from mlsiem.soc.store import input_digest

L = 60_000


@pytest.fixture(scope="module")
def flows(synthetic_flows):
    return pl.concat(list(synthetic_flows.values()))


@pytest.fixture(scope="module")
def side(flows):
    return sides(flows, "auto").select(W.SIDE_COLUMNS)


def test_grid_from_epoch(flows, side):
    a = W.assign_windows(flows, side, length_ms=L)
    j = a.join(flows.select("flow_uid", W.FIRST), on="flow_uid")
    assert (j["window_start_ms"] == (j[W.FIRST] // L) * L).all()
    assert ((j["window_start_ms"] <= j[W.FIRST]) & (j[W.FIRST] < j["window_start_ms"] + L)).all()


def test_window_id_deterministic_and_order_free(flows, side):
    a1 = W.assign_windows(flows, side, length_ms=L)
    shuffled = flows.sample(fraction=1.0, shuffle=True, seed=7)
    a2 = W.assign_windows(shuffled, side.sample(fraction=1.0, shuffle=True, seed=3), length_ms=L)
    assert a1.equals(a2)
    row = a1.row(0, named=True)
    expected = "w-" + input_digest(row["attacker_ip"], str(row["window_start_ms"]), str(L))[:16]
    assert row["window_id"] == expected


def test_key_is_attacker_side():
    """Ответный поток (SYN только у второй стороны) попадает в окно клиента-атакующего."""
    base = {
        "flow_uid": ["a", "b"],
        "protocol": [6, 6],
        "src_ip": ["10.0.0.1", "20.0.0.2"],
        "dst_ip": ["20.0.0.2", "10.0.0.1"],
        "src_port": [40000, 80],
        "dst_port": [80, 40000],
        "src2dst_syn_packets": [1, 0],
        "dst2src_syn_packets": [0, 1],
        W.FIRST: [1_000, 2_000],
    }
    flows = pl.DataFrame(base)
    side = sides(flows, "auto").select(W.SIDE_COLUMNS)
    a = W.assign_windows(flows, side, length_ms=L)
    assert a["attacker_ip"].to_list() == ["10.0.0.1", "10.0.0.1"]
    assert a["window_id"].n_unique() == 1


def test_windows_fields(flows, side):
    w = W.build_windows(flows, side, length_ms=L, seq_max=5, part="test")
    a = W.assign_windows(flows, side, length_ms=L)
    counts = a.group_by("window_id").len()
    j = w.join(counts, on="window_id")
    assert (j["n_flows"] == j["len"]).all()
    assert (w["truncated"] == (w["n_flows"] > 5)).all()
    assert (w["window_end_ms"] == w["window_start_ms"] + L).all()
    assert (w["part"] == "test").all()
    # Цели — по убыванию числа потоков
    for targets in w["targets"].to_list():
        ns = [t["n"] for t in targets]
        assert ns == sorted(ns, reverse=True)
    # flow_uids — в порядке времени начала
    starts = dict(zip(flows["flow_uid"], flows[W.FIRST], strict=True))
    for uids in w.filter(pl.col("n_flows") > 3)["flow_uids"].head(20).to_list():
        ts = [starts[u] for u in uids]
        assert ts == sorted(ts)


def test_shifts_only_on_request_and_overlap(flows, side):
    a0, w0 = W.windows_of_flows(flows, side, length_ms=L, seq_max=128)
    assert set(w0["shift_ms"].unique().to_list()) == {0}
    a, w = W.windows_of_flows(flows, side, length_ms=L, seq_max=128, shifts=[0, 15_000, 30_000])
    assert set(w["shift_ms"].unique().to_list()) == {0, 15_000, 30_000}
    # Каждый поток — ровно в одном окне каждой сетки
    assert a.height == 3 * flows.height
    s = w.filter(pl.col("shift_ms") == 15_000)
    assert ((s["window_start_ms"] - 15_000) % L == 0).all()
    # Окна с разными сдвигами не совпадают по id
    assert w["window_id"].n_unique() == w.height


def test_windows_never_cross_parts(synthetic_split):
    """SC-004: все потоки окна — из одной части разбиения (окна строятся внутри части)."""
    cfg = W.load_windows_config("configs/windows.yaml")
    split = pl.read_parquet(synthetic_split / "splits" / "unsw_time.parquet")
    part_of = dict(zip(split["flow_uid"], split["part"], strict=True))
    for part in ("train", "val", "test"):
        pw = W.build_part_windows(
            "unsw_time", part, cfg, data_dir=synthetic_split, direction="auto", shifts=(0,)
        )
        parts = {part_of[u] for uids in pw.windows["flow_uids"].to_list() for u in uids}
        assert parts == {part}


def test_holdout_is_tail_with_gap():
    starts = [i * L for i in range(100)]
    w = pl.DataFrame(
        {
            "window_start_ms": starts + [s + 15_000 for s in starts],
            "shift_ms": [0] * 100 + [15_000] * 100,
        }
    ).with_columns((pl.col("window_start_ms") + L).alias("window_end_ms"))
    fit, hold = W.train_holdout_split(w, 0.10, L)
    cut = w.filter(pl.Series(hold))["window_start_ms"].min()
    assert hold.sum() == 10
    assert (w.filter(pl.Series(hold))["shift_ms"] == 0).all()
    # Окна обучения закончились минимум за одно окно до хвоста
    assert w.filter(pl.Series(fit))["window_end_ms"].max() <= cut - L
    assert not (fit & hold).any()
