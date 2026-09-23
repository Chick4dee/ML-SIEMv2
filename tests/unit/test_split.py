"""Тесты разбиений на синтетических таблицах двух «дней» UNSW и сценариев CTU-13."""

import polars as pl
import pytest

from mlsiem.data.config import SplitConfig
from mlsiem.data.split import (
    FIRST,
    LAST,
    SplitInvariantError,
    check_invariants,
    compute_split,
    split_hash,
    summarize,
)

MIN = 60_000
GAP = 10 * MIN
CFG = SplitConfig(
    quantiles=(0.70, 0.85),
    gap_ms=GAP,
    ctu13_parts={"train": (1, 2, 3, 4, 5, 6, 9, 13), "val": (7, 10, 11), "test": (8, 12)},
)


def _day(day: str, n: int, t0: int, step: int = MIN, dur: int = 1000, labels=None):
    """n потоков через каждые step мс длительностью dur."""
    labels = labels or ["benign"] * n
    return pl.DataFrame(
        {
            "flow_uid": [f"unsw_{day}_01/{i}" for i in range(n)],
            "capture_id": [f"unsw_{day}_01"] * n,
            FIRST: [t0 + i * step for i in range(n)],
            LAST: [t0 + i * step + dur for i in range(n)],
            "label": labels,
        }
    )


def _two_days():
    d1 = _day("22-1-2015", 200, 0, labels=["benign"] * 150 + ["dos"] * 50)
    d2 = _day("17-2-2015", 300, 10**10)
    return pl.concat([d1, d2])


def test_unsw_time_boundaries_and_gap():
    flows = _two_days()
    assigned, parts = compute_split(flows, "unsw_time", CFG)
    check_invariants(assigned, parts, "unsw_time", GAP)

    day1 = assigned.filter(pl.col("capture_id") == "unsw_22-1-2015_01").sort(FIRST)
    # граница 0.70 из 200 потоков — начало 140-го потока; зазор ±10 минут
    b1 = 140 * MIN
    for row in day1.iter_rows(named=True):
        if row[FIRST] <= b1 + GAP and row[LAST] >= b1 - GAP:
            assert row["part"] is None, row
    assert day1.filter(pl.col(FIRST) < b1 - GAP)["part"].unique().to_list() == ["train"]

    # границы считаются внутри каждого дня: у второго дня тоже есть все три части
    day2 = assigned.filter(pl.col("capture_id") == "unsw_17-2-2015_01")
    assert set(day2["part"].drop_nulls().unique().to_list()) == {"train", "val", "test"}

    _, excluded, missing = summarize(assigned, parts)
    assert excluded["total"] == assigned["part"].null_count() > 0
    assert sum(excluded["by_label"].values()) == excluded["total"]
    # dos есть только в конце первого дня → в train его нет
    assert "dos" in missing["train"]


def test_unsw_cross_day():
    assigned, parts = compute_split(_two_days(), "unsw_cross_day", CFG)
    check_invariants(assigned, parts, "unsw_cross_day", GAP)
    day2 = assigned.filter(pl.col("capture_id") == "unsw_17-2-2015_01")
    assert day2["part"].to_list() == ["test"] * 300
    day1 = assigned.filter(pl.col("capture_id") == "unsw_22-1-2015_01")
    assert set(day1["part"].drop_nulls().unique().to_list()) == {"train", "val"}
    b = 170 * MIN  # квантиль 0.85 из 200
    assert day1.filter(pl.col(FIRST) < b - GAP)["part"].unique().to_list() == ["train"]


def _ctu(scenarios=range(1, 14)):
    rows = []
    for s in scenarios:
        for i in range(3):
            rows.append(
                (
                    f"ctu13_{s:02d}/{i}",
                    f"ctu13_{s:02d}",
                    s * 10**6 + i,
                    s * 10**6 + i,
                    "botnet" if i else "background",
                )
            )
    return pl.DataFrame(rows, schema=["flow_uid", "capture_id", FIRST, LAST, "label"], orient="row")


def test_ctu13_scenario_whole_in_one_part():
    assigned, parts = compute_split(_ctu(), "ctu13_scenario", CFG)
    check_invariants(assigned, parts, "ctu13_scenario", GAP)
    per = assigned.group_by("capture_id").agg(pl.col("part").unique())
    for _cid, part in per.iter_rows():
        assert len(part) == 1
    assert assigned.filter(pl.col("capture_id") == "ctu13_08")["part"].unique().to_list() == [
        "test"
    ]
    assert "Murlo" in parts["test"]["new_families"]


def test_ctu13_requires_new_family_in_test():
    cfg = SplitConfig(
        CFG.quantiles,
        GAP,
        {"train": (1, 2, 3, 4, 5, 6, 7, 8, 12), "val": (10, 11), "test": (9, 13)},
    )
    with pytest.raises(ValueError, match="семейства"):
        compute_split(_ctu(), "ctu13_scenario", cfg)


def test_invariants_catch_duplicate_uid():
    assigned, parts = compute_split(_two_days(), "unsw_time", CFG)
    dup = pl.concat([assigned, assigned.head(1).with_columns(pl.lit("test").alias("part"))])
    with pytest.raises(SplitInvariantError, match="flow_uid"):
        check_invariants(dup, parts, "unsw_time", GAP)


def test_invariants_catch_overlapping_intervals():
    assigned, parts = compute_split(_two_days(), "unsw_time", CFG)
    iv = parts["val"]["intervals"][0]
    iv["start_ms"] -= 3 * GAP  # val залез на train
    with pytest.raises(SplitInvariantError, match="пересекаются"):
        check_invariants(assigned, parts, "unsw_time", GAP)


def test_invariants_catch_flow_in_gap():
    assigned, parts = compute_split(_two_days(), "unsw_time", CFG)
    leaked = assigned.with_columns(
        pl.when(pl.col("part").is_null())
        .then(pl.lit("train"))
        .otherwise(pl.col("part"))
        .alias("part")
    )
    with pytest.raises(SplitInvariantError, match="зазор"):
        check_invariants(leaked, parts, "unsw_time", GAP)


def test_hash_repeatable():
    flows = _two_days()
    a, _ = compute_split(flows, "unsw_time", CFG)
    b, _ = compute_split(flows.sample(fraction=1.0, shuffle=True, seed=3), "unsw_time", CFG)
    assert split_hash(a) == split_hash(b)
