"""Тесты сверки с v1 на синтетических агрегатах и мини-таблицах."""

from pathlib import Path

import polars as pl

from mlsiem.data.compare_v1 import compare, load_notes, read_v1, unexplained, v1_capture_id


def _s(n, counts, matched=None):
    return {"n_flows": n, "label_counts": counts, "n_matched": matched}


def test_basic_numbers_and_shares():
    t = compare(
        {"unsw_22-1-2015_01": _s(100, {"benign": 90, "dos": 10})},
        {"unsw_22-1-2015_01": _s(103, {"benign": 93, "dos": 10})},
        {},
    )
    r = t.row(0, named=True)
    assert r["n_flows_v1"] == 100 and r["n_flows_v2"] == 103
    assert abs(r["rel_diff"] - 0.03) < 1e-12
    assert abs(r["max_class_share_diff_pp"] - 100 * abs(0.9 - 93 / 103)) < 1e-9
    assert unexplained(t) == []


def test_flow_count_diff_needs_explanation():
    v1 = {"ctu13_01": _s(100, {"botnet": 100}, 100)}
    v2 = {"ctu13_01": _s(110, {"botnet": 110}, 110)}
    assert [u["capture_id"] for u in unexplained(compare(v1, v2, {}))] == ["ctu13_01"]
    t = compare(v1, v2, {"ctu13_01": "в v2 другой active_timeout"})
    assert t["explained"][0] == "в v2 другой active_timeout"
    assert unexplained(t) == []


def test_share_diff_in_percentage_points():
    # редкий класс 2% → 3%: +50% относительно, но всего 1 п. п. — не тревога
    v1 = {"u": _s(100, {"benign": 98, "worms": 2})}
    ok = compare(v1, {"u": _s(100, {"benign": 97, "worms": 3})}, {})
    assert unexplained(ok) == []
    bad = compare(v1, {"u": _s(100, {"benign": 90, "worms": 10})}, {})
    assert bad["max_class_share_diff_pp"][0] > 5
    assert "п. п." in unexplained(bad)[0]["reason"]


def test_match_rate_drop_ctu13():
    v1 = {"ctu13_07": _s(51, {"botnet": 44, "unlabeled": 7}, 44)}
    v2 = {"ctu13_07": _s(51, {"botnet": 43, "unlabeled": 8}, 43)}
    assert "сопоставления" in unexplained(compare(v1, v2, {}))[0]["reason"]


def test_capture_missing_in_v1_is_marked_not_crash():
    t = compare({}, {"adhoc_x": _s(5, {"benign": 5})}, {})
    assert t["in_v1"].to_list() == [False]
    assert unexplained(t) == []


def test_notes_and_v1_files(tmp_path):
    notes = tmp_path / "notes.yaml"
    notes.write_text("ctu13_07: 'объяснение'\n", encoding="utf-8")
    assert load_notes(notes) == {"ctu13_07": "объяснение"}

    assert v1_capture_id(Path("22-1-2015__1.parquet")) == "unsw_22-1-2015_01"
    assert v1_capture_id(Path("scenario_07.parquet")) == "ctu13_07"
    assert v1_capture_id(Path("summary.parquet")) is None

    (tmp_path / "ctu13").mkdir()
    pl.DataFrame({"label_class": ["botnet", None, "normal"], "x": [1, 2, 3]}).write_parquet(
        tmp_path / "ctu13" / "scenario_07.parquet"
    )
    (tmp_path / "unsw").mkdir()
    pl.DataFrame({"canonical": ["benign", "dos"]}).write_parquet(
        tmp_path / "unsw" / "22-1-2015__1.parquet"
    )
    v1 = read_v1(tmp_path)
    assert v1["ctu13_07"] == _s(3, {"botnet": 1, "unlabeled": 1, "benign": 1}, 2)
    assert v1["unsw_22-1-2015_01"]["label_counts"] == {"benign": 1, "dos": 1}
