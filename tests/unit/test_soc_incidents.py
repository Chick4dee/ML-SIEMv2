"""Группировка алертов в инциденты и серьёзность (FR-012, FR-013)."""

import json
import re

import polars as pl
import pytest

from mlsiem.soc.incidents import group_alerts, severity

BASE = {"exploits": "high", "dos": "medium", "reconnaissance": "low", "worms": "high"}
W = 900_000
MIN = 60_000


def alerts(rows):
    """rows: (flow_uid, src_ip, класс, first_seen_ms, dst_ip, score)."""
    return pl.DataFrame(
        {
            "flow_uid": [r[0] for r in rows],
            "capture_id": ["c"] * len(rows),
            "src_ip": [r[1] for r in rows],
            "src_port": [1000] * len(rows),
            "dst_ip": [r[4] for r in rows],
            "dst_port": [80] * len(rows),
            "protocol": [6] * len(rows),
            "first_seen_ms": [r[3] for r in rows],
            "last_seen_ms": [r[3] + 500 for r in rows],
            "predicted_class": [r[2] for r in rows],
            "attack_score": [r[5] for r in rows],
        }
    )


def group(df, **kw):
    return group_alerts(
        df, window_ms=W, run_id="run-1", severity_base=BASE, bump_at=kw.get("bump_at", 100)
    )


def test_window_boundaries():
    df = alerts(
        [
            ("a/0", "1.1.1.1", "dos", 0, "9.9.9.1", 0.9),
            ("a/1", "1.1.1.1", "dos", W, "9.9.9.1", 0.8),  # ровно окно — тот же инцидент
            ("a/2", "1.1.1.1", "dos", 2 * W + 1, "9.9.9.2", 0.7),  # разрыв > окна — новый
        ]
    )
    with_inc, inc = group(df)
    assert inc.height == 2
    ids = dict(zip(with_inc["flow_uid"], with_inc["incident_id"], strict=True))
    assert ids["a/0"] == ids["a/1"] != ids["a/2"]


def test_two_classes_two_incidents():
    df = alerts(
        [
            ("a/0", "1.1.1.1", "dos", 0, "9.9.9.1", 0.9),
            ("a/1", "1.1.1.1", "exploits", MIN, "9.9.9.1", 0.9),
        ]
    )
    _, inc = group(df)
    assert inc.height == 2
    assert set(inc["attack_class"]) == {"dos", "exploits"}


def test_each_alert_in_exactly_one_incident():
    rows = [
        (f"a/{i}", f"1.1.1.{i % 3}", ["dos", "exploits"][i % 2], i * 7 * MIN, "9.9.9.1", 0.5)
        for i in range(60)
    ]
    with_inc, inc = group(alerts(rows))
    assert with_inc.height == 60
    assert with_inc["incident_id"].null_count() == 0
    assert inc["n_alerts"].sum() == 60
    assert set(with_inc["incident_id"]) == set(inc["incident_id"])


def test_incident_fields():
    df = alerts(
        [
            ("a/0", "1.1.1.1", "dos", 1000, "9.9.9.2", 0.6),
            ("a/1", "1.1.1.1", "dos", 5000, "9.9.9.1", 1.0),
            ("a/2", "1.1.1.1", "dos", 3000, "9.9.9.2", 0.8),
        ]
    )
    _, inc = group(df)
    row = inc.row(0, named=True)
    assert json.loads(row["targets"]) == ["9.9.9.1", "9.9.9.2"]
    assert row["first_seen_ms"] == 1000
    assert row["last_seen_ms"] == 5500
    assert row["n_alerts"] == 3
    assert row["max_score"] == pytest.approx(1.0)
    assert row["mean_score"] == pytest.approx(0.8)
    assert re.fullmatch(r"inc-[0-9a-f]{12}", row["incident_id"])


def test_incident_id_stable_under_permutation():
    rows = [(f"a/{i}", f"1.1.1.{i % 2}", "dos", i * 20 * MIN, "9.9.9.1", 0.5) for i in range(20)]
    df = alerts(rows)
    w1, i1 = group(df)
    w2, i2 = group(df.sample(fraction=1.0, shuffle=True, seed=3))
    assert i1.equals(i2)
    assert w1.sort("flow_uid").equals(w2.sort("flow_uid"))


def test_severity_levels():
    assert severity("reconnaissance", 5, BASE, 100)[0] == "low"
    assert severity("reconnaissance", 100, BASE, 100)[0] == "medium"
    assert severity("exploits", 99, BASE, 100)[0] == "high"
    level, reason = severity("exploits", 150, BASE, 100)
    assert level == "critical"
    assert "high" in reason and "150" in reason
    with pytest.raises(ValueError, match="severity.base"):
        severity("unknown", 1, BASE, 100)


def test_critical_does_not_grow():
    base = {"x": "critical"}
    assert severity("x", 1000, base, 100)[0] == "critical"


def test_severity_ignores_confidence():
    low = alerts([("a/0", "1.1.1.1", "dos", 0, "9.9.9.1", 0.01)])
    high = alerts([("a/0", "1.1.1.1", "dos", 0, "9.9.9.1", 0.99)])
    assert group(low)[1]["severity"].item() == group(high)[1]["severity"].item()


def test_bump_in_grouping():
    rows = [(f"a/{i}", "1.1.1.1", "dos", i * 1000, "9.9.9.1", 0.5) for i in range(5)]
    _, inc = group(alerts(rows), bump_at=5)
    assert inc["severity"].item() == "high"
    assert "+1" in inc["severity_reason"].item()


def test_empty():
    with_inc, inc = group(alerts([]).head(0))
    assert with_inc.height == 0 and inc.height == 0
