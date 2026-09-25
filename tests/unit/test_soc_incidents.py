"""Группировка алертов в инциденты и серьёзность (FR-012, FR-013)."""

import json
import re
from pathlib import Path

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


# ---------------------------------------------------------------- фича 004: атакующая сторона


def _response_case(direction):
    """Ответный поток 149.171.126.17:80 → 175.45.176.0 и прямой с того же атакующего."""
    from mlsiem.soc.verdicts import alerts_from_verdicts

    flows = pl.DataFrame(
        [
            {
                "flow_uid": "r/1",
                "capture_id": "c",
                "src_ip": "149.171.126.17",
                "src_port": 80,
                "dst_ip": "175.45.176.0",
                "dst_port": 40000,
                "protocol": 6,
                "bidirectional_first_seen_ms": 0,
                "bidirectional_last_seen_ms": 10,
                "src2dst_syn_packets": 0,
                "dst2src_syn_packets": 1,
            },
            {
                "flow_uid": "r/2",
                "capture_id": "c",
                "src_ip": "175.45.176.0",
                "src_port": 40001,
                "dst_ip": "149.171.126.18",
                "dst_port": 80,
                "protocol": 6,
                "bidirectional_first_seen_ms": MIN,
                "bidirectional_last_seen_ms": MIN + 10,
                "src2dst_syn_packets": 1,
                "dst2src_syn_packets": 1,
            },
        ]
    )
    verdicts = pl.DataFrame(
        {
            "flow_uid": ["r/1", "r/2"],
            "predicted_class": ["exploits", "exploits"],
            "attack_score": [0.99, 0.98],
            "is_alert": [True, True],
            "e_classifier_score": [0.99, 0.98],
            "e_classifier_fired": [True, True],
            "explanation": ["сработал классификатор", "сработал классификатор"],
        }
    )
    a = alerts_from_verdicts(verdicts, flows, direction=direction)
    return a, *group(a)


def test_reversed_alert_grouped_by_attacker():
    from mlsiem.soc.config import load_soc_config
    from mlsiem.soc.playbooks import propose_action

    a, with_inc, inc = _response_case("auto")
    row = a.filter(pl.col("flow_uid") == "r/1").row(0, named=True)
    # исходные src/dst не тронуты, а атакующий — вторая сторона
    assert (row["src_ip"], row["dst_ip"]) == ("149.171.126.17", "175.45.176.0")
    assert (row["attacker_ip"], row["victim_ip"], row["reversed"]) == (
        "175.45.176.0",
        "149.171.126.17",
        1,
    )
    assert "поток ответный" in row["explanation"] and "175.45.176.0" in row["explanation"]
    # оба алерта — один инцидент с ключом 175.45.176.0
    assert inc.height == 1
    i = inc.row(0, named=True)
    assert i["src_ip"] == "175.45.176.0"
    assert json.loads(i["targets"]) == ["149.171.126.17", "149.171.126.18"]
    rules = load_soc_config(Path(__file__).parents[2] / "configs" / "soc.yaml").rules
    action = propose_action({**i, "severity": "high"}, rules, ())
    assert action["action_type"] == "block_source_ip" and action["target"] == "175.45.176.0"


def test_as_is_is_002_behaviour():
    a, with_inc, inc = _response_case("as_is")
    assert (a["reversed"] == 0).all()
    assert sorted(inc["src_ip"]) == ["149.171.126.17", "175.45.176.0"]
    # байт в байт то же, что группировка 002 (без полей атакующей стороны)
    old = a.drop("attacker_ip", "victim_ip", "reversed", "direction_rule")
    _, inc_002 = group(old)
    assert inc.equals(inc_002)


def test_as_is_equals_auto_on_synthetic(synthetic_flows, tiny_detector):
    """На синтетике (инициатор — src) auto и as_is дают одни и те же инциденты."""
    from mlsiem.detect.artifact import load_detector
    from mlsiem.soc.verdicts import alerts_from_verdicts, compute_verdicts

    flows = pl.concat(list(synthetic_flows.values()))
    det = load_detector(tiny_detector)
    out = {}
    for mode in ("auto", "as_is"):
        v = compute_verdicts(det, flows, direction=mode)
        out[mode] = group_alerts(
            alerts_from_verdicts(v, flows, direction=mode),
            window_ms=W,
            run_id="run-1",
            severity_base={c: "medium" for c in det.classes},
            bump_at=100,
        )[1]
    assert out["auto"].equals(out["as_is"])
