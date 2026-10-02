"""Отчёт по запуску сценария (фича 006, US3, FR-016).

На подставных алертах/инцидентах в хранилище: отчёт собирает только алерты окна запуска
(атакующий → цель, время в окне), классы, эксперты (вкл. окна 007), инциденты и задержки.
"""

import json

import pytest

from mlsiem.lab import journal
from mlsiem.lab.report import run_report, scenario_alerts
from mlsiem.soc import store

RUN = "stream-sensorlive00"
ATK, VICTIM = "10.88.0.30", "10.88.0.20"
START = "2026-10-02T12:00:00.000Z"
END = "2026-10-02T12:01:00.000Z"
W0 = journal.to_ms(START)


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "soc.db")
    store.init_db(c)
    c.execute(
        "INSERT INTO runs (run_id, source, input_hash, detector_version, started_at, finished_at, "
        "n_flows, n_alerts, n_incidents, summary, warnings, mode, status, source_id) VALUES "
        "(?, 'stream:sensor:live', 'h', 'd1', ?, ?, 0, 0, 0, '{}', '[]', 'stream', 'running', "
        "'sensor:live')",
        (RUN, START, START),
    )
    return c


def _iso(ms: int) -> str:
    from datetime import UTC, datetime

    return (
        datetime.fromtimestamp(ms / 1000, UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _incident(conn, inc_id, created_ms_offset):
    created = _iso(W0 + created_ms_offset)
    conn.execute(
        "INSERT INTO incidents (incident_id, run_id, src_ip, attack_class, targets, first_seen_ms, "
        "last_seen_ms, n_alerts, max_score, mean_score, severity, severity_reason, created_at, "
        "updated_at) VALUES "
        "(?, ?, ?, 'reconnaissance', '[]', ?, ?, 1, 0.9, 0.9, 'medium', 'x', ?, ?)",
        (inc_id, RUN, ATK, W0, W0 + 1000, created, created),
    )


def _alert(
    conn,
    uid,
    inc_id,
    *,
    first_ms,
    src=ATK,
    dst=VICTIM,
    cls="reconnaissance",
    experts=None,
    kind="flow",
    received=START,
):
    conn.execute(
        "INSERT INTO alerts (alert_id, run_id, incident_id, flow_uid, capture_id, src_ip, dst_ip, "
        "first_seen_ms, last_seen_ms, predicted_class, attack_score, attacker_ip, victim_ip, "
        "fired_experts, received_at, alert_kind) VALUES "
        "(?, ?, ?, ?, 'c', ?, ?, ?, ?, ?, 0.9, ?, ?, ?, ?, ?)",
        (
            uid,
            RUN,
            inc_id,
            uid,
            src,
            dst,
            first_ms,
            first_ms + 10,
            cls,
            src,
            dst,
            json.dumps(experts) if experts else None,
            received,
            kind,
        ),
    )


def _record(**over):
    base = dict(
        name="port_scan",
        version="1",
        attacker_ip=ATK,
        targets=[VICTIM],
        expected_class="reconnaissance",
        started_at=START,
        ended_at=END,
        outcome="completed",
    )
    base.update(over)
    return journal.make_record(**base)


def test_report_collects_window_alerts_and_experts(conn):
    _incident(conn, "inc-1", 0)
    _alert(conn, "a1", "inc-1", first_ms=W0 + 1000, experts=["classifier"])
    _alert(conn, "a2", "inc-1", first_ms=W0 + 2000, experts=["classifier", "anomaly"])
    # окно 007
    _alert(conn, "w1", "inc-1", first_ms=W0 + 3000, experts=["windows"], kind="window")
    # чужой поток (другой атакующий) и поток вне окна по времени — не считаются
    _alert(conn, "x1", "inc-1", first_ms=W0 + 1000, src="10.88.0.99")
    _alert(conn, "x2", "inc-1", first_ms=W0 + 10_000_000)

    rep = run_report(conn, RUN, _record(), margin_ms=0)
    assert rep["n_alerts"] == 3
    assert rep["n_window_alerts"] == 1 and rep["n_flow_alerts"] == 2
    assert rep["by_class"]["reconnaissance"] == 3
    assert rep["fired_experts"]["classifier"] == 2
    assert rep["fired_experts"]["anomaly"] == 1 and rep["fired_experts"]["windows"] == 1
    assert rep["incidents"] == ["inc-1"] and rep["n_incidents"] == 1


def test_scenario_alerts_filter_by_attacker_and_target(conn):
    _incident(conn, "inc-1", 0)
    _alert(conn, "a1", "inc-1", first_ms=W0 + 1000)  # верный
    _alert(conn, "a2", "inc-1", first_ms=W0 + 1000, dst="10.88.0.77")  # другая цель
    got = scenario_alerts(conn, RUN, _record(), margin_ms=0)
    assert [a["alert_id"] for a in got] == ["a1"]


def test_alert_share_from_dataset(conn):
    _incident(conn, "inc-1", 0)
    for i in range(3):
        _alert(conn, f"a{i}", "inc-1", first_ms=W0 + 1000 + i)
    rep = run_report(conn, RUN, _record(), margin_ms=0, dataset_flows=10)
    assert rep["alert_share"] == pytest.approx(0.3)
    md = __import__("mlsiem.lab.report", fromlist=["report_md"]).report_md(rep)
    assert "port_scan@1" in md and "доля с алертом" in md


def test_no_alerts_zero_report(conn):
    rep = run_report(conn, RUN, _record(), margin_ms=0)
    assert rep["n_alerts"] == 0 and rep["n_incidents"] == 0
    assert rep["first_alert_latency_s"] is None
