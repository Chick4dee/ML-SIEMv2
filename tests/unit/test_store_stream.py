"""Запись пачки потребителя (`store.append_batch`, FR-012, FR-014, FR-015, FR-017, FR-020).

Одна транзакция на пачку, повтор без дублей, рост инцидента после решения аналитика не
трогает решение, серьёзность и предложение пересчитываются, конфликт с аналитиком ловится
версией.
"""

import sqlite3
from pathlib import Path

import polars as pl
import pytest

from mlsiem.soc import store
from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.stream.incremental import plan_batch

REPO = Path(__file__).parents[2]
A = "175.45.176.1"
T = ("mlsiem.flows", 0)


@pytest.fixture(scope="module")
def soc_cfg():
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    return parse_soc_config({**raw, "severity": {**raw["severity"], "bump_at": 3}})


@pytest.fixture
def db(tmp_path):
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    run = store.create_session(conn, "replay:x:1", model_version="m1", summary={"model": {}})
    return conn, run["run_id"]


def _alert(uid, t, cls="reconnaissance", victim="149.171.126.10"):
    return {
        "flow_uid": uid,
        "capture_id": "c",
        "src_ip": A,
        "src_port": 4000,
        "dst_ip": victim,
        "dst_port": 80,
        "protocol": 6,
        "first_seen_ms": t,
        "last_seen_ms": t + 10,
        "predicted_class": cls,
        "attack_score": 0.9,
        "attacker_ip": A,
        "victim_ip": victim,
        "reversed": 0,
        "direction_rule": "default",
        "fired_experts": "classifier",
        "experts": None,
        "explanation": None,
    }


def _plan(conn, run_id, soc_cfg, rows):
    frame = pl.DataFrame(rows, schema_overrides={"experts": pl.String, "explanation": pl.String})
    return plan_batch(conn, run_id, frame, soc_cfg)


def _write(conn, run_id, soc_cfg, rows, offset):
    plan = _plan(conn, run_id, soc_cfg, rows)
    store.append_batch(
        conn,
        [plan],
        offsets={T: offset},
        seen={run_id: [(r["flow_uid"], i) for i, r in enumerate(rows)]},
        sessions={run_id: {"n_flows": len(rows)}},
    )
    return plan


def _counts(conn):
    return {
        t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        for t in ("alerts", "incidents", "actions", "audit_log", "stream_seen", "stream_offsets")
    }


def test_new_incident_with_action_and_offsets(db, soc_cfg):
    conn, run_id = db
    _write(conn, run_id, soc_cfg, [_alert("f1", 1000)], 5)
    inc = store.list_incidents(conn, {"run_id": run_id})[1][0]
    assert inc["n_alerts"] == 1 and inc["action"]["state"] == "proposed"
    assert store.load_offsets(conn) == {T: 5}
    run = store.get_run(conn, run_id)
    assert (run["n_flows"], run["n_alerts"], run["n_incidents"]) == (1, 1, 1)
    alert = conn.execute("SELECT late, received_at FROM alerts").fetchone()
    assert alert["late"] == 0 and alert["received_at"]


def test_failure_mid_batch_writes_nothing(db, soc_cfg, monkeypatch):
    conn, run_id = db
    _write(conn, run_id, soc_cfg, [_alert("f1", 1000)], 5)
    before = _counts(conn)
    plan = _plan(conn, run_id, soc_cfg, [_alert("f2", 2000), _alert("f3", 3000)])
    real = store._apply_plan

    def boom(*a, **kw):
        real(*a, **kw)
        raise sqlite3.OperationalError("диск полон (имитация)")

    monkeypatch.setattr(store, "_apply_plan", boom)
    with pytest.raises(sqlite3.OperationalError):
        store.append_batch(conn, [plan], offsets={T: 9}, seen={run_id: [("f2", 1), ("f3", 2)]})
    assert _counts(conn) == before
    assert store.load_offsets(conn) == {T: 5}


def test_repeat_batch_no_duplicates(db, soc_cfg):
    conn, run_id = db
    rows = [_alert("f1", 1000), _alert("f2", 2000)]
    _write(conn, run_id, soc_cfg, rows, 2)
    before = _counts(conn)
    inc_before = store.list_incidents(conn, {"run_id": run_id})[1][0]
    plan = _plan(conn, run_id, soc_cfg, rows)
    assert plan.alerts == [] and plan.updates == [] and plan.new_incidents == []
    store.append_batch(conn, [plan], offsets={T: 2}, seen={run_id: [("f1", 0), ("f2", 1)]})
    after = _counts(conn)
    assert {k: v for k, v in after.items() if k != "audit_log"} == {
        k: v for k, v in before.items() if k != "audit_log"
    }
    assert (
        store.list_incidents(conn, {"run_id": run_id})[1][0]["n_alerts"] == inc_before["n_alerts"]
    )


def test_after_decision_keeps_decision(db, soc_cfg):
    conn, run_id = db
    _write(conn, run_id, soc_cfg, [_alert("f1", 1000, "exploits")], 1)
    inc = store.list_incidents(conn, {"run_id": run_id})[1][0]
    store.confirm_action(conn, inc["action"]["action_id"], "vlad", 1)
    store.change_status(conn, inc["incident_id"], "vlad", "closed", "confirmed", "всё ясно", 1)
    _write(
        conn, run_id, soc_cfg, [_alert("f2", 5000, "exploits"), _alert("f3", 4000, "exploits")], 3
    )
    got = store.get_incident(conn, inc["incident_id"])
    assert got["status"] == "closed" and got["resolution"] == "confirmed"
    assert got["action"]["state"] == "executed" and got["action"]["action_type"] == "isolate_host"
    assert got["n_alerts"] == 3
    assert got["alerts_after_decision"] == 2 and got["first_after_decision_ms"] == 4000
    upd = [
        e
        for e in store.incident_audit(conn, inc["incident_id"])
        if e["event"] == "incident_updated"
    ]
    assert upd[-1]["details"]["after_decision"] is True and upd[-1]["actor"] == "system"
    # ещё пачка — счётчик растёт, «первый» остаётся минимумом
    _write(conn, run_id, soc_cfg, [_alert("f4", 9000, "exploits")], 4)
    got = store.get_incident(conn, inc["incident_id"])
    assert got["alerts_after_decision"] == 3 and got["first_after_decision_ms"] == 4000
    assert store.list_incidents(conn, {"run_id": run_id, "after_decision": "only"})[0] == 1


def test_severity_growth_history_and_reproposal(db, soc_cfg):
    conn, run_id = db
    _write(conn, run_id, soc_cfg, [_alert("f1", 1000)], 1)
    inc = store.list_incidents(conn, {"run_id": run_id})[1][0]
    assert inc["severity"] == "low" and inc["action"]["action_type"] == "observe"
    _write(conn, run_id, soc_cfg, [_alert(f"g{i}", 2000 + i) for i in range(3)], 4)
    got = store.get_incident(conn, inc["incident_id"])
    assert got["severity"] == "medium" and got["n_alerts"] == 4
    hist = [h for h in got["history"] if h["field"] == "severity"]
    assert hist == [
        {
            "at": hist[0]["at"],
            "analyst": "system",
            "field": "severity",
            "old": "low",
            "new": "medium",
            "comment": got["severity_reason"],
        }
    ]
    # Правило recon (min_severity: medium) теперь подходит — предложение пересчитано
    assert got["action"]["action_type"] == "block_source_ip"
    assert got["action"]["version"] == 2 and got["action"]["state"] == "proposed"
    events = [e for e in store.incident_audit(conn, inc["incident_id"])]
    rep = [e for e in events if e["event"] == "action_reproposed"]
    assert rep and rep[0]["details"]["old"]["action_type"] == "observe"
    assert rep[0]["details"]["new"]["action_type"] == "block_source_ip"


def test_concurrent_analyst_decision_conflict_then_replan(db, soc_cfg):
    conn, run_id = db
    _write(conn, run_id, soc_cfg, [_alert("f1", 1000)], 1)
    inc = store.list_incidents(conn, {"run_id": run_id})[1][0]
    plan = _plan(conn, run_id, soc_cfg, [_alert(f"g{i}", 2000 + i) for i in range(3)])
    # Пока план готовился, аналитик (другое соединение) отклонил предложение
    other = store.connect(conn.execute("PRAGMA database_list").fetchone()[2])
    store.reject_action(other, inc["action"]["action_id"], "vlad", 1, "не нужно")
    with pytest.raises(store.Conflict):
        store.append_batch(conn, [plan], offsets={T: 4})
    # Пересчёт плана: решение аналитика сохранено, алерты дописаны «после решения»
    _write(conn, run_id, soc_cfg, [_alert(f"g{i}", 2000 + i) for i in range(3)], 4)
    got = store.get_incident(conn, inc["incident_id"])
    assert got["action"]["state"] == "rejected" and got["action"]["decided_by"] == "vlad"
    assert got["action"]["action_type"] == "observe"
    assert got["n_alerts"] == 4 and got["alerts_after_decision"] == 3


def test_session_status_and_audit(db):
    conn, run_id = db
    assert store.set_session_status(conn, run_id, "stopped", "Ctrl+C") is True
    assert store.set_session_status(conn, run_id, "stopped", "ещё раз") is False
    assert store.get_run(conn, run_id)["status"] == "stopped"
    ev = store.list_audit(conn, {"event": "session_status_changed"})[1]
    assert ev[0]["details"] == {"old": "running", "new": "stopped", "reason": "Ctrl+C"}
    with pytest.raises(store.BadRequest):
        store.set_session_status(conn, run_id, "paused", "")


def test_create_session_idempotent(db):
    conn, run_id = db
    again = store.create_session(conn, "replay:x:1", model_version="m1", summary={})
    assert again["run_id"] == run_id
    assert len(store.list_audit(conn, {"event": "run_loaded"})[1]) == 1


def test_lease(tmp_path):
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    store.acquire_lease(conn, "host:1", 30, now=1000.0)
    with pytest.raises(store.LeaseHeld, match="уже работает потребитель host:1"):
        store.acquire_lease(conn, "host:2", 30, now=1010.0)
    assert store.lease_info(conn, 30, now=1010.0)["alive"] is True
    # Истекла — второй забирает, первый при продлении узнаёт о потере
    store.acquire_lease(conn, "host:2", 30, now=1031.0)
    assert store.renew_lease(conn, "host:1", now=1032.0) is False
    assert store.renew_lease(conn, "host:2", now=1032.0) is True
    store.release_lease(conn, "host:2")
    assert store.lease_info(conn, 30, now=1033.0)["alive"] is False
