"""Запись прогона: одна транзакция (FR-028), формат run_id, прогоны не смешиваются."""

import json
import re
from datetime import UTC, datetime

import pytest

from mlsiem.soc import store


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "soc.db")
    store.init_db(c)
    yield c
    c.close()


def make_run(run_id, n=3):
    incidents = [
        {
            "incident_id": f"inc-{run_id}-{i}",
            "src_ip": "1.1.1.1",
            "attack_class": "dos",
            "targets": json.dumps(["9.9.9.1"]),
            "first_seen_ms": i * 1000,
            "last_seen_ms": i * 1000 + 10,
            "n_alerts": 1,
            "max_score": 0.9,
            "mean_score": 0.9,
            "severity": "medium",
            "severity_reason": "базовый уровень класса dos = medium",
        }
        for i in range(n)
    ]
    alerts = [
        {
            "incident_id": inc["incident_id"],
            "flow_uid": f"cap/{i}",
            "capture_id": "cap",
            "src_ip": "1.1.1.1",
            "src_port": 1000,
            "dst_ip": "9.9.9.1",
            "dst_port": 80,
            "protocol": 6,
            "first_seen_ms": i * 1000,
            "last_seen_ms": i * 1000 + 10,
            "predicted_class": "dos",
            "attack_score": 0.9,
        }
        for i, inc in enumerate(incidents)
    ]
    run = {
        "run_id": run_id,
        "source": "split:unsw_time/test",
        "input_hash": "abcdef0123",
        "detector_version": "20260924-deadbeef",
        "started_at": store.now_iso(),
        "n_flows": 100,
        "summary": {"x": 1},
        "warnings": [],
    }
    return run, alerts, incidents


def count(conn, table, run_id):
    return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id = ?", (run_id,)).fetchone()[0]


def test_write_run(conn):
    store.write_run(conn, *make_run("r1"))
    assert count(conn, "runs", "r1") == 1
    assert count(conn, "incidents", "r1") == 3
    assert count(conn, "alerts", "r1") == 3
    inc = conn.execute("SELECT * FROM incidents LIMIT 1").fetchone()
    assert inc["status"] == "new" and inc["version"] == 1 and inc["resolution"] is None
    audit = conn.execute("SELECT * FROM audit_log WHERE event = 'run_loaded'").fetchone()
    assert audit["actor"] == "system" and audit["run_id"] == "r1"
    run = store.list_runs(conn)[0]
    assert run["n_alerts"] == 3 and run["n_incidents"] == 3
    assert run["incidents_by_status"] == {"new": 3, "in_progress": 0, "closed": 0}


def test_failure_leaves_nothing(conn, monkeypatch):
    run, alerts, incidents = make_run("r1")
    alerts[-1]["incident_id"] = "inc-которого-нет"  # нарушение внешнего ключа посреди записи
    with pytest.raises(Exception):  # noqa: B017 — важно лишь, что запись сорвалась
        store.write_run(conn, run, alerts, incidents)
    for table in ("runs", "incidents", "alerts"):
        assert count(conn, table, "r1") == 0
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0


def test_failure_in_middle_by_patched_insert(conn, monkeypatch):
    real = store._insert_many

    def boom(c, table, columns, rows):
        if table == "alerts":
            raise RuntimeError("сбой при записи алертов")
        return real(c, table, columns, rows)

    monkeypatch.setattr(store, "_insert_many", boom)
    with pytest.raises(RuntimeError):
        store.write_run(conn, *make_run("r1"))
    assert count(conn, "runs", "r1") == 0
    assert count(conn, "incidents", "r1") == 0


def test_run_id_format_and_unique(conn):
    now = datetime(2026, 9, 24, 10, 15, 0, tzinfo=UTC)
    rid = store.new_run_id(conn, "a1b2c3d4e5", now=now)
    assert rid == "20260924T101500-a1b2c3"
    assert re.fullmatch(r"\d{8}T\d{6}-[0-9a-f]{6}", rid)
    store.write_run(conn, *make_run(rid))
    rid2 = store.new_run_id(conn, "a1b2c3d4e5", now=now)
    assert rid2 != rid


def test_two_runs_do_not_mix(conn):
    store.write_run(conn, *make_run("r1"))
    store.write_run(conn, *make_run("r2", n=2))
    assert count(conn, "incidents", "r1") == 3
    assert count(conn, "incidents", "r2") == 2
    assert [r["run_id"] for r in store.list_runs(conn)] == ["r2", "r1"]
