"""Схема SQLite: таблицы, индексы, WAL и аудит-журнал, который нельзя изменить."""

import json
import sqlite3
from datetime import datetime

import pytest

from mlsiem.soc import store

TABLES = {"runs", "alerts", "incidents", "incident_history", "actions", "audit_log"}


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "sub" / "soc.db")
    store.init_db(c)
    yield c
    c.close()


def _names(conn, kind):
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = ?", (kind,)).fetchall()
    return {r["name"] for r in rows}


def test_tables_and_indexes(conn):
    assert _names(conn, "table") >= TABLES
    indexes = _names(conn, "index")
    for ix in (
        "ix_incidents_run",
        "ix_incidents_severity",
        "ix_incidents_status",
        "ix_incidents_class",
        "ix_alerts_incident",
        "ix_audit_incident",
    ):
        assert ix in indexes
    assert {"audit_log_no_update", "audit_log_no_delete"} <= _names(conn, "trigger")


def test_init_twice_is_harmless(conn):
    store.append_audit(conn, "system", "run_loaded", details={"x": 1})
    store.init_db(conn)
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1


def test_wal_and_foreign_keys(conn):
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_audit_is_append_only(conn):
    entry = store.append_audit(conn, "vlad", "incident_status_changed", incident_id="inc-1")
    with pytest.raises(sqlite3.DatabaseError, match="нельзя изменять"):
        conn.execute("UPDATE audit_log SET actor = 'кто-то' WHERE entry_id = ?", (entry,))
    with pytest.raises(sqlite3.DatabaseError, match="нельзя удалять"):
        conn.execute("DELETE FROM audit_log WHERE entry_id = ?", (entry,))
    assert conn.execute("SELECT actor FROM audit_log").fetchone()[0] == "vlad"


def test_append_audit_format(conn):
    store.append_audit(
        conn,
        "system",
        "action_proposed",
        run_id="r1",
        incident_id="inc-1",
        action_id="act-inc-1",
        details={"rule": "recon", "target": "1.2.3.4"},
    )
    row = conn.execute("SELECT * FROM audit_log").fetchone()
    at = datetime.fromisoformat(row["at"].replace("Z", "+00:00"))
    assert at.utcoffset().total_seconds() == 0
    assert json.loads(row["details"]) == {"rule": "recon", "target": "1.2.3.4"}
    assert (row["run_id"], row["incident_id"], row["action_id"]) == ("r1", "inc-1", "act-inc-1")


def test_audit_event_checked(conn):
    with pytest.raises(sqlite3.IntegrityError):
        store.append_audit(conn, "system", "something_else")


def test_transaction_rolls_back(conn):
    with pytest.raises(RuntimeError), store.transaction(conn):
        store.append_audit(conn, "system", "run_loaded")
        raise RuntimeError("сбой посреди записи")
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0
