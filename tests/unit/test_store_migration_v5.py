"""Миграция хранилища 005 (схема 4) → 007 (схема 5): только добавления (research R14).

База схемы 4 строится из снимка DDL фичи 005 (tests/fixtures/soc_schema_v4.sql), не из
текущего кода. После `init_db`: у старых алертов `alert_kind = 'flow'`, есть `window_info`,
таблицы незакрытых окон и индекс на месте, данные и аудит не тронуты.
"""

import sqlite3
from pathlib import Path

import pytest

from mlsiem.soc import store

FIXTURES = Path(__file__).parents[1] / "fixtures"


def _v4_db(path) -> sqlite3.Connection:
    conn = store.connect(path)
    conn.executescript((FIXTURES / "soc_schema_v4.sql").read_text(encoding="utf-8"))
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 4
    conn.execute(
        "INSERT INTO runs (run_id, source, input_hash, detector_version, started_at, finished_at, "
        "n_flows, n_alerts, n_incidents, summary, warnings) VALUES ('r1', 'split:x/test', 'h', "
        "'d1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 10, 1, 1, '{}', '[]')"
    )
    conn.execute(
        "INSERT INTO incidents (incident_id, run_id, src_ip, attack_class, targets, first_seen_ms, "
        "last_seen_ms, n_alerts, max_score, mean_score, severity, severity_reason, created_at, "
        "updated_at) VALUES ('inc-1', 'r1', '1.1.1.1', 'dos', '[]', 100, 200, 1, 0.9, 0.9, "
        "'medium', 'база', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO alerts (alert_id, run_id, incident_id, flow_uid, capture_id, src_ip, "
        "first_seen_ms, last_seen_ms, predicted_class, attack_score) VALUES "
        "('r1/f0', 'r1', 'inc-1', 'f0', 'c', '1.1.1.1', 100, 200, 'dos', 0.9)"
    )
    store.append_audit(conn, "system", "run_loaded", run_id="r1")
    return conn


def _columns(conn, table) -> dict[str, str]:
    return {r[1]: r[2] for r in conn.execute(f"PRAGMA table_info({table})")}


def test_migrate_v4_to_v5(tmp_path):
    conn = _v4_db(tmp_path / "soc.db")
    audit_before = conn.execute("SELECT * FROM audit_log").fetchall()
    assert store.init_db(conn) is True
    # фича 006 довела схему до 6: цепочка 4 → 5 → 6, здесь проверяем часть 007
    assert conn.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION == 6
    cols = _columns(conn, "alerts")
    assert "alert_kind" in cols and "window_info" in cols
    a = store.get_alert(conn, "r1", "f0")
    assert a["alert_kind"] == "flow" and a["window_info"] is None
    assert set(_columns(conn, "window_pending")) == {
        "run_id",
        "flow_uid",
        "window_id",
        "window_start_ms",
        "attacker_ip",
        "payload",
    }
    assert set(_columns(conn, "window_closed")) == {"run_id", "window_id", "closed_at", "n_flows"}
    idx = {r[1] for r in conn.execute("PRAGMA index_list(window_pending)")}
    assert "ix_window_pending_start" in idx
    assert conn.execute("SELECT * FROM audit_log").fetchall() == audit_before


def test_alert_kind_check(tmp_path):
    conn = _v4_db(tmp_path / "soc.db")
    store.init_db(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE alerts SET alert_kind = 'packet'")


def test_pending_primary_key(tmp_path):
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    row = ("s", "f1", "w-1", 0, "1.1.1.1", b"{}")
    conn.execute("INSERT INTO window_pending VALUES (?, ?, ?, ?, ?, ?)", row)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO window_pending VALUES (?, ?, ?, ?, ?, ?)", row)


def test_chain_from_v3(tmp_path):
    conn = store.connect(tmp_path / "soc.db")
    conn.executescript((FIXTURES / "soc_schema_v3.sql").read_text(encoding="utf-8"))
    store.init_db(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION
    assert "alert_kind" in _columns(conn, "alerts")
    assert "window_pending" in {
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def test_newer_refused(tmp_path):
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    conn.execute(f"PRAGMA user_version = {store.SCHEMA_VERSION + 1}")
    with pytest.raises(store.SchemaTooNew, match="новее"):
        store.init_db(conn)
