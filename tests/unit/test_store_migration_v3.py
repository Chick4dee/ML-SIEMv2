"""Миграция хранилища 003 (схема 2) → 004 (схема 3): только добавления, ничего не теряется.

База схемы 2 строится из снимка DDL фичи 003 (tests/fixtures/soc_schema_v2.sql) и заполняется
прогоном, алертами, решением и аудитом. После `init_db`: новые колонки алертов на месте,
атакующая сторона старых алертов = src_ip (как группировал 002), ответы экспертов — NULL
(«прогон до ансамбля»), а инциденты, действия, история и аудит — байт в байт прежние.
"""

import sqlite3
from pathlib import Path

import pytest

from mlsiem.soc import store

FIXTURES = Path(__file__).parents[1] / "fixtures"
NEW_ALERT_COLUMNS = (
    "attacker_ip",
    "victim_ip",
    "reversed",
    "fired_experts",
    "experts",
    "explanation",
)


def _v2_db(path) -> sqlite3.Connection:
    conn = store.connect(path)
    conn.executescript((FIXTURES / "soc_schema_v2.sql").read_text(encoding="utf-8"))
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    conn.execute(
        "INSERT INTO runs VALUES ('r1', 'split:x/test', 'h', 'd1', NULL, '2026-01-01T00:00:00Z', "
        "'2026-01-01T00:00:01Z', 10, 2, 1, '{}', '[]')"
    )
    conn.execute(
        "INSERT INTO incidents (incident_id, run_id, src_ip, attack_class, targets, first_seen_ms, "
        "last_seen_ms, n_alerts, max_score, mean_score, severity, severity_reason, created_at, "
        "updated_at, assignee) VALUES ('inc-1', 'r1', '1.1.1.1', 'dos', '[\"2.2.2.2\"]', 1, 2, 2, "
        "0.9, 0.9, 'medium', 'база', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'alice')"
    )
    for i in range(2):
        conn.execute(
            "INSERT INTO alerts (alert_id, run_id, incident_id, flow_uid, capture_id, src_ip, "
            "src_port, dst_ip, dst_port, protocol, first_seen_ms, last_seen_ms, predicted_class, "
            f"attack_score) VALUES ('r1/f{i}', 'r1', 'inc-1', 'f{i}', 'c', '1.1.1.1', 4000, "
            f"'2.2.2.{i + 2}', 80, 6, {i + 1}, {i + 2}, 'dos', 0.9)"
        )
    conn.execute(
        "INSERT INTO actions (action_id, incident_id, action_type, target, rule_id, rule_text) "
        "VALUES ('act-inc-1', 'inc-1', 'block_source_ip', '1.1.1.1', 'noisy_attack', 'правило')"
    )
    conn.execute(
        "INSERT INTO incident_history (incident_id, at, analyst, field, old, new, comment) "
        "VALUES ('inc-1', '2026-01-01T00:00:05Z', 'alice', 'assignee', NULL, 'alice', NULL)"
    )
    for i, event in enumerate(["run_loaded", "action_proposed", "incident_assigned"]):
        store.append_audit(
            conn,
            "system",
            event,
            run_id="r1",
            incident_id="inc-1",
            details={"n": i},
            at=f"2026-01-01T00:00:{i:02d}.000Z",
        )
    return conn


def _rows(conn, table, order, cols=None):
    what = ", ".join(f'"{c}"' for c in cols) if cols else "*"
    return [tuple(r) for r in conn.execute(f"SELECT {what} FROM {table} ORDER BY {order}")]


SNAPSHOT_TABLES = {
    "incidents": "incident_id",
    "actions": "action_id",
    "incident_history": "history_id",
    "audit_log": "entry_id",
    "runs": "run_id",
}


def _columns(conn):
    return {
        t: [r["name"] for r in conn.execute(f"PRAGMA table_info({t})")] for t in SNAPSHOT_TABLES
    }


def _snapshot(conn, cols=None):
    """Строки таблиц; `cols` — только эти колонки (схема 4 фичи 005 добавляет свои колонки
    к runs и incidents — сравниваем то, что было в схеме 2, байт в байт)."""
    cols = cols or {}
    return {t: _rows(conn, t, order, cols.get(t)) for t, order in SNAPSHOT_TABLES.items()}


def test_migrate_v2_to_v3(tmp_path):
    conn = _v2_db(tmp_path / "soc.db")
    before = _snapshot(conn)
    cols_v2 = _columns(conn)
    n_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    assert store.init_db(conn) is True
    assert conn.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION
    cols = {r["name"]: r for r in conn.execute("PRAGMA table_info(alerts)")}
    for c in NEW_ALERT_COLUMNS:
        assert c in cols
    assert cols["reversed"]["notnull"] == 1 and cols["reversed"]["dflt_value"] == "0"

    rows = conn.execute("SELECT * FROM alerts").fetchall()
    assert len(rows) == n_alerts
    for r in rows:
        assert r["attacker_ip"] == r["src_ip"] and r["victim_ip"] == r["dst_ip"]
        assert r["reversed"] == 0
        assert r["experts"] is None and r["fired_experts"] is None and r["explanation"] is None
    # Всё, кроме алертов, — байт в байт как было (включая entry_id аудита)
    assert _snapshot(conn, cols_v2) == before
    idx = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert "ix_alerts_incident_experts" in idx

    # Запреты аудита на месте
    with pytest.raises(sqlite3.DatabaseError, match="нельзя изменять"):
        conn.execute("UPDATE audit_log SET actor = 'x'")
    with pytest.raises(sqlite3.DatabaseError, match="нельзя удалять"):
        conn.execute("DELETE FROM audit_log")


def test_second_init_is_noop(tmp_path):
    conn = _v2_db(tmp_path / "soc.db")
    store.init_db(conn)
    snap = _snapshot(conn)
    assert store.init_db(conn) is False
    assert _snapshot(conn) == snap


def test_chain_from_002(tmp_path):
    """База фичи 002 (схема 0) доходит до 3 за один init_db, аудит цел."""
    conn = store.connect(tmp_path / "soc.db")
    conn.executescript((FIXTURES / "soc_schema_002.sql").read_text(encoding="utf-8"))
    conn.execute(
        "INSERT INTO runs VALUES ('r1', 'split:x/test', 'h', 'd1', NULL, '2026-01-01T00:00:00Z', "
        "'2026-01-01T00:00:01Z', 10, 0, 0, '{}', '[]')"
    )
    store.append_audit(conn, "system", "run_loaded", run_id="r1", at="2026-01-01T00:00:00.000Z")
    audit = _rows(conn, "audit_log", "entry_id")
    assert store.init_db(conn) is True
    assert conn.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION
    assert _rows(conn, "audit_log", "entry_id") == audit
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(alerts)")]
    assert set(NEW_ALERT_COLUMNS) <= set(cols)
    assert "assignee" in [r["name"] for r in conn.execute("PRAGMA table_info(incidents)")]


def test_newer_refused(tmp_path):
    conn = store.connect(tmp_path / "future.db")
    store.init_db(conn)
    conn.execute(f"PRAGMA user_version = {store.SCHEMA_VERSION + 1}")
    with pytest.raises(store.SchemaTooNew):
        store.init_db(conn)


def test_failed_v3_migration_keeps_schema_2(tmp_path, monkeypatch):
    conn = _v2_db(tmp_path / "soc.db")
    before = _snapshot(conn)
    alerts_before = _rows(conn, "alerts", "alert_id")
    steps = list(store.MIGRATION_V3)
    steps.insert(steps.index(next(s for s in steps if s.startswith("UPDATE"))), "SELECT boom()")
    monkeypatch.setattr(store, "MIGRATION_V3", tuple(steps))
    with pytest.raises(sqlite3.OperationalError):
        store.init_db(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(alerts)")]
    assert not set(NEW_ALERT_COLUMNS) & set(cols)
    assert _snapshot(conn) == before
    assert _rows(conn, "alerts", "alert_id") == alerts_before


def test_write_run_without_new_fields(tmp_path):
    """Вызов в стиле 002/003 (без полей 004) пишет алерты с атакующим = src_ip."""
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    alert = {
        "flow_uid": "f1",
        "capture_id": "c",
        "src_ip": "1.1.1.1",
        "src_port": 4000,
        "dst_ip": "2.2.2.2",
        "dst_port": 80,
        "protocol": 6,
        "first_seen_ms": 1,
        "last_seen_ms": 2,
        "predicted_class": "dos",
        "attack_score": 0.9,
        "incident_id": "inc-1",
    }
    incident = {
        "incident_id": "inc-1",
        "src_ip": "1.1.1.1",
        "attack_class": "dos",
        "targets": '["2.2.2.2"]',
        "first_seen_ms": 1,
        "last_seen_ms": 2,
        "n_alerts": 1,
        "max_score": 0.9,
        "mean_score": 0.9,
        "severity": "medium",
        "severity_reason": "база",
    }
    store.write_run(
        conn,
        {
            "run_id": "r1",
            "source": "s",
            "input_hash": "h",
            "detector_version": "d",
            "started_at": "2026-01-01T00:00:00Z",
            "n_flows": 1,
        },
        [alert],
        [incident],
    )
    r = conn.execute("SELECT * FROM alerts").fetchone()
    assert (r["attacker_ip"], r["victim_ip"], r["reversed"], r["experts"]) == (
        "1.1.1.1",
        "2.2.2.2",
        0,
        None,
    )
