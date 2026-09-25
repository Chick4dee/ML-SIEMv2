"""Миграция хранилища 002 (схема 0) → 003 (схема 2): аудит не теряется и остаётся неизменяемым.

База 002 строится из настоящего DDL той фичи (tests/fixtures/soc_schema_002.sql), заполняется
прогоном, решениями и записями аудита, а потом её открывает код 003. Главное, что проверяем:
все записи аудита на месте с теми же entry_id/at/details, а триггеры запрета UPDATE/DELETE
после пересоздания таблицы снова работают (принцип V).
"""

import sqlite3
from pathlib import Path

import pytest

from mlsiem.soc import store

FIXTURES = Path(__file__).parents[1] / "fixtures"


def _old_db(path) -> sqlite3.Connection:
    """База в состоянии фичи 002: старый DDL, user_version = 0, данные и ≥ 5 записей аудита."""
    conn = store.connect(path)
    conn.executescript((FIXTURES / "soc_schema_002.sql").read_text(encoding="utf-8"))
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
    conn.execute(
        "INSERT INTO runs VALUES ('r1', 'split:x/test', 'h', 'd1', NULL, '2026-01-01T00:00:00Z', "
        "'2026-01-01T00:00:01Z', 10, 1, 1, '{}', '[]')"
    )
    conn.execute(
        "INSERT INTO incidents (incident_id, run_id, src_ip, attack_class, targets, first_seen_ms, "
        "last_seen_ms, n_alerts, max_score, mean_score, severity, severity_reason, created_at, "
        "updated_at) VALUES ('inc-1', 'r1', '1.1.1.1', 'dos', '[\"2.2.2.2\"]', 1, 2, 1, 0.9, 0.9, "
        "'medium', 'база', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO actions (action_id, incident_id, action_type, target, rule_id, rule_text) "
        "VALUES ('act-inc-1', 'inc-1', 'block_source_ip', '1.1.1.1', 'noisy_attack', 'правило')"
    )
    for i, event in enumerate(
        ["run_loaded", "action_proposed", "incident_status_changed", "action_executed"] * 2
    ):
        store.append_audit(
            conn,
            "vlad" if i % 2 else "system",
            event,
            run_id="r1",
            incident_id="inc-1",
            details={"n": i, "текст": "проверка"},
            at=f"2026-01-01T00:00:{i:02d}.000Z",
        )
    return conn


def _audit(conn):
    return [tuple(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY entry_id")]


def _names(conn, kind):
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = ?", (kind,))}


def test_migrate_002_database(tmp_path):
    conn = _old_db(tmp_path / "soc.db")
    before = _audit(conn)
    assert len(before) >= 5

    assert store.init_db(conn) is True
    # Фича 004: цепочка 0 → 2 → 3 проходит за один init_db
    assert conn.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION == 3

    cols = [r["name"] for r in conn.execute("PRAGMA table_info(incidents)")]
    assert "assignee" in cols
    assert conn.execute("SELECT assignee FROM incidents").fetchone()[0] is None
    # Все записи аудита — те же, с теми же entry_id, временем и деталями
    assert _audit(conn) == before

    # Новое событие принимается CHECK-ом, а старые запреты — на месте
    store.append_audit(conn, "vlad", "incident_assigned", incident_id="inc-1")
    with pytest.raises(sqlite3.DatabaseError, match="нельзя изменять"):
        conn.execute("UPDATE audit_log SET actor = 'x'")
    with pytest.raises(sqlite3.DatabaseError, match="нельзя удалять"):
        conn.execute("DELETE FROM audit_log")
    with pytest.raises(sqlite3.IntegrityError):
        store.append_audit(conn, "vlad", "что-то_новое")

    assert {"ix_alerts_run_time", "ix_incidents_assignee", "ix_audit_incident"} <= _names(
        conn, "index"
    )
    assert {"audit_log_no_update", "audit_log_no_delete"} <= _names(conn, "trigger")
    assert "audit_log_v1" not in _names(conn, "table")
    # Новые записи продолжают нумерацию, а не начинают её заново
    last = store.append_audit(conn, "vlad", "run_loaded")
    assert last == len(before) + 2


def test_second_init_changes_nothing(tmp_path):
    conn = _old_db(tmp_path / "soc.db")
    store.init_db(conn)
    audit = _audit(conn)
    schema = sorted(tuple(r) for r in conn.execute("SELECT type, name, sql FROM sqlite_master"))
    assert store.init_db(conn) is False
    assert _audit(conn) == audit
    assert sorted(tuple(r) for r in conn.execute("SELECT type, name, sql FROM sqlite_master")) == (
        schema
    )


def test_new_file_gets_current_schema(tmp_path):
    conn = store.connect(tmp_path / "new.db")
    assert store.init_db(conn) is False
    assert conn.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION
    assert "assignee" in [r["name"] for r in conn.execute("PRAGMA table_info(incidents)")]
    store.append_audit(conn, "vlad", "incident_assigned")
    assert {"ix_alerts_run_time", "ix_incidents_assignee"} <= _names(conn, "index")


def test_newer_database_refused(tmp_path):
    conn = store.connect(tmp_path / "future.db")
    store.init_db(conn)
    conn.execute(f"PRAGMA user_version = {store.SCHEMA_VERSION + 1}")
    with pytest.raises(store.SchemaTooNew, match="новее"):
        store.init_db(conn)


def test_failed_migration_rolls_back(tmp_path, monkeypatch):
    conn = _old_db(tmp_path / "soc.db")
    before = _audit(conn)
    schema_before = sorted(tuple(r) for r in conn.execute("SELECT type, name FROM sqlite_master"))
    steps = list(store.MIGRATION_V2)
    # Сбой в середине: после переименования аудита и переноса строк, но до конца миграции
    steps.insert(steps.index(next(s for s in steps if s.startswith("DROP TABLE"))), "SELECT boom()")
    monkeypatch.setattr(store, "MIGRATION_V2", tuple(steps))
    with pytest.raises(sqlite3.OperationalError):
        store.init_db(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
    assert "assignee" not in [r["name"] for r in conn.execute("PRAGMA table_info(incidents)")]
    assert sorted(tuple(r) for r in conn.execute("SELECT type, name FROM sqlite_master")) == (
        schema_before
    )
    assert _audit(conn) == before
    with pytest.raises(sqlite3.DatabaseError, match="нельзя удалять"):
        conn.execute("DELETE FROM audit_log")
