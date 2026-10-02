"""Миграция хранилища 004 (схема 3) → 005 (схема 4): только добавления, аудит пересоздан без потерь.

База схемы 3 строится из снимка DDL фичи 004 (tests/fixtures/soc_schema_v3.sql) и заполняется
прогоном, алертами, решением и аудитом. После `init_db`: прогоны стали `batch/completed`,
у инцидентов посчитана правая граница окна (`last_alert_start_ms`), служебные таблицы потока
на месте, а аудит — те же строки с теми же entry_id, принимает новые события и по-прежнему
не даёт себя менять.
"""

import sqlite3
from pathlib import Path

import pytest

from mlsiem.soc import store

FIXTURES = Path(__file__).parents[1] / "fixtures"
STREAM_TABLES = {
    "stream_offsets",
    "stream_seen",
    "stream_lease",
    "stream_stats",
    "stream_divergences",
}
NEW_EVENTS = ("incident_updated", "incident_merged", "action_reproposed", "session_status_changed")


def _v3_db(path) -> sqlite3.Connection:
    conn = store.connect(path)
    conn.executescript((FIXTURES / "soc_schema_v3.sql").read_text(encoding="utf-8"))
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
    conn.execute(
        "INSERT INTO runs VALUES ('r1', 'split:x/test', 'h', 'd1', NULL, '2026-01-01T00:00:00Z', "
        "'2026-01-01T00:00:01Z', 10, 3, 1, '{}', '[]')"
    )
    conn.execute(
        "INSERT INTO incidents (incident_id, run_id, src_ip, attack_class, targets, first_seen_ms, "
        "last_seen_ms, n_alerts, max_score, mean_score, severity, severity_reason, created_at, "
        "updated_at, assignee) VALUES ('inc-1', 'r1', '1.1.1.1', 'dos', '[\"2.2.2.2\"]', 100, "
        "900, 3, 0.9, 0.9, 'medium', 'база', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', "
        "'alice')"
    )
    # Время начала алертов 100, 300, 500, а конец последнего потока — 900: правая граница окна
    # после миграции — 500 (время НАЧАЛА), а не 900
    for i, start in enumerate((100, 300, 500)):
        conn.execute(
            "INSERT INTO alerts (alert_id, run_id, incident_id, flow_uid, capture_id, src_ip, "
            "src_port, dst_ip, dst_port, protocol, first_seen_ms, last_seen_ms, predicted_class, "
            "attack_score, attacker_ip, victim_ip) VALUES "
            f"('r1/f{i}', 'r1', 'inc-1', 'f{i}', 'c', '1.1.1.1', 4000, '2.2.2.2', 80, 6, {start}, "
            f"{start + 400}, 'dos', 0.9, '1.1.1.1', '2.2.2.2')"
        )
    conn.execute(
        "INSERT INTO actions (action_id, incident_id, action_type, target, rule_id, rule_text, "
        "state, decided_by) VALUES ('act-inc-1', 'inc-1', 'block_source_ip', '1.1.1.1', "
        "'noisy_attack', 'правило', 'executed', 'alice')"
    )
    conn.execute(
        "INSERT INTO incident_history (incident_id, at, analyst, field, old, new, comment) "
        "VALUES ('inc-1', '2026-01-01T00:00:05Z', 'alice', 'assignee', NULL, 'alice', NULL)"
    )
    for i, event in enumerate(["run_loaded", "action_proposed", "action_executed"]):
        store.append_audit(
            conn,
            "alice" if event == "action_executed" else "system",
            event,
            run_id="r1",
            incident_id="inc-1",
            details={"n": i, "текст": "проверка"},
            at=f"2026-01-01T00:00:{i:02d}.000Z",
        )
    return conn


def _rows(conn, table, order, cols=None):
    what = ", ".join(f'"{c}"' for c in cols) if cols else "*"
    return [tuple(r) for r in conn.execute(f"SELECT {what} FROM {table} ORDER BY {order}")]


TABLES = {
    "runs": "run_id",
    "incidents": "incident_id",
    "alerts": "alert_id",
    "actions": "action_id",
    "incident_history": "history_id",
    "audit_log": "entry_id",
}


def _columns(conn):
    return {t: [r["name"] for r in conn.execute(f"PRAGMA table_info({t})")] for t in TABLES}


def _snapshot(conn, cols=None):
    cols = cols or {}
    return {t: _rows(conn, t, order, cols.get(t)) for t, order in TABLES.items()}


def _names(conn, kind):
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = ?", (kind,))}


def test_migrate_v3_to_v4(tmp_path):
    conn = _v3_db(tmp_path / "soc.db")
    cols_v3 = _columns(conn)
    before = _snapshot(conn)

    assert store.init_db(conn) is True
    assert (
        conn.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION
    )  # 007: до 5, не 4

    run = conn.execute("SELECT * FROM runs").fetchone()
    assert (run["mode"], run["status"], run["source_id"], run["last_activity_at"]) == (
        "batch",
        "completed",
        None,
        None,
    )
    inc = conn.execute("SELECT * FROM incidents").fetchone()
    assert inc["last_alert_start_ms"] == 500
    assert inc["alerts_after_decision"] == 0
    assert inc["merged_into"] is None and inc["first_after_decision_ms"] is None
    assert {r["late"] for r in conn.execute("SELECT late FROM alerts")} == {0}
    assert _names(conn, "table") >= STREAM_TABLES
    assert {"ux_runs_source", "ix_incidents_after_decision"} <= _names(conn, "index")

    # Всё, что было в схеме 3, — байт в байт, включая entry_id, время и детали аудита
    assert _snapshot(conn, cols_v3) == before
    assert "audit_log_v3" not in _names(conn, "table")
    assert {"audit_log_no_update", "audit_log_no_delete"} <= _names(conn, "trigger")

    # Новые события принимаются, неизвестные — нет, запреты на месте
    for event in NEW_EVENTS:
        store.append_audit(conn, "system", event, run_id="r1")
    with pytest.raises(sqlite3.IntegrityError):
        store.append_audit(conn, "system", "что-то_новое")
    with pytest.raises(sqlite3.DatabaseError, match="нельзя изменять"):
        conn.execute("UPDATE audit_log SET actor = 'x'")
    with pytest.raises(sqlite3.DatabaseError, match="нельзя удалять"):
        conn.execute("DELETE FROM audit_log")
    # Нумерация аудита продолжается
    assert store.append_audit(conn, "system", "run_loaded") == 3 + len(NEW_EVENTS) + 1


def test_status_and_mode_checked(tmp_path):
    conn = _v3_db(tmp_path / "soc.db")
    store.init_db(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE runs SET status = 'paused'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE runs SET mode = 'online'")


def test_source_id_unique(tmp_path):
    conn = _v3_db(tmp_path / "soc.db")
    store.init_db(conn)
    conn.execute("UPDATE runs SET source_id = 'replay:a'")
    conn.execute(
        'INSERT INTO runs (run_id, source, input_hash, detector_version, "limit", started_at, '
        "finished_at, n_flows, n_alerts, n_incidents, summary, warnings) VALUES "
        "('r2', 's', 'h', 'd', NULL, 'x', 'x', 0, 0, 0, '{}', '[]')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE runs SET source_id = 'replay:a' WHERE run_id = 'r2'")


def test_second_init_is_noop(tmp_path):
    conn = _v3_db(tmp_path / "soc.db")
    store.init_db(conn)
    snap = _snapshot(conn)
    schema = sorted(tuple(r) for r in conn.execute("SELECT type, name, sql FROM sqlite_master"))
    assert store.init_db(conn) is False
    assert _snapshot(conn) == snap
    assert sorted(tuple(r) for r in conn.execute("SELECT type, name, sql FROM sqlite_master")) == (
        schema
    )


def test_migrated_matches_fresh_schema(tmp_path):
    """Мигрированная база и новая — одни и те же колонки (по именам) и объекты."""
    migrated = _v3_db(tmp_path / "old.db")
    store.init_db(migrated)
    fresh = store.connect(tmp_path / "new.db")
    store.init_db(fresh)
    for t in (*TABLES, *STREAM_TABLES):
        cols_m = {r["name"] for r in migrated.execute(f"PRAGMA table_info({t})")}
        cols_f = {r["name"] for r in fresh.execute(f"PRAGMA table_info({t})")}
        assert cols_m == cols_f, t
    for kind in ("table", "index", "trigger"):
        assert _names(migrated, kind) == _names(fresh, kind)


def test_chain_from_002(tmp_path):
    """База фичи 002 (схема 0) доходит до 4 за один init_db, аудит цел."""
    conn = store.connect(tmp_path / "soc.db")
    conn.executescript((FIXTURES / "soc_schema_002.sql").read_text(encoding="utf-8"))
    conn.execute(
        "INSERT INTO runs VALUES ('r1', 'split:x/test', 'h', 'd1', NULL, '2026-01-01T00:00:00Z', "
        "'2026-01-01T00:00:01Z', 10, 0, 0, '{}', '[]')"
    )
    store.append_audit(conn, "system", "run_loaded", run_id="r1", at="2026-01-01T00:00:00.000Z")
    audit = _rows(conn, "audit_log", "entry_id")
    assert store.init_db(conn) is True
    assert (
        conn.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION
    )  # 007: цепочка доходит до 5
    assert _rows(conn, "audit_log", "entry_id") == audit
    assert _names(conn, "table") >= STREAM_TABLES
    assert tuple(conn.execute("SELECT mode, status FROM runs").fetchone()) == ("batch", "completed")


def test_chain_from_v2(tmp_path):
    conn = store.connect(tmp_path / "soc.db")
    conn.executescript((FIXTURES / "soc_schema_v2.sql").read_text(encoding="utf-8"))
    assert store.init_db(conn) is True
    assert (
        conn.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION
    )  # 007: цепочка доходит до 5
    assert "late" in {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")}


def test_newer_refused(tmp_path):
    conn = store.connect(tmp_path / "future.db")
    store.init_db(conn)
    conn.execute(f"PRAGMA user_version = {store.SCHEMA_VERSION + 1}")  # 007: 5 теперь своя
    with pytest.raises(store.SchemaTooNew, match="новее"):
        store.init_db(conn)


def test_failed_v4_migration_keeps_schema_3(tmp_path, monkeypatch):
    conn = _v3_db(tmp_path / "soc.db")
    before = _snapshot(conn)
    schema_before = sorted(tuple(r) for r in conn.execute("SELECT type, name FROM sqlite_master"))
    steps = list(store.MIGRATION_V4)
    # Сбой после переноса аудита, но до удаления старой таблицы — худшее место
    steps.insert(steps.index(next(s for s in steps if s.startswith("DROP TABLE"))), "SELECT boom()")
    monkeypatch.setattr(store, "MIGRATION_V4", tuple(steps))
    with pytest.raises(sqlite3.OperationalError):
        store.init_db(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
    assert sorted(tuple(r) for r in conn.execute("SELECT type, name FROM sqlite_master")) == (
        schema_before
    )
    assert _snapshot(conn) == before
    with pytest.raises(sqlite3.DatabaseError, match="нельзя удалять"):
        conn.execute("DELETE FROM audit_log")


def test_write_run_is_batch(tmp_path):
    """Пакетный прогон пишет mode=batch, status=completed и правую границу окна инцидента."""
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    alerts = [
        {
            "flow_uid": f"f{i}",
            "capture_id": "c",
            "src_ip": "1.1.1.1",
            "src_port": 4000,
            "dst_ip": "2.2.2.2",
            "dst_port": 80,
            "protocol": 6,
            "first_seen_ms": start,
            "last_seen_ms": start + 1000,
            "predicted_class": "dos",
            "attack_score": 0.9,
            "incident_id": "inc-1",
        }
        for i, start in enumerate((10, 40))
    ]
    incident = {
        "incident_id": "inc-1",
        "src_ip": "1.1.1.1",
        "attack_class": "dos",
        "targets": '["2.2.2.2"]',
        "first_seen_ms": 10,
        "last_seen_ms": 1040,
        "n_alerts": 2,
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
            "n_flows": 2,
        },
        alerts,
        [incident],
    )
    run = store.get_run(conn, "r1")
    assert (run["mode"], run["status"], run["source_id"]) == ("batch", "completed", None)
    assert store.get_incident(conn, "inc-1")["last_alert_start_ms"] == 40
    assert store.list_runs(conn)[0]["mode"] == "batch"
