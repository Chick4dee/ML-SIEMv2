"""Миграция хранилища 007 (схема 5) → 006 (схема 6): только добавления (data-model 006).

База схемы 5 строится из снимка DDL фичи 007 (tests/fixtures/soc_schema_v5.sql), не из
текущего кода. После `init_db`: у `stream_stats` появились показатели сенсора (у старых строк —
NULL), у `runs` — флаг `lossy` (у старых — 0), данные и аудит не тронуты.
"""

import sqlite3
from pathlib import Path

import pytest

from mlsiem.soc import store

FIXTURES = Path(__file__).parents[1] / "fixtures"
SENSOR_COLS = {"packets_per_s", "flows_per_s", "drops", "buffer_fill", "liveness"}


def _v5_db(path) -> sqlite3.Connection:
    conn = store.connect(path)
    conn.executescript((FIXTURES / "soc_schema_v5.sql").read_text(encoding="utf-8"))
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 5
    conn.execute(
        "INSERT INTO runs (run_id, source, input_hash, detector_version, started_at, finished_at, "
        "n_flows, n_alerts, n_incidents, summary, warnings) VALUES ('r1', 'split:x/test', 'h', "
        "'d1', '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 10, 0, 0, '{}', '[]')"
    )
    conn.execute(
        "INSERT INTO stream_stats (at, run_id, processed, rejected, late, rate_per_s) "
        "VALUES ('2026-01-01T00:00:00Z', 'r1', 5, 0, 0, 2.5)"
    )
    store.append_audit(conn, "system", "run_loaded", run_id="r1")
    return conn


def _columns(conn, table) -> dict[str, str]:
    return {r[1]: r[2] for r in conn.execute(f"PRAGMA table_info({table})")}


def test_migrate_v5_to_v6(tmp_path):
    conn = _v5_db(tmp_path / "soc.db")
    audit_before = conn.execute("SELECT * FROM audit_log").fetchall()
    assert store.init_db(conn) is True
    assert conn.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION == 6
    assert set(_columns(conn, "stream_stats")) >= SENSOR_COLS
    assert "lossy" in _columns(conn, "runs")
    # Старые строки: показатели сенсора пусты, «потерь» нет, остальное цело
    row = conn.execute("SELECT * FROM stream_stats").fetchone()
    assert row["processed"] == 5 and row["rate_per_s"] == 2.5
    assert all(row[c] is None for c in SENSOR_COLS)
    assert store.get_run(conn, "r1")["lossy"] == 0
    assert conn.execute("SELECT * FROM audit_log").fetchall() == audit_before


def test_fresh_db_has_same_columns_as_migrated(tmp_path):
    migrated = _v5_db(tmp_path / "a.db")
    store.init_db(migrated)
    fresh = store.connect(tmp_path / "b.db")
    store.init_db(fresh)
    for table in ("stream_stats", "runs"):
        assert _columns(migrated, table) == _columns(fresh, table)


def test_failed_step_rolls_back(tmp_path, monkeypatch):
    conn = _v5_db(tmp_path / "soc.db")
    monkeypatch.setattr(
        store,
        "MIGRATION_V6",
        ("ALTER TABLE runs ADD COLUMN lossy INTEGER NOT NULL DEFAULT 0", "BOGUS SQL"),
    )
    with pytest.raises(sqlite3.Error):
        store.init_db(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 5
    assert "lossy" not in _columns(conn, "runs")


def test_write_stats_with_sensor_fields_and_lossy(tmp_path):
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    conn.execute(
        "INSERT INTO runs (run_id, source, input_hash, detector_version, started_at, finished_at, "
        "n_flows, n_alerts, n_incidents, summary, warnings) VALUES ('r1', 's', 'h', 'd', "
        "'2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0, 0, 0, '{}', '[]')"
    )
    store.write_stats(
        conn,
        [{"run_id": "r1", "processed": 3, "packets_per_s": 120.0, "drops": 4, "liveness": 1}],
    )
    last = store.latest_stats(conn, "r1")
    assert last["packets_per_s"] == 120.0 and last["drops"] == 4 and last["liveness"] == 1
    assert last["buffer_fill"] is None
    store.mark_lossy(conn, "r1")
    assert store.get_run(conn, "r1")["lossy"] == 1


def test_chain_from_v4(tmp_path):
    conn = store.connect(tmp_path / "soc.db")
    conn.executescript((FIXTURES / "soc_schema_v4.sql").read_text(encoding="utf-8"))
    store.init_db(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 6
    assert "lossy" in _columns(conn, "runs")


def test_newer_refused(tmp_path):
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    conn.execute(f"PRAGMA user_version = {store.SCHEMA_VERSION + 1}")
    with pytest.raises(store.SchemaTooNew, match="новее"):
        store.init_db(conn)
