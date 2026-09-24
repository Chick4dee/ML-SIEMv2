-- Схема SQLite фичи 002 (user_version = 0) — копия DDL из src/mlsiem/soc/store.py на коммите dd6acb7.
-- Нужна тестам миграции 0 → 2: так тест проверяет переход с настоящей старой базы.
CREATE TABLE IF NOT EXISTS runs (
    run_id           TEXT PRIMARY KEY,
    source           TEXT NOT NULL,
    input_hash       TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    "limit"          INTEGER,
    started_at       TEXT NOT NULL,
    finished_at      TEXT NOT NULL,
    n_flows          INTEGER NOT NULL,
    n_alerts         INTEGER NOT NULL,
    n_incidents      INTEGER NOT NULL,
    summary          TEXT NOT NULL,
    warnings         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id      TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES runs(run_id),
    src_ip           TEXT NOT NULL,
    attack_class     TEXT NOT NULL,
    targets          TEXT NOT NULL,
    first_seen_ms    INTEGER NOT NULL,
    last_seen_ms     INTEGER NOT NULL,
    n_alerts         INTEGER NOT NULL,
    max_score        REAL NOT NULL,
    mean_score       REAL NOT NULL,
    severity         TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    severity_reason  TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'in_progress', 'closed')),
    resolution       TEXT CHECK (resolution IS NULL OR resolution IN ('confirmed', 'false_positive')),
    version          INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id         TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES runs(run_id),
    incident_id      TEXT NOT NULL REFERENCES incidents(incident_id),
    flow_uid         TEXT NOT NULL,
    capture_id       TEXT NOT NULL,
    src_ip           TEXT,
    src_port         INTEGER,
    dst_ip           TEXT,
    dst_port         INTEGER,
    protocol         INTEGER,
    first_seen_ms    INTEGER NOT NULL,
    last_seen_ms     INTEGER NOT NULL,
    predicted_class  TEXT NOT NULL,
    attack_score     REAL NOT NULL,
    UNIQUE (run_id, flow_uid)
);

CREATE TABLE IF NOT EXISTS incident_history (
    history_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id      TEXT NOT NULL REFERENCES incidents(incident_id),
    at               TEXT NOT NULL,
    analyst          TEXT NOT NULL,
    field            TEXT NOT NULL,
    old              TEXT,
    new              TEXT,
    comment          TEXT
);

CREATE TABLE IF NOT EXISTS actions (
    action_id        TEXT PRIMARY KEY,
    incident_id      TEXT NOT NULL UNIQUE REFERENCES incidents(incident_id),
    action_type      TEXT NOT NULL CHECK (action_type IN ('block_source_ip', 'isolate_host', 'observe', 'manual_review')),
    target           TEXT,
    rule_id          TEXT NOT NULL,
    rule_text        TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'proposed' CHECK (state IN ('proposed', 'executed', 'rejected')),
    decided_by       TEXT,
    decided_at       TEXT,
    comment          TEXT,
    simulation       TEXT,
    version          INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_log (
    entry_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at               TEXT NOT NULL,
    actor            TEXT NOT NULL,
    event            TEXT NOT NULL CHECK (event IN ('action_proposed', 'action_executed', 'action_rejected', 'incident_status_changed', 'run_loaded')),
    run_id           TEXT,
    incident_id      TEXT,
    action_id        TEXT,
    details          TEXT NOT NULL
);

-- Журнал только на вставку: любые UPDATE/DELETE отменяются самой базой
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'аудит-журнал нельзя изменять');
END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'из аудит-журнала нельзя удалять');
END;

CREATE INDEX IF NOT EXISTS ix_incidents_run ON incidents(run_id);
CREATE INDEX IF NOT EXISTS ix_incidents_severity ON incidents(severity, first_seen_ms);
CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS ix_incidents_class ON incidents(attack_class);
CREATE INDEX IF NOT EXISTS ix_alerts_incident ON alerts(incident_id, first_seen_ms);
CREATE INDEX IF NOT EXISTS ix_audit_incident ON audit_log(incident_id);
CREATE INDEX IF NOT EXISTS ix_history_incident ON incident_history(incident_id);
