-- Снимок схемы хранилища фичи 005 (user_version = 4) — до правки store фичей 007.
-- Нужен тесту миграции 4 → 5 (tests/unit/test_store_migration_v5.py): база строится из
-- этого DDL, а не из текущего кода, иначе миграция проверялась бы на самой себе.
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
    warnings         TEXT NOT NULL,
    -- фича 005: пакетный прогон или онлайн-сеанс, статус сеанса, его источник
    mode             TEXT NOT NULL DEFAULT 'batch' CHECK (mode IN ('batch', 'stream')),
    status           TEXT NOT NULL DEFAULT 'completed' CHECK (status IN ('running', 'stopped', 'completed')),
    source_id        TEXT,
    last_activity_at TEXT,
    model_version    TEXT
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
    updated_at       TEXT NOT NULL,
    assignee         TEXT,
    -- фича 005: дописывание в потоке (research R8, R9)
    merged_into      TEXT,
    alerts_after_decision INTEGER NOT NULL DEFAULT 0,
    first_after_decision_ms INTEGER,
    last_alert_start_ms INTEGER
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
    -- фича 004: атакующая сторона (research R8) и ответы экспертов (R10).
    -- experts/fired_experts/explanation = NULL — прогон сделан до ансамбля
    attacker_ip      TEXT,
    victim_ip        TEXT,
    reversed         INTEGER NOT NULL DEFAULT 0,
    fired_experts    TEXT,
    experts          TEXT,
    explanation      TEXT,
    -- фича 005: опоздавший поток и когда потребитель записал алерт (для задержки)
    late             INTEGER NOT NULL DEFAULT 0,
    received_at      TEXT,
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
    event            TEXT NOT NULL CHECK (event IN ('action_proposed', 'action_executed', 'action_rejected', 'incident_status_changed', 'run_loaded', 'incident_assigned', 'incident_updated', 'incident_merged', 'action_reproposed', 'session_status_changed')),
    run_id           TEXT,
    incident_id      TEXT,
    action_id        TEXT,
    details          TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'аудит-журнал нельзя изменять');
END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'из аудит-журнала нельзя удалять');
END;
CREATE INDEX IF NOT EXISTS ix_audit_incident ON audit_log(incident_id);

CREATE INDEX IF NOT EXISTS ix_incidents_run ON incidents(run_id);
CREATE INDEX IF NOT EXISTS ix_incidents_severity ON incidents(severity, first_seen_ms);
CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS ix_incidents_class ON incidents(attack_class);
CREATE INDEX IF NOT EXISTS ix_alerts_incident ON alerts(incident_id, first_seen_ms);
CREATE INDEX IF NOT EXISTS ix_history_incident ON incident_history(incident_id);
CREATE INDEX IF NOT EXISTS ix_alerts_run_time ON alerts(run_id, first_seen_ms);
CREATE INDEX IF NOT EXISTS ix_incidents_assignee ON incidents(assignee);
CREATE INDEX IF NOT EXISTS ix_alerts_incident_experts ON alerts(incident_id, fired_experts);
CREATE TABLE IF NOT EXISTS stream_offsets (
    topic            TEXT NOT NULL,
    partition        INTEGER NOT NULL,
    next_offset      INTEGER NOT NULL,
    updated_at       TEXT NOT NULL,
    PRIMARY KEY (topic, partition)
);
CREATE TABLE IF NOT EXISTS stream_seen (
    run_id           TEXT NOT NULL REFERENCES runs(run_id),
    flow_uid         TEXT NOT NULL,
    seq              INTEGER NOT NULL,
    PRIMARY KEY (run_id, flow_uid)
);
CREATE TABLE IF NOT EXISTS stream_lease (
    name             TEXT PRIMARY KEY,
    holder           TEXT NOT NULL,
    acquired_at      TEXT NOT NULL,
    renewed_at       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stream_stats (
    stat_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at               TEXT NOT NULL,
    run_id           TEXT NOT NULL,
    processed        INTEGER NOT NULL,
    lag_messages     INTEGER,
    lag_seconds      REAL,
    latency_p50_ms   REAL,
    latency_p95_ms   REAL,
    rejected         INTEGER NOT NULL,
    late             INTEGER NOT NULL,
    rate_per_s       REAL
);
CREATE TABLE IF NOT EXISTS stream_divergences (
    divergence_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           TEXT NOT NULL,
    kind             TEXT NOT NULL,
    incident_id      TEXT,
    other_incident_id TEXT,
    flow_uid         TEXT,
    at               TEXT NOT NULL,
    details          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_stream_stats_run ON stream_stats(run_id, at);
CREATE INDEX IF NOT EXISTS ix_stream_seen_seq ON stream_seen(run_id, seq);
CREATE UNIQUE INDEX IF NOT EXISTS ux_runs_source ON runs(source_id) WHERE source_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_incidents_after_decision ON incidents(run_id, alerts_after_decision);
PRAGMA user_version = 4;
