"""Хранилище SOC на SQLite: прогоны, алерты, инциденты, действия, аудит-журнал (research R8).

Почему SQLite: встроенная БД без сервера, работает на Windows без Docker, даёт транзакции
и индексы. Вердикты всех потоков прогона сюда не пишутся (их сотни тысяч) — они лежат
в `var/runs/<run_id>/verdicts.parquet`; в БД только то, с чем работает аналитик.

Три гарантии, ради которых этот модуль написан аккуратно:
1. Прогон пишется одной транзакцией (FR-028): либо все его строки в базе, либо ни одной.
2. Оптимистичная блокировка (FR-024): у инцидента и действия есть `version`; изменение идёт
   через `UPDATE … WHERE version = ?`, и если кто-то успел раньше, 0 строк → `Conflict`.
3. Аудит-журнал только на вставку (FR-021): триггеры в самой БД запрещают UPDATE и DELETE —
   даже случайный код не сможет «подчистить» журнал.

Схема таблиц — строго по data-model.md.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import math
import sqlite3
import unicodedata
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mlsiem.soc.config import ACTION_TYPES, SEVERITY_LEVELS

INCIDENT_STATUSES = ("new", "in_progress", "closed")
RESOLUTIONS = ("confirmed", "false_positive")
ACTION_STATES = ("proposed", "executed", "rejected")
AUDIT_EVENTS = (
    "action_proposed",
    "action_executed",
    "action_rejected",
    "incident_status_changed",
    "run_loaded",
    # фича 003: назначение ответственного
    "incident_assigned",
    # фича 005: инцидент растёт в потоке, сливается, плейбук пересчитывает предложение,
    # сеанс меняет статус — всё от имени system (data-model «Аудит — новые события»)
    "incident_updated",
    "incident_merged",
    "action_reproposed",
    "session_status_changed",
)
# Режим и статус прогона (фича 005): пакетный прогон всегда «завершён», онлайн-сеанс живёт
RUN_MODES = ("batch", "stream")
RUN_STATUSES = ("running", "stopped", "completed")
SYSTEM_ACTOR = "system"
# Версия схемы в PRAGMA user_version. База фичи 002 имеет 0 (единица зарезервирована как
# «схема 002», чтобы явно отличать её от пустого файла); фича 003 вводит версию 2, фича 004 — 3,
# фича 005 — 4, фича 007 — 5, фича 006 — 6
SCHEMA_VERSION = 6
# Вид алерта (фича 007): алерт потока или алерт окна (research R12)
ALERT_KINDS = ("flow", "window")


# ---------------------------------------------------------------- ошибки
# От этих исключений API строит ответы: имя класса ↔ код ошибки контракта api.md


class StoreError(Exception):
    """Базовая ошибка хранилища; message — готовый текст для аналитика по-русски."""

    code = "bad_request"

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class NotFound(StoreError):
    code = "not_found"


class InvalidTransition(StoreError):
    code = "invalid_transition"


class Conflict(StoreError):
    code = "conflict"


class BadRequest(StoreError):
    code = "bad_request"


class SchemaTooNew(StoreError):
    """База создана более новой версией кода — трогать её мы не имеем права."""


# ---------------------------------------------------------------- схема


def _in(values: tuple[str, ...]) -> str:
    return "(" + ", ".join(f"'{v}'" for v in values) + ")"


AUDIT_TABLE_DDL = f"""
CREATE TABLE IF NOT EXISTS audit_log (
    entry_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at               TEXT NOT NULL,
    actor            TEXT NOT NULL,
    event            TEXT NOT NULL CHECK (event IN {_in(AUDIT_EVENTS)}),
    run_id           TEXT,
    incident_id      TEXT,
    action_id        TEXT,
    details          TEXT NOT NULL
)"""

# Триггеры и индекс аудита вынесены отдельно: миграция пересоздаёт таблицу и должна
# поставить их заново ровно в том же виде
AUDIT_GUARDS = (
    # Журнал только на вставку: любые UPDATE/DELETE отменяются самой базой
    """CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'аудит-журнал нельзя изменять');
END""",
    """CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'из аудит-журнала нельзя удалять');
END""",
    "CREATE INDEX IF NOT EXISTS ix_audit_incident ON audit_log(incident_id)",
)
AUDIT_GUARDS_DDL = "".join(f"{stmt};\n" for stmt in AUDIT_GUARDS)

# Индексы фичи 003: лента последних алертов панели и фильтр по ответственному
INDEXES_V2 = (
    "CREATE INDEX IF NOT EXISTS ix_alerts_run_time ON alerts(run_id, first_seen_ms)",
    "CREATE INDEX IF NOT EXISTS ix_incidents_assignee ON incidents(assignee)",
)
INDEXES_V2_DDL = "".join(f"{stmt};\n" for stmt in INDEXES_V2)

# Индекс фичи 004: сводка «кто поднял алерты» по инциденту — один GROUP BY по нему
INDEXES_V3 = (
    "CREATE INDEX IF NOT EXISTS ix_alerts_incident_experts ON alerts(incident_id, fired_experts)",
)
INDEXES_V3_DDL = "".join(f"{stmt};\n" for stmt in INDEXES_V3)

# Индексы фичи 005: сеанс ищется по источнику (он же его уникальный ключ — повторное
# проигрывание того же входа идёт новым источником и новым сеансом), фильтр «новые алерты
# после решения» — по счётчику в пределах прогона
INDEXES_V4 = (
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_runs_source ON runs(source_id) "
    "WHERE source_id IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS ix_incidents_after_decision "
    "ON incidents(run_id, alerts_after_decision)",
)
INDEXES_V4_DDL = "".join(f"{stmt};\n" for stmt in INDEXES_V4)

# Служебные таблицы потока (фича 005, data-model «Служебные таблицы потока»):
# - stream_offsets — позиция чтения каждой партиции, пишется в ТОЙ ЖЕ транзакции, что и
#   результат пачки: это источник истины при перезапуске потребителя (research R7);
# - stream_seen — какие потоки сеанса уже обработаны: повторная доставка отсекается здесь;
# - stream_lease — аренда единственного потребителя (FR-019);
# - stream_stats — показатели для `stream status` и панели (хранятся сутки, это не аудит);
# - stream_divergences — известные причины расхождения с пакетным режимом (FR-021)
STREAM_TABLES = (
    """CREATE TABLE IF NOT EXISTS stream_offsets (
    topic            TEXT NOT NULL,
    partition        INTEGER NOT NULL,
    next_offset      INTEGER NOT NULL,
    updated_at       TEXT NOT NULL,
    PRIMARY KEY (topic, partition)
)""",
    """CREATE TABLE IF NOT EXISTS stream_seen (
    run_id           TEXT NOT NULL REFERENCES runs(run_id),
    flow_uid         TEXT NOT NULL,
    seq              INTEGER NOT NULL,
    PRIMARY KEY (run_id, flow_uid)
)""",
    """CREATE TABLE IF NOT EXISTS stream_lease (
    name             TEXT PRIMARY KEY,
    holder           TEXT NOT NULL,
    acquired_at      TEXT NOT NULL,
    renewed_at       TEXT NOT NULL
)""",
    """CREATE TABLE IF NOT EXISTS stream_stats (
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
)""",
    """CREATE TABLE IF NOT EXISTS stream_divergences (
    divergence_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           TEXT NOT NULL,
    kind             TEXT NOT NULL,
    incident_id      TEXT,
    other_incident_id TEXT,
    flow_uid         TEXT,
    at               TEXT NOT NULL,
    details          TEXT NOT NULL
)""",
    "CREATE INDEX IF NOT EXISTS ix_stream_stats_run ON stream_stats(run_id, at)",
    "CREATE INDEX IF NOT EXISTS ix_stream_seen_seq ON stream_seen(run_id, seq)",
)
# Для свежей базы stream_stats сразу создаётся со столбцами сенсора (фича 006). STREAM_TABLES
# остаётся прежним: его же использует MIGRATION_V4, а столбцы сенсора добавляет MIGRATION_V6.
_STATS_TAIL_V4 = "    rate_per_s       REAL\n)"
_STATS_TAIL_V6 = """    rate_per_s       REAL,
    -- фича 006: показатели живого сенсора (R17); у проигрывателей 005 — NULL
    packets_per_s    REAL,
    flows_per_s      REAL,
    drops            INTEGER,
    buffer_fill      REAL,
    liveness         INTEGER
)"""
STREAM_TABLES_FRESH = tuple(
    stmt.replace(_STATS_TAIL_V4, _STATS_TAIL_V6) if "stream_stats (" in stmt else stmt
    for stmt in STREAM_TABLES
)
STREAM_TABLES_DDL = "".join(f"{stmt};\n" for stmt in STREAM_TABLES_FRESH)

# Незакрытые окна онлайн-сеанса (фича 007, research R13, data-model «Незакрытые окна»):
# - window_pending — потоки открытых окон: payload — orjson полей, нужных `build_windows` и
#   эксперту окон. Пишется в ТОЙ ЖЕ транзакции, что пачка и позиция: окна переживают
#   перезапуск потребителя без потерь, а перечитывать Kafka не нужно;
# - window_closed — какие окна сеанса уже закрыты: поток, пришедший в закрытое окно, в него не
#   добавляется (опоздал сильнее допустимого) и считается в n_window_late_dropped
WINDOW_TABLES = (
    """CREATE TABLE IF NOT EXISTS window_pending (
    run_id           TEXT NOT NULL,
    flow_uid         TEXT NOT NULL,
    window_id        TEXT NOT NULL,
    window_start_ms  INTEGER NOT NULL,
    attacker_ip      TEXT NOT NULL,
    payload          BLOB NOT NULL,
    PRIMARY KEY (run_id, flow_uid)
)""",
    "CREATE INDEX IF NOT EXISTS ix_window_pending_start ON window_pending(run_id, window_start_ms)",
    """CREATE TABLE IF NOT EXISTS window_closed (
    run_id           TEXT NOT NULL,
    window_id        TEXT NOT NULL,
    closed_at        TEXT NOT NULL,
    n_flows          INTEGER NOT NULL,
    PRIMARY KEY (run_id, window_id)
)""",
    "CREATE INDEX IF NOT EXISTS ix_alerts_kind ON alerts(incident_id, alert_kind)",
)
WINDOW_TABLES_DDL = "".join(f"{stmt};\n" for stmt in WINDOW_TABLES)

DDL = f"""
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
    mode             TEXT NOT NULL DEFAULT 'batch' CHECK (mode IN {_in(RUN_MODES)}),
    status           TEXT NOT NULL DEFAULT 'completed' CHECK (status IN {_in(RUN_STATUSES)}),
    source_id        TEXT,
    last_activity_at TEXT,
    model_version    TEXT,
    -- фича 006: у сеанса живого сенсора были потери захвата или буфера (R10)
    lossy            INTEGER NOT NULL DEFAULT 0
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
    severity         TEXT NOT NULL CHECK (severity IN {_in(SEVERITY_LEVELS)}),
    severity_reason  TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'new' CHECK (status IN {_in(INCIDENT_STATUSES)}),
    resolution       TEXT CHECK (resolution IS NULL OR resolution IN {_in(RESOLUTIONS)}),
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
    -- фича 007: вид алерта и описание окна (JSON) у алертов окон
    alert_kind       TEXT NOT NULL DEFAULT 'flow' CHECK (alert_kind IN {_in(ALERT_KINDS)}),
    window_info      TEXT,
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
    action_type      TEXT NOT NULL CHECK (action_type IN {_in(ACTION_TYPES)}),
    target           TEXT,
    rule_id          TEXT NOT NULL,
    rule_text        TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'proposed' CHECK (state IN {_in(ACTION_STATES)}),
    decided_by       TEXT,
    decided_at       TEXT,
    comment          TEXT,
    simulation       TEXT,
    version          INTEGER NOT NULL DEFAULT 1
);

{AUDIT_TABLE_DDL};
{AUDIT_GUARDS_DDL}
CREATE INDEX IF NOT EXISTS ix_incidents_run ON incidents(run_id);
CREATE INDEX IF NOT EXISTS ix_incidents_severity ON incidents(severity, first_seen_ms);
CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS ix_incidents_class ON incidents(attack_class);
CREATE INDEX IF NOT EXISTS ix_alerts_incident ON alerts(incident_id, first_seen_ms);
CREATE INDEX IF NOT EXISTS ix_history_incident ON incident_history(incident_id);
{INDEXES_V2_DDL}{INDEXES_V3_DDL}{STREAM_TABLES_DDL}{INDEXES_V4_DDL}{WINDOW_TABLES_DDL}"""

# Миграция схемы 002 (0) → 2. Шаги выполняются по одному внутри ОДНОЙ транзакции (см.
# `migrate`): executescript здесь нельзя — он сам делает COMMIT перед началом.
#
# Почему аудит пересоздаётся, а не ALTER-ится: CHECK на событиях в SQLite не меняется
# ALTER TABLE, а новое событие incident_assigned старый CHECK не пропустит. Поэтому таблица
# переименовывается, создаётся заново с новым CHECK, строки переносятся КАК ЕСТЬ — вместе
# с entry_id (это «номер записи» журнала, по нему ссылаются и сортируют).
#
# Почему это не нарушает «только вставка»: при RENAME триггеры запрета едут вместе с таблицей
# на audit_log_v1, а DROP TABLE не запускает DELETE-триггеры (SQLite удаляет таблицу целиком,
# без построчного DELETE) и уносит их с собой. Сразу после этого те же триггеры ставятся на
# новую таблицу. Всё — одной транзакцией: при сбое база остаётся в схеме 002 целиком.
MIGRATION_V2: tuple[str, ...] = (
    "ALTER TABLE incidents ADD COLUMN assignee TEXT",
    "ALTER TABLE audit_log RENAME TO audit_log_v1",
    AUDIT_TABLE_DDL,
    "INSERT INTO audit_log (entry_id, at, actor, event, run_id, incident_id, action_id, details) "
    "SELECT entry_id, at, actor, event, run_id, incident_id, action_id, details FROM audit_log_v1",
    "DROP TABLE audit_log_v1",
    *AUDIT_GUARDS,
    *INDEXES_V2,
    "PRAGMA user_version = 2",
)

# Миграция схемы 2 (фича 003) → 3 (фича 004), тоже одной транзакцией (data-model «Миграция
# 2 → 3»). Здесь только добавления: новых событий аудита нет, поэтому аудит, в отличие от
# миграции 0 → 2, не пересоздаётся и не трогается вовсе. Старым алертам атакующая сторона
# заполняется как в 002 (атакующий = src_ip) — это не правка аудита: на alerts запрещающих
# триггеров нет, а прогоны до 004 и группировались ровно так. Ответы экспертов у них остаются
# NULL — это и есть пометка «прогон сделан до появления ансамбля» (FR-020).
MIGRATION_V3: tuple[str, ...] = (
    "ALTER TABLE alerts ADD COLUMN attacker_ip TEXT",
    "ALTER TABLE alerts ADD COLUMN victim_ip TEXT",
    "ALTER TABLE alerts ADD COLUMN reversed INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE alerts ADD COLUMN fired_experts TEXT",
    "ALTER TABLE alerts ADD COLUMN experts TEXT",
    "ALTER TABLE alerts ADD COLUMN explanation TEXT",
    "UPDATE alerts SET attacker_ip = src_ip, victim_ip = dst_ip",
    *INDEXES_V3,
    "PRAGMA user_version = 3",
)

# Миграция схемы 3 (фича 004) → 4 (фича 005), одной транзакцией (data-model «Миграция 3 → 4»).
# Колонки и таблицы только добавляются. Аудит пересоздаётся ровно как в миграции 0 → 2 и по
# той же причине: у него появились четыре новых события, а CHECK в SQLite не меняется
# ALTER TABLE. entry_id сохраняются, триггеры запрета ставятся заново в той же транзакции.
# Старым инцидентам заполняется last_alert_start_ms — максимум времени начала их алертов:
# это правая граница окна присоединения (research R8); колонка должна значить одно и то же
# у всех инцидентов, пакетных и потоковых.
MIGRATION_V4: tuple[str, ...] = (
    "ALTER TABLE runs ADD COLUMN mode TEXT NOT NULL DEFAULT 'batch' "
    f"CHECK (mode IN {_in(RUN_MODES)})",
    "ALTER TABLE runs ADD COLUMN status TEXT NOT NULL DEFAULT 'completed' "
    f"CHECK (status IN {_in(RUN_STATUSES)})",
    "ALTER TABLE runs ADD COLUMN source_id TEXT",
    "ALTER TABLE runs ADD COLUMN last_activity_at TEXT",
    "ALTER TABLE runs ADD COLUMN model_version TEXT",
    "ALTER TABLE incidents ADD COLUMN merged_into TEXT",
    "ALTER TABLE incidents ADD COLUMN alerts_after_decision INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE incidents ADD COLUMN first_after_decision_ms INTEGER",
    "ALTER TABLE incidents ADD COLUMN last_alert_start_ms INTEGER",
    "UPDATE incidents SET last_alert_start_ms = (SELECT MAX(a.first_seen_ms) FROM alerts a "
    "WHERE a.incident_id = incidents.incident_id)",
    "ALTER TABLE alerts ADD COLUMN late INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE alerts ADD COLUMN received_at TEXT",
    *STREAM_TABLES,
    "ALTER TABLE audit_log RENAME TO audit_log_v3",
    AUDIT_TABLE_DDL,
    "INSERT INTO audit_log (entry_id, at, actor, event, run_id, incident_id, action_id, details) "
    "SELECT entry_id, at, actor, event, run_id, incident_id, action_id, details FROM audit_log_v3",
    "DROP TABLE audit_log_v3",
    *AUDIT_GUARDS,
    *INDEXES_V4,
    "PRAGMA user_version = 4",
)

# Миграция схемы 4 (фича 005) → 5 (фича 007), одной транзакцией (research R14). Только
# добавления: вид алерта (старые алерты получают 'flow' значением по умолчанию — это и есть
# «прогон до 007»), описание окна и таблицы незакрытых окон сеанса. Аудит не трогается: новых
# событий нет.
MIGRATION_V5: tuple[str, ...] = (
    "ALTER TABLE alerts ADD COLUMN alert_kind TEXT NOT NULL DEFAULT 'flow' "
    f"CHECK (alert_kind IN {_in(ALERT_KINDS)})",
    "ALTER TABLE alerts ADD COLUMN window_info TEXT",
    *WINDOW_TABLES,
    "PRAGMA user_version = 5",
)

# Миграция схемы 5 (фича 007) → 6 (фича 006), одной транзакцией (data-model «Миграция 5 → 6»).
# Только добавления: показатели живого сенсора в stream_stats (у старых строк и у источников-
# проигрывателей они NULL) и флаг «были потери» у сеанса (по умолчанию 0 — потерь не было).
MIGRATION_V6: tuple[str, ...] = (
    "ALTER TABLE stream_stats ADD COLUMN packets_per_s REAL",
    "ALTER TABLE stream_stats ADD COLUMN flows_per_s REAL",
    "ALTER TABLE stream_stats ADD COLUMN drops INTEGER",
    "ALTER TABLE stream_stats ADD COLUMN buffer_fill REAL",
    "ALTER TABLE stream_stats ADD COLUMN liveness INTEGER",
    "ALTER TABLE runs ADD COLUMN lossy INTEGER NOT NULL DEFAULT 0",
    "PRAGMA user_version = 6",
)


def now_iso() -> str:
    """Текущее время в ISO-8601 UTC с точностью до миллисекунд."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Открывает базу (создаёт каталог и файл при необходимости) и включает нужные режимы.

    isolation_level=None — автокоммит: транзакции мы открываем явно (`transaction()`),
    иначе модуль sqlite3 сам начинает их в неожиданных местах. check_same_thread=False —
    FastAPI может выполнить обработчик в другом потоке, чем создал соединение.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, isolation_level=None, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    # WAL: читатели (API) не блокируют писателя (прогон) и наоборот
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> bool:
    """Готовит базу к работе и возвращает True, если пришлось мигрировать схему.

    Случаи по `PRAGMA user_version` и наличию таблиц:
    - пустой файл → сразу схема 6;
    - схема 002 (версия 0 или 1, таблицы есть) → `MIGRATION_V2`, `MIGRATION_V3`, `MIGRATION_V4`;
    - схема 2 (фича 003) → `MIGRATION_V3`, затем `MIGRATION_V4`;
    - схема 3 (фича 004) → `MIGRATION_V4`, затем `MIGRATION_V5`;
    - схема 4 (фича 005) → `MIGRATION_V5`, затем `MIGRATION_V6`;
    - схема 5 (фича 007) → `MIGRATION_V6`;
    - схема 6 → только IF NOT EXISTS (ничего не меняется);
    - версия больше известной → `SchemaTooNew`: база от более нового кода, трогать нельзя.
    """
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise SchemaTooNew(
            f"база новее, чем знает код: версия схемы {version}, а этот код понимает до "
            f"{SCHEMA_VERSION} — обновите mlsiem или укажите другую базу"
        )
    has_tables = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'incidents'"
    ).fetchone()
    if has_tables and version < SCHEMA_VERSION:
        migrate(conn)
        return True
    conn.executescript(DDL)
    if version != SCHEMA_VERSION:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    return False


def migrate(conn: sqlite3.Connection) -> None:
    """Доводит базу до текущей схемы; каждый шаг цепочки — своей транзакцией.

    0 → 2 (фича 003), 2 → 3 (фича 004), 3 → 4 (фича 005), 4 → 5 (фича 007) и 5 → 6 (фича
    006). Сбой посреди шага откатывает только
    этот шаг: база остаётся целиком в предыдущей схеме, и повторный запуск продолжит с неё.
    Списки шагов читаются из модуля в момент вызова — тесты подменяют их, чтобы уронить шаг.
    """
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    for target, steps in (
        (2, MIGRATION_V2),
        (3, MIGRATION_V3),
        (4, MIGRATION_V4),
        (5, MIGRATION_V5),
        (6, MIGRATION_V6),
    ):
        if version < target:
            with transaction(conn):
                for step in steps:
                    conn.execute(step)
            version = target


@contextlib.contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Явная транзакция: BEGIN IMMEDIATE сразу берёт блокировку на запись.

    С IMMEDIATE два одновременных писателя не упираются в «database is locked» посреди
    работы: второй ждёт (timeout соединения) ещё до того, как что-то прочитал. При любом
    исключении — ROLLBACK, и в базе не остаётся ни одной строки из этой транзакции.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def append_audit(
    conn: sqlite3.Connection,
    actor: str,
    event: str,
    *,
    run_id: str | None = None,
    incident_id: str | None = None,
    action_id: str | None = None,
    details: dict | None = None,
    at: str | None = None,
) -> int:
    """Добавляет запись в аудит-журнал и возвращает её entry_id.

    Транзакцию не открывает: запись аудита должна попасть в ту же транзакцию, что и само
    изменение, — иначе возможно «действие выполнено, а в журнале пусто».
    """
    cur = conn.execute(
        "INSERT INTO audit_log (at, actor, event, run_id, incident_id, action_id, details) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (at or now_iso(), actor, event, run_id, incident_id, action_id, _json(details or {})),
    )
    return int(cur.lastrowid)


def input_digest(*parts: str) -> str:
    """Короткий sha1 от строк — для идентификаторов (детерминированных, а не счётчиков)."""
    h = hashlib.sha1()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\x1f")
    return h.hexdigest()


# ---------------------------------------------------------------- прогоны


def new_run_id(conn: sqlite3.Connection, input_hash: str, *, now: datetime | None = None) -> str:
    """`YYYYMMDDTHHMMSS-<хеш6 входа>`.

    Если такой уже есть (два прогона одного входа в одну секунду) — к нему добавляется `-2`, `-3`…
    """
    base = f"{(now or datetime.now(UTC)).strftime('%Y%m%dT%H%M%S')}-{input_hash[:6]}"
    run_id, n = base, 1
    while conn.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone():
        n += 1
        run_id = f"{base}-{n}"
    return run_id


ALERT_COLUMNS = (
    "alert_id",
    "run_id",
    "incident_id",
    "flow_uid",
    "capture_id",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "first_seen_ms",
    "last_seen_ms",
    "predicted_class",
    "attack_score",
    # фича 004
    "attacker_ip",
    "victim_ip",
    "reversed",
    "fired_experts",
    "experts",
    "explanation",
    # фича 007
    "alert_kind",
    "window_info",
)
INCIDENT_COLUMNS = (
    "incident_id",
    "run_id",
    "src_ip",
    "attack_class",
    "targets",
    "first_seen_ms",
    "last_seen_ms",
    "n_alerts",
    "max_score",
    "mean_score",
    "severity",
    "severity_reason",
    "status",
    "resolution",
    "version",
    "created_at",
    "updated_at",
    "last_alert_start_ms",
)
ACTION_COLUMNS = (
    "action_id",
    "incident_id",
    "action_type",
    "target",
    "rule_id",
    "rule_text",
    "state",
    "version",
)


def _insert_many(conn: sqlite3.Connection, table: str, columns: tuple[str, ...], rows) -> None:
    placeholders = ", ".join("?" for _ in columns)
    conn.executemany(
        f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
        (tuple(r[c] for c in columns) for r in rows),
    )


def _alert_defaults(a: dict) -> dict:
    """Поля фичи 004 для алертов, пришедших без них (вызовы 002/003 и тесты тех фич):
    атакующий — src_ip, как группировал 002; ответов экспертов нет."""
    return {
        "attacker_ip": a.get("src_ip"),
        "victim_ip": a.get("dst_ip"),
        "reversed": 0,
        "fired_experts": None,
        "experts": None,
        "explanation": None,
        "alert_kind": "flow",
        "window_info": None,
    }


def write_run(
    conn: sqlite3.Connection,
    run: dict,
    alerts: list[dict],
    incidents: list[dict],
    actions: list[dict] | None = None,
) -> None:
    """Пишет прогон целиком ОДНОЙ транзакцией (FR-028).

    run — поля таблицы runs (summary — словарь, warnings — список); alerts — с incident_id;
    incidents — результат группировки; actions — предложения плейбуков. При любой ошибке —
    откат, и в базе не остаётся ни строки этого прогона.
    """
    at = now_iso()
    run_id = run["run_id"]
    with transaction(conn):
        conn.execute(
            'INSERT INTO runs (run_id, source, input_hash, detector_version, "limit", started_at, '
            "finished_at, n_flows, n_alerts, n_incidents, summary, warnings, mode, status, "
            "model_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'batch', 'completed', ?)",
            (
                run_id,
                run["source"],
                run["input_hash"],
                run["detector_version"],
                run.get("limit"),
                run["started_at"],
                run.get("finished_at") or at,
                run["n_flows"],
                len(alerts),
                len(incidents),
                _json(run.get("summary") or {}),
                _json(run.get("warnings") or []),
                run["detector_version"],
            ),
        )
        _insert_many(
            conn,
            "incidents",
            INCIDENT_COLUMNS,
            (
                {
                    "last_alert_start_ms": None,
                    **i,
                    "run_id": run_id,
                    "status": "new",
                    "resolution": None,
                    "version": 1,
                    "created_at": at,
                    "updated_at": at,
                }
                for i in incidents
            ),
        )
        _insert_many(
            conn,
            "alerts",
            ALERT_COLUMNS,
            (
                {
                    **_alert_defaults(a),
                    **a,
                    "run_id": run_id,
                    "alert_id": f"{run_id}/{a['flow_uid']}",
                }
                for a in alerts
            ),
        )
        # Правая граница окна инцидента (фича 005) — максимум времени начала его алертов. У
        # группировки она уже посчитана; вызовы 002/003 (и их тесты) её не передают — тогда
        # её считает база по только что записанным алертам
        conn.execute(
            "UPDATE incidents SET last_alert_start_ms = (SELECT MAX(a.first_seen_ms) "
            "FROM alerts a WHERE a.incident_id = incidents.incident_id) "
            "WHERE run_id = ? AND last_alert_start_ms IS NULL",
            (run_id,),
        )
        for a in actions or []:
            _insert_many(
                conn, "actions", ACTION_COLUMNS, [{**a, "state": "proposed", "version": 1}]
            )
            append_audit(
                conn,
                SYSTEM_ACTOR,
                "action_proposed",
                run_id=run_id,
                incident_id=a["incident_id"],
                action_id=a["action_id"],
                details={
                    "action_type": a["action_type"],
                    "target": a["target"],
                    "rule_id": a["rule_id"],
                    "rule_text": a["rule_text"],
                },
                at=at,
            )
        append_audit(
            conn,
            SYSTEM_ACTOR,
            "run_loaded",
            run_id=run_id,
            details={
                "source": run["source"],
                "n_flows": run["n_flows"],
                "n_alerts": len(alerts),
                "n_incidents": len(incidents),
                "detector_version": run["detector_version"],
            },
            at=at,
        )


def _run_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["summary"] = json.loads(d["summary"])
    d["warnings"] = json.loads(d["warnings"])
    d["model"] = run_model(d)
    # Фича 007: раздел «эксперт окон» сводки; None — прогон до 007
    d["windows"] = d["summary"].get("windows")
    return d


def run_model(run: dict) -> dict:
    """Модель прогона (фича 004): из сводки, а у прогонов до 004 — «детектор <версия>»."""
    model = (run.get("summary") or {}).get("model")
    if model:
        return {
            "kind": model.get("kind", "detector"),
            "version": model.get("version", run["detector_version"]),
            "selected": model.get("selected"),
            "experts": model.get("experts"),
        }
    return {
        "kind": "detector",
        "version": run["detector_version"],
        "selected": None,
        "experts": None,
    }


def alert_row(r: sqlite3.Row | dict) -> dict:
    """Строка алерта для API и консоли: JSON экспертов → словарь, список сработавших
    экспертов → список (`[]` — алерт поднял мета-слой), `reversed` → bool. У алертов прогона
    до ансамбля `experts` и `fired_experts` остаются None («прогон до ансамбля»)."""
    d = dict(r)
    if "experts" in d:
        d["experts"] = json.loads(d["experts"]) if d["experts"] else None
    if "fired_experts" in d and d["fired_experts"] is not None:
        d["fired_experts"] = [x for x in d["fired_experts"].split(",") if x]
    if "reversed" in d:
        d["reversed"] = bool(d["reversed"])
    # Фича 007: вид алерта и разобранное описание окна (у алертов потоков — None)
    if "alert_kind" in d or "window_info" in d:
        d["alert_kind"] = d.get("alert_kind") or "flow"
        d["window_info"] = json.loads(d["window_info"]) if d.get("window_info") else None
        # Имена контракта API (contracts/api-ui-additions.md): kind и window
        d["kind"], d["window"] = d["alert_kind"], d["window_info"]
    return d


def list_runs(conn: sqlite3.Connection) -> list[dict]:
    """Прогоны, новые сверху, с числом инцидентов по статусам."""
    runs = [
        _run_row(r)
        for r in conn.execute("SELECT * FROM runs ORDER BY started_at DESC, run_id DESC")
    ]
    counts = conn.execute(
        "SELECT run_id, status, COUNT(*) AS n FROM incidents WHERE merged_into IS NULL "
        "GROUP BY run_id, status"
    ).fetchall()
    by_run: dict[str, dict[str, int]] = {}
    for c in counts:
        by_run.setdefault(c["run_id"], {})[c["status"]] = c["n"]
    for r in runs:
        got = by_run.get(r["run_id"], {})
        r["incidents_by_status"] = {s: got.get(s, 0) for s in INCIDENT_STATUSES}
    return runs


# ---------------------------------------------------------------- действия


def _action_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["simulation"] = json.loads(d["simulation"]) if d["simulation"] else None
    return d


def get_action(conn: sqlite3.Connection, action_id: str) -> dict:
    row = conn.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,)).fetchone()
    if row is None:
        raise NotFound(f"действие {action_id} не найдено")
    return _action_row(row)


MAX_NAME = 64


def clean_name(value: str | None, what: str = "имя аналитика") -> str:
    """Проверяет имя человека (аналитик, ответственный): 1–64 символа после обрезки по краям,
    без управляющих символов. Возвращает обрезанное имя или бросает `BadRequest`.

    Управляющие символы (перевод строки, \\x00, табуляция) отсекаем не из вредности: имя
    выводится в журнале и шапке, и «vl\\nad» там выглядело бы как две разные записи.
    """
    name = (value or "").strip()
    if not name:
        raise BadRequest(f"{what}: пустое значение — нужно от 1 до {MAX_NAME} символов")
    if len(name) > MAX_NAME:
        raise BadRequest(f"{what}: {len(name)} символов, а можно не больше {MAX_NAME}")
    if any(unicodedata.category(ch) == "Cc" for ch in name):
        raise BadRequest(f"{what}: управляющие символы (перевод строки и т. п.) недопустимы")
    return name


def _require_analyst(analyst: str | None) -> str:
    if analyst is None or not str(analyst).strip():
        raise BadRequest("не указан аналитик: изменения без автора запрещены (заголовок X-Analyst)")
    return str(analyst).strip()


def _assignee_mark(assignee: str | None, analyst: str) -> dict:
    """Поля аудита «кто был ответственным и решал ли он сам» (FR-012a, research R6).

    Считается здесь, в ядре, внутри транзакции решения — а не передаётся из интерфейса:
    иначе клиент API мог бы «забыть» передать флаг и спрятать, что решал не ответственный.
    """
    return {"assignee": assignee, "by_non_assignee": assignee is not None and assignee != analyst}


def _decide(
    conn: sqlite3.Connection,
    action_id: str,
    analyst: str,
    expected_version: int,
    comment: str | None,
    *,
    new_state: str,
) -> dict:
    """Общая часть подтверждения и отклонения: проверки, UPDATE с версией, аудит — атомарно."""
    from mlsiem.soc.playbooks import simulate

    analyst = _require_analyst(analyst)
    event = "action_executed" if new_state == "executed" else "action_rejected"
    with transaction(conn):
        row = conn.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,)).fetchone()
        if row is None:
            raise NotFound(f"действие {action_id} не найдено")
        action = dict(row)
        if action["state"] != "proposed":
            raise InvalidTransition(
                f"по действию {action_id} решение уже принято (состояние «{action['state']}») — "
                "повторно подтвердить или отклонить его нельзя"
            )
        if action["version"] != expected_version:
            raise Conflict(
                f"действие {action_id} изменено кем-то ещё: ваша версия {expected_version}, "
                f"текущая {action['version']} — обновите карточку и повторите"
            )
        at = now_iso()
        simulation = simulate(action) if new_state == "executed" else None
        cur = conn.execute(
            "UPDATE actions SET state = ?, decided_by = ?, decided_at = ?, comment = ?, "
            "simulation = ?, version = version + 1 "
            "WHERE action_id = ? AND version = ? AND state = 'proposed'",
            (
                new_state,
                analyst,
                at,
                comment,
                _json(simulation) if simulation else None,
                action_id,
                expected_version,
            ),
        )
        # BEGIN IMMEDIATE не пускает второго писателя, так что 0 строк здесь — только гонка
        # с кем-то, кто писал в базу в обход transaction(); всё равно честно сообщаем
        if cur.rowcount != 1:
            raise Conflict(f"действие {action_id} изменено кем-то ещё — обновите и повторите")
        inc = conn.execute(
            "SELECT run_id, assignee FROM incidents WHERE incident_id = ?",
            (action["incident_id"],),
        ).fetchone()
        append_audit(
            conn,
            analyst,
            event,
            run_id=inc["run_id"],
            incident_id=action["incident_id"],
            action_id=action_id,
            details={
                "action_type": action["action_type"],
                "target": action["target"],
                "rule_id": action["rule_id"],
                "comment": comment,
                "simulation": simulation,
                **_assignee_mark(inc["assignee"], analyst),
            },
            at=at,
        )
    return get_action(conn, action_id)


def confirm_action(
    conn: sqlite3.Connection,
    action_id: str,
    analyst: str,
    expected_version: int,
    comment: str | None = None,
) -> dict:
    """proposed → executed: подтверждение = симулированное выполнение (FR-018, FR-019)."""
    return _decide(conn, action_id, analyst, expected_version, comment, new_state="executed")


def reject_action(
    conn: sqlite3.Connection,
    action_id: str,
    analyst: str,
    expected_version: int,
    comment: str | None,
) -> dict:
    """proposed → rejected; комментарий обязателен — почему отказались от предложения."""
    if comment is None or not comment.strip():
        raise BadRequest("для отклонения действия нужен комментарий: почему оно не нужно")
    return _decide(
        conn, action_id, analyst, expected_version, comment.strip(), new_state="rejected"
    )


# ---------------------------------------------------------------- инциденты: статус

# Допустимые переходы статуса (data-model): из closed — никуда
TRANSITIONS = {"new": {"in_progress", "closed"}, "in_progress": {"closed"}, "closed": set()}


def change_status(
    conn: sqlite3.Connection,
    incident_id: str,
    analyst: str,
    status: str,
    resolution: str | None,
    comment: str | None,
    expected_version: int,
) -> dict:
    """Смена статуса инцидента с историей и аудитом (FR-014, FR-015, FR-024)."""
    analyst = _require_analyst(analyst)
    if status not in INCIDENT_STATUSES:
        raise BadRequest(f"неизвестный статус {status!r}: допустимы {', '.join(INCIDENT_STATUSES)}")
    if status == "closed" and resolution not in RESOLUTIONS:
        raise BadRequest(
            "при закрытии инцидента нужна резолюция: confirmed (подтверждён) "
            "или false_positive (ложное срабатывание)"
        )
    if status != "closed" and resolution is not None:
        raise BadRequest("резолюция указывается только при закрытии инцидента")
    with transaction(conn):
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"инцидент {incident_id} не найден")
        inc = dict(row)
        if status not in TRANSITIONS[inc["status"]]:
            raise InvalidTransition(
                f"нельзя перевести инцидент из «{inc['status']}» в «{status}»; "
                "допустимо: new → in_progress, new → closed, in_progress → closed"
            )
        if inc["version"] != expected_version:
            raise Conflict(
                f"инцидент {incident_id} изменён кем-то ещё: ваша версия {expected_version}, "
                f"текущая {inc['version']} — обновите карточку и повторите"
            )
        at = now_iso()
        cur = conn.execute(
            "UPDATE incidents SET status = ?, resolution = ?, version = version + 1, "
            "updated_at = ? WHERE incident_id = ? AND version = ?",
            (status, resolution, at, incident_id, expected_version),
        )
        if cur.rowcount != 1:
            raise Conflict(f"инцидент {incident_id} изменён кем-то ещё — обновите и повторите")
        changes = [("status", inc["status"], status)]
        if resolution != inc["resolution"]:
            changes.append(("resolution", inc["resolution"], resolution))
        conn.executemany(
            "INSERT INTO incident_history (incident_id, at, analyst, field, old, new, comment) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(incident_id, at, analyst, f, old, new, comment) for f, old, new in changes],
        )
        append_audit(
            conn,
            analyst,
            "incident_status_changed",
            run_id=inc["run_id"],
            incident_id=incident_id,
            details={
                "changes": [{"field": f, "old": o, "new": n} for f, o, n in changes],
                "comment": comment,
                **_assignee_mark(inc["assignee"], analyst),
            },
            at=at,
        )
    return get_incident(conn, incident_id)


# ---------------------------------------------------------------- инциденты: ответственный


def assign(
    conn: sqlite3.Connection,
    incident_id: str,
    analyst: str,
    assignee: str | None,
    expected_version: int,
    comment: str | None = None,
) -> dict:
    """Назначить или снять ответственного (FR-012, data-model 003).

    Правила те же, что у смены статуса: оптимистичная блокировка по `version`, запись
    в историю (`field = 'assignee'`) и аудит (`incident_assigned`) — одной транзакцией.
    Пустое имя = снять назначение. Назначать можно и закрытый инцидент: статус и резолюция
    при этом не меняются (например, «кто разбирал» проставляют задним числом).
    """
    analyst = _require_analyst(analyst)
    new = None
    if assignee is not None and str(assignee).strip():
        new = clean_name(assignee, "имя ответственного")
    comment = comment.strip() if comment and comment.strip() else None
    with transaction(conn):
        row = conn.execute(
            "SELECT run_id, assignee, version FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if row is None:
            raise NotFound(f"инцидент {incident_id} не найден")
        if row["version"] != expected_version:
            raise Conflict(
                f"инцидент {incident_id} изменён кем-то ещё: ваша версия {expected_version}, "
                f"текущая {row['version']} — обновите карточку и повторите"
            )
        old = row["assignee"]
        if old == new:
            raise BadRequest(
                f"ответственный уже «{new}» — назначать повторно нечего"
                if new
                else "у инцидента и так нет ответственного — снимать нечего"
            )
        at = now_iso()
        cur = conn.execute(
            "UPDATE incidents SET assignee = ?, version = version + 1, updated_at = ? "
            "WHERE incident_id = ? AND version = ?",
            (new, at, incident_id, expected_version),
        )
        if cur.rowcount != 1:
            raise Conflict(f"инцидент {incident_id} изменён кем-то ещё — обновите и повторите")
        conn.execute(
            "INSERT INTO incident_history (incident_id, at, analyst, field, old, new, comment) "
            "VALUES (?, ?, ?, 'assignee', ?, ?, ?)",
            (incident_id, at, analyst, old, new, comment),
        )
        append_audit(
            conn,
            analyst,
            "incident_assigned",
            run_id=row["run_id"],
            incident_id=incident_id,
            details={"old": old, "new": new, "comment": comment},
            at=at,
        )
    return get_incident(conn, incident_id)


# ---------------------------------------------------------------- чтение

# Серьёзность по убыванию: critical первым
SEVERITY_RANK_SQL = (
    "CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
)
# Та же серьёзность числом «чем больше, тем серьёзнее» — чтобы `desc` значил то, что ждёт
# человек: сначала критические
SEVERITY_VALUE_SQL = f"(3 - {SEVERITY_RANK_SQL})"
# Белый список сортировок (research R9): в ORDER BY попадает только выражение отсюда,
# никогда — строка из запроса, так что SQL-инъекция через параметр невозможна
SORTS = {
    "severity": SEVERITY_VALUE_SQL,
    "first_seen": "i.first_seen_ms",
    "last_seen": "i.last_seen_ms",
    "n_alerts": "i.n_alerts",
}
DIRECTIONS = ("asc", "desc")
NO_ASSIGNEE = "__none__"


def _incident_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["targets"] = json.loads(d["targets"])
    return d


def parse_ip_filter(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Точный адрес или префикс сети → сеть (адрес = сеть /32 или /128)."""
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise BadRequest(
            f"фильтр по источнику: {value!r} — не IP-адрес и не сеть вида 10.0.0.0/24"
        ) from exc


def _src_ips_in(conn: sqlite3.Connection, net, run_id: str | None) -> list[str]:
    """Адреса источников (в пределах прогона), входящие в сеть.

    Отбор в Python через ipaddress, а не LIKE в SQL: «10.0.0.1» LIKE «10.0.0.1%» поймал бы
    и 10.0.0.15, а IPv6 вообще пишется по-разному. Источников в прогоне — сотни, это быстро.
    """
    sql = "SELECT DISTINCT src_ip FROM incidents" + (" WHERE run_id = ?" if run_id else "")
    out = []
    for (ip,) in conn.execute(sql, (run_id,) if run_id else ()):
        try:
            if ipaddress.ip_address(ip) in net:
                out.append(ip)
        except ValueError:
            continue
    return out


def _placeholders(values) -> str:
    return ", ".join("?" for _ in values)


def _incident_filters(conn: sqlite3.Connection, filters: dict) -> tuple[str, list]:
    where: list[str] = []
    params: list[Any] = []
    for key in ("status", "severity"):
        values = filters.get(key)
        if values:
            where.append(f"i.{key} IN ({_placeholders(values)})")
            params += list(values)
    for key in ("attack_class", "run_id"):
        if filters.get(key):
            where.append(f"i.{key} = ?")
            params.append(filters[key])
    # Интервал: инцидент подходит, если [first_seen, last_seen] пересекается с [from, to]
    if filters.get("from_ms") is not None:
        where.append("i.last_seen_ms >= ?")
        params.append(filters["from_ms"])
    if filters.get("to_ms") is not None:
        where.append("i.first_seen_ms <= ?")
        params.append(filters["to_ms"])
    # ---- фича 003
    if filters.get("src_ip"):
        ips = _src_ips_in(conn, parse_ip_filter(filters["src_ip"]), filters.get("run_id"))
        where.append(f"i.src_ip IN ({_placeholders(ips)})" if ips else "0")
        params += ips
    if filters.get("assignee"):
        if filters["assignee"] == NO_ASSIGNEE:
            where.append("i.assignee IS NULL")
        else:
            where.append("i.assignee = ?")
            params.append(filters["assignee"])
    if filters.get("action_state"):
        values = filters["action_state"]
        where.append(f"a.state IN ({_placeholders(values)})")
        params += list(values)
    # incident_ids / exclude_ids — для фильтра по меткам подозрительного источника: метки
    # считаются в Python (soc.flags), а сюда приходит готовый список инцидентов
    if filters.get("incident_ids") is not None:
        ids = list(filters["incident_ids"])
        where.append(f"i.incident_id IN ({_placeholders(ids)})" if ids else "0")
        params += ids
    if filters.get("exclude_ids"):
        ids = list(filters["exclude_ids"])
        where.append(f"i.incident_id NOT IN ({_placeholders(ids)})")
        params += ids
    # ---- фича 005
    # «Новые алерты после решения» (FR-017): инциденты, в которые поток дописал алерты уже
    # после решения аналитика
    if filters.get("after_decision") == "only":
        where.append("i.alerts_after_decision > 0")
    # Поглощённые слиянием инциденты (у них 0 алертов и ссылка на поглотителя) по умолчанию
    # скрыты. У пакетных прогонов merged_into всегда NULL — их выдача не меняется
    if not filters.get("show_merged"):
        where.append("i.merged_into IS NULL")
    # ---- фича 007: инциденты с алертами окон (индекс ix_alerts_kind)
    if filters.get("has_window_alerts") is not None:
        exists = f"EXISTS (SELECT 1 {WINDOW_ALERTS_OF_INCIDENT})"
        where.append(exists if filters["has_window_alerts"] else f"NOT {exists}")
    return (" WHERE " + " AND ".join(where)) if where else "", params


def _order_by(sort: str | None, direction: str | None) -> str:
    if sort is None:
        # Порядок фичи 002 — API без параметра sort обязан отдавать его как прежде
        return f"{SEVERITY_RANK_SQL}, i.first_seen_ms, i.incident_id"
    if sort not in SORTS:
        raise BadRequest(f"сортировка {sort!r} не поддерживается; допустимы {list(SORTS)}")
    direction = direction or "desc"
    if direction not in DIRECTIONS:
        raise BadRequest(f"направление сортировки {direction!r}: допустимы asc и desc")
    if sort == "severity":
        # Внутри одной серьёзности — сначала свежие (спека US1 сц. 1)
        return f"{SORTS[sort]} {direction.upper()}, i.first_seen_ms DESC, i.incident_id"
    return f"{SORTS[sort]} {direction.upper()}, i.incident_id"


INCIDENT_FROM = "FROM incidents i LEFT JOIN actions a ON a.incident_id = i.incident_id"
# Алерты окон инцидента `i` (фича 007) — подзапрос по индексу ix_alerts_kind. У прогонов до
# 007 все алерты — `flow` (значение по умолчанию колонки), поэтому число окон там 0
WINDOW_ALERTS_OF_INCIDENT = (
    "FROM alerts w WHERE w.incident_id = i.incident_id AND w.alert_kind = 'window'"
)
N_WINDOW_ALERTS_SQL = f"(SELECT COUNT(*) {WINDOW_ALERTS_OF_INCIDENT}) AS n_window_alerts"


def list_incidents(
    conn: sqlite3.Connection,
    filters: dict,
    limit: int = 50,
    offset: int = 0,
    *,
    sort: str | None = None,
    direction: str | None = None,
) -> tuple[int, list[dict]]:
    """(всего подходящих, страница).

    Без `sort` — порядок 002: серьёзность ↓, first_seen_ms ↑, incident_id. С `sort` — ключ
    из белого списка `SORTS` в направлении `direction` и `incident_id` для стабильности.
    """
    where, params = _incident_filters(conn, filters)
    order = _order_by(sort, direction)
    total = conn.execute(f"SELECT COUNT(*) {INCIDENT_FROM}{where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT i.*, {N_WINDOW_ALERTS_SQL}, a.action_id AS a_action_id, "
        "a.action_type AS a_action_type, "
        f"a.target AS a_target, a.state AS a_state {INCIDENT_FROM}{where} "
        f"ORDER BY {order} LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    items = []
    for r in rows:
        d = _incident_row(r)
        action = {k[2:]: d.pop(k) for k in list(d) if k.startswith("a_")}
        d["action"] = action if action["action_id"] else None
        items.append(d)
    return total, items


def get_incident(conn: sqlite3.Connection, incident_id: str) -> dict:
    """Карточка: инцидент + полное действие + история изменений."""
    row = conn.execute(
        f"SELECT i.*, {N_WINDOW_ALERTS_SQL} FROM incidents i WHERE i.incident_id = ?",
        (incident_id,),
    ).fetchone()
    if row is None:
        raise NotFound(f"инцидент {incident_id} не найден")
    inc = _incident_row(row)
    action = conn.execute("SELECT * FROM actions WHERE incident_id = ?", (incident_id,)).fetchone()
    inc["action"] = _action_row(action) if action else None
    inc["history"] = [
        dict(h)
        for h in conn.execute(
            "SELECT at, analyst, field, old, new, comment FROM incident_history "
            "WHERE incident_id = ? ORDER BY history_id",
            (incident_id,),
        )
    ]
    return inc


def list_alerts(
    conn: sqlite3.Connection,
    incident_id: str,
    limit: int = 50,
    offset: int = 0,
    *,
    kind: str | None = None,
) -> tuple[int, list[dict]]:
    """Алерты инцидента постранично, по времени начала потока. `kind` (фича 007) —
    только алерты потоков (`flow`) или окон (`window`); без него — все, как раньше."""
    exists = conn.execute(
        "SELECT 1 FROM incidents WHERE incident_id = ?", (incident_id,)
    ).fetchone()
    if exists is None:
        raise NotFound(f"инцидент {incident_id} не найден")
    where, params = "incident_id = ?", [incident_id]
    if kind is not None:
        if kind not in ALERT_KINDS:
            raise BadRequest(f"вид алерта {kind!r}: допустимы {list(ALERT_KINDS)}")
        where += " AND alert_kind = ?"
        params.append(kind)
    total = conn.execute(f"SELECT COUNT(*) FROM alerts WHERE {where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM alerts WHERE {where} ORDER BY first_seen_ms, flow_uid LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    return total, [alert_row(r) for r in rows]


def get_alert(conn: sqlite3.Connection, run_id: str, flow_uid: str) -> dict | None:
    """Один алерт прогона по потоку (или None, если поток не стал алертом)."""
    row = conn.execute(
        "SELECT * FROM alerts WHERE run_id = ? AND flow_uid = ?", (run_id, flow_uid)
    ).fetchone()
    return alert_row(row) if row else None


EXPERTS_NOTE = "алерт, поднятый несколькими экспертами, учитывается у каждого в by_expert"


def experts_summary(conn: sqlite3.Connection, incident_id: str) -> dict:
    """Кто поднял алерты инцидента (фича 004, data-model «Сводка по экспертам»).

    Один GROUP BY по `fired_experts` (индекс ix_alerts_incident_experts): сочетания
    «классификатор», «классификатор + аномалии», «только мета-слой» и т. д. У алертов прогона
    до ансамбля `fired_experts` = NULL — тогда `available: false` и пометка с версией детектора.
    """
    row = conn.execute(
        "SELECT r.detector_version FROM incidents i JOIN runs r ON r.run_id = i.run_id "
        "WHERE i.incident_id = ?",
        (incident_id,),
    ).fetchone()
    if row is None:
        raise NotFound(f"инцидент {incident_id} не найден")
    groups = conn.execute(
        "SELECT fired_experts, COUNT(*) AS n FROM alerts WHERE incident_id = ? "
        "GROUP BY fired_experts ORDER BY fired_experts",
        (incident_id,),
    ).fetchall()
    known = [(g["fired_experts"], g["n"]) for g in groups if g["fired_experts"] is not None]
    if not known:
        return {
            "available": False,
            "by_expert": {},
            "combinations": [],
            "note": (
                f"прогон сделан до появления ансамбля (один детектор {row['detector_version']})"
            ),
        }
    by_expert: dict[str, int] = {}
    combinations = []
    for fired, n in known:
        names = sorted(x for x in fired.split(",") if x)
        for name in names:
            by_expert[name] = by_expert.get(name, 0) + n
        combinations.append({"experts": names, "n_alerts": n})
    combinations.sort(key=lambda c: (-c["n_alerts"], c["experts"]))
    return {
        "available": True,
        "by_expert": dict(sorted(by_expert.items())),
        "combinations": combinations,
        "note": EXPERTS_NOTE,
    }


def list_audit(
    conn: sqlite3.Connection,
    filters: dict,
    limit: int = 50,
    offset: int = 0,
    *,
    newest_first: bool = False,
) -> tuple[int, list[dict]]:
    """Аудит-журнал с фильтрами. По умолчанию — по порядку записи (как в API 002);
    `newest_first` — новые сверху, для страницы журнала консоли."""
    where: list[str] = []
    params: list[Any] = []
    for key in ("incident_id", "actor", "event", "run_id", "action_id"):
        if filters.get(key):
            where.append(f"{key} = ?")
            params.append(filters[key])
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    order = "entry_id DESC" if newest_first else "entry_id"
    total = conn.execute(f"SELECT COUNT(*) FROM audit_log{clause}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM audit_log{clause} ORDER BY {order} LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["details"] = json.loads(d["details"])
        items.append(d)
    return total, items


# ---------------------------------------------------------------- чтение для консоли (003)


def incident_audit(conn: sqlite3.Connection, incident_id: str) -> list[dict]:
    """Все записи аудита инцидента по порядку записи — для карточки и хронологии."""
    total, _ = list_audit(conn, {"incident_id": incident_id}, limit=1)
    return list_audit(conn, {"incident_id": incident_id}, limit=max(total, 1))[1]


def get_run(conn: sqlite3.Connection, run_id: str) -> dict:
    row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise NotFound(f"прогон {run_id} не найден")
    return _run_row(row)


def latest_run_id(conn: sqlite3.Connection) -> str | None:
    """Последний прогон — тот же порядок, что у `list_runs` (новые сверху)."""
    row = conn.execute(
        "SELECT run_id FROM runs ORDER BY started_at DESC, run_id DESC LIMIT 1"
    ).fetchone()
    return row["run_id"] if row else None


def run_sources(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    """`incident_id`, `src_ip`, `targets` всех инцидентов прогона — вход для меток (soc.flags)."""
    return [
        {
            "incident_id": r["incident_id"],
            "src_ip": r["src_ip"],
            "targets": json.loads(r["targets"]),
        }
        for r in conn.execute(
            "SELECT incident_id, src_ip, targets FROM incidents WHERE run_id = ? "
            "ORDER BY first_seen_ms, incident_id",
            (run_id,),
        )
    ]


def alert_histogram(conn: sqlite3.Connection, incident_id: str, bins: int = 40) -> dict:
    """Распределение алертов инцидента по времени (FR-011, research R11).

    Ширина корзины — не уже секунды: для инцидента из алертов одной секунды 40 корзин по
    25 мс выглядели бы как шум. Считает сама база (GROUP BY по номеру корзины) — карточка
    инцидента с тысячами алертов открывается так же быстро, как с одним.
    """
    inc = conn.execute(
        "SELECT first_seen_ms, last_seen_ms, n_alerts FROM incidents WHERE incident_id = ?",
        (incident_id,),
    ).fetchone()
    if inc is None:
        raise NotFound(f"инцидент {incident_id} не найден")
    start, end = inc["first_seen_ms"], max(inc["last_seen_ms"], inc["first_seen_ms"])
    bin_ms = max(1000, math.ceil((end - start) / bins))
    n_bins = min(bins, (end - start) // bin_ms + 1)
    counts = [0] * n_bins
    # Фича 007: алерты окон — отдельным рядом (консоль раскрашивает их иначе); `counts` по-
    # прежнему считает ВСЕ алерты, чтобы смысл поля 003 не менялся
    window_counts = [0] * n_bins
    rows = conn.execute(
        "SELECT MAX(0, MIN((first_seen_ms - ?) / ?, ?)) AS b, alert_kind, COUNT(*) AS n "
        "FROM alerts WHERE incident_id = ? GROUP BY b, alert_kind",
        (start, bin_ms, n_bins - 1, incident_id),
    )
    for r in rows:
        counts[int(r["b"])] += r["n"]
        if r["alert_kind"] == "window":
            window_counts[int(r["b"])] += r["n"]
    return {
        "start_ms": start,
        "end_ms": end,
        "bin_ms": bin_ms,
        "counts": counts,
        "window_counts": window_counts,
    }


def dashboard_summary(conn: sqlite3.Connection, run_id: str) -> dict:
    """Счётчики панели прогона (FR-021, data-model DashboardSummary).

    Каждый счётчик считается ровно тем же условием, что и фильтр списка, в который он ведёт
    (SC-004): «без ответственного» = assignee IS NULL и статус не closed, «ждут решения» =
    действие в состоянии proposed.
    """

    def grouped(column: str) -> dict[str, int]:
        return {
            r[0]: r[1]
            for r in conn.execute(
                f"SELECT {column}, COUNT(*) FROM incidents WHERE run_id = ? "
                f"AND merged_into IS NULL GROUP BY {column}",
                (run_id,),
            )
        }

    by_status, by_severity = grouped("status"), grouped("severity")
    by_class = dict(sorted(grouped("attack_class").items(), key=lambda kv: (-kv[1], kv[0])))
    actions_pending = conn.execute(
        "SELECT COUNT(*) FROM actions a JOIN incidents i ON i.incident_id = a.incident_id "
        "WHERE i.run_id = ? AND a.state = 'proposed' AND i.merged_into IS NULL",
        (run_id,),
    ).fetchone()[0]
    unassigned = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE run_id = ? AND assignee IS NULL "
        "AND status != 'closed' AND merged_into IS NULL",
        (run_id,),
    ).fetchone()[0]
    return {
        "total": sum(by_status.values()),
        "by_status": {s: by_status.get(s, 0) for s in INCIDENT_STATUSES},
        "by_severity": {s: by_severity.get(s, 0) for s in reversed(SEVERITY_LEVELS)},
        "by_class": by_class,
        "actions_pending": actions_pending,
        "unassigned": unassigned,
    }


def recent_alerts(conn: sqlite3.Connection, run_id: str, n: int) -> list[dict]:
    """Последние по времени потока алерты прогона (индекс ix_alerts_run_time)."""
    return [
        alert_row(r)
        for r in conn.execute(
            "SELECT * FROM alerts WHERE run_id = ? ORDER BY first_seen_ms DESC, flow_uid LIMIT ?",
            (run_id, n),
        )
    ]


def list_state(conn: sqlite3.Connection, run_id: str | None) -> str:
    """Короткий «отпечаток» состояния прогона — основа ETag опрашиваемых фрагментов.

    Меняется при любом решении: смена статуса или назначения двигает `updated_at` инцидента,
    решение по действию — `version` действия, и всё это пишет аудит (`max(entry_id)`).
    Не меняется, пока никто ничего не решал, — тогда опрос отвечает 204 и страница не мигает.
    """
    row = conn.execute(
        "SELECT COUNT(*), MAX(i.updated_at), SUM(COALESCE(a.version, 0)) "
        f"{INCIDENT_FROM} WHERE i.run_id = ?",
        (run_id,),
    ).fetchone()
    audit = conn.execute("SELECT MAX(entry_id) FROM audit_log").fetchone()[0]
    runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    # Фича 005: онлайн-сеанс растёт — каждая записанная пачка двигает last_activity_at
    # (у пакетных прогонов он NULL и ETag прежний)
    activity = conn.execute(
        "SELECT last_activity_at, status FROM runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if activity is not None and activity[0] is not None:
        runs = f"{runs}:{activity[0]}:{activity[1]}"
    return input_digest(run_id or "", *(str(x) for x in (*tuple(row), audit, runs)))[:16]


def incident_versions(conn: sqlite3.Connection, incident_id: str) -> tuple[int, int | None]:
    """(версия инцидента, версия действия или None) — для «штампа» открытой карточки."""
    row = conn.execute(
        "SELECT i.version, a.version AS av FROM incidents i "
        "LEFT JOIN actions a ON a.incident_id = i.incident_id WHERE i.incident_id = ?",
        (incident_id,),
    ).fetchone()
    if row is None:
        raise NotFound(f"инцидент {incident_id} не найден")
    return row["version"], row["av"]


def run_assignees(conn: sqlite3.Connection, run_id: str) -> list[str]:
    """Имена ответственных в прогоне — варианты для фильтра «ответственный» в консоли."""
    return [
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT assignee FROM incidents WHERE run_id = ? AND assignee IS NOT NULL "
            "ORDER BY assignee",
            (run_id,),
        )
    ]


# ---------------------------------------------------------------- поток (фича 005)
#
# Онлайн-сеанс — это прогон с mode = 'stream' (data-model «Сеанс»). Его пишет потребитель
# `mlsiem stream consume` пачками: каждая пачка — ОДНА транзакция, в которой вместе лежат
# алерты, инциденты, действия, аудит, отметки обработанных потоков и позиция чтения брокера.
# Поэтому после любого сбоя база либо содержит пачку целиком вместе с позицией, либо не
# содержит ни того, ни другого — и перечитанные сообщения дадут ровно тот же результат
# (research R7).

SESSION_PREFIX = "stream-"
LEASE_NAME = "consumer"
STATS_KEEP_HOURS = 24


def session_run_id(source_id: str) -> str:
    """`stream-<хеш12>` от источника: один источник — один сеанс при любых перезапусках."""
    return SESSION_PREFIX + input_digest(source_id)[:12]


def session_by_source(conn: sqlite3.Connection, source_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM runs WHERE source_id = ?", (source_id,)).fetchone()
    return _run_row(row) if row else None


def create_session(
    conn: sqlite3.Connection,
    source_id: str,
    *,
    model_version: str,
    summary: dict,
    at: str | None = None,
) -> dict:
    """Новый сеанс `running` для источника (или уже существующий — идемпотентно).

    `summary` — как у пакетного прогона 004 (model, experts, experts_meta, threshold, classes…)
    плюс раздел `stream` со счётчиками; `run_loaded` пишется в аудит один раз, при создании.
    """
    existing = session_by_source(conn, source_id)
    if existing is not None:
        return existing
    at = at or now_iso()
    run_id = session_run_id(source_id)
    stream = {
        "n_rejected": 0,
        "n_late": 0,
        "n_merged": 0,
        "n_after_decision": 0,
        "end_received": False,
        "last_seq": None,
        "max_first_seen_ms": None,
        "parts": 0,
    }
    with transaction(conn):
        conn.execute(
            'INSERT INTO runs (run_id, source, input_hash, detector_version, "limit", started_at, '
            "finished_at, n_flows, n_alerts, n_incidents, summary, warnings, mode, status, "
            "source_id, last_activity_at, model_version) "
            "VALUES (?, ?, ?, ?, NULL, ?, ?, 0, 0, 0, ?, '[]', 'stream', 'running', ?, ?, ?)",
            (
                run_id,
                f"stream:{source_id}",
                input_digest(source_id),
                model_version,
                at,
                at,
                _json({**summary, "stream": {**stream, **summary.get("stream", {})}}),
                source_id,
                at,
                model_version,
            ),
        )
        append_audit(
            conn,
            SYSTEM_ACTOR,
            "run_loaded",
            run_id=run_id,
            details={
                "source": f"stream:{source_id}",
                "mode": "stream",
                "n_flows": 0,
                "n_alerts": 0,
                "n_incidents": 0,
                "detector_version": model_version,
            },
            at=at,
        )
    return get_run(conn, run_id)


def _set_status(conn, run_id: str, new: str, reason: str, at: str) -> bool:
    """Смена статуса сеанса с аудитом; внутри уже открытой транзакции. True — изменился."""
    if new not in RUN_STATUSES:
        raise BadRequest(f"неизвестный статус сеанса {new!r}: допустимы {list(RUN_STATUSES)}")
    row = conn.execute("SELECT status, mode FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise NotFound(f"сеанс {run_id} не найден")
    if row["mode"] != "stream":
        raise BadRequest(f"прогон {run_id} — пакетный, у него нет статуса сеанса")
    if row["status"] == new:
        return False
    conn.execute("UPDATE runs SET status = ? WHERE run_id = ?", (new, run_id))
    append_audit(
        conn,
        SYSTEM_ACTOR,
        "session_status_changed",
        run_id=run_id,
        details={"old": row["status"], "new": new, "reason": reason},
        at=at,
    )
    return True


def set_session_status(conn: sqlite3.Connection, run_id: str, new: str, reason: str) -> bool:
    """running | stopped | completed с записью в аудит (data-model «Переходы статуса»)."""
    with transaction(conn):
        return _set_status(conn, run_id, new, reason, now_iso())


def load_offsets(conn: sqlite3.Connection) -> dict[tuple[str, int], int]:
    """Позиции чтения брокера из SQLite — источник истины при старте потребителя (R7)."""
    return {
        (r["topic"], r["partition"]): r["next_offset"]
        for r in conn.execute("SELECT topic, partition, next_offset FROM stream_offsets")
    }


def seen_flows(conn: sqlite3.Connection, run_id: str, flow_uids: list[str]) -> set[str]:
    """Какие из потоков сеанса уже обработаны (повторная доставка отсекается здесь, FR-015)."""
    out: set[str] = set()
    for i in range(0, len(flow_uids), 500):
        chunk = flow_uids[i : i + 500]
        out |= {
            r[0]
            for r in conn.execute(
                "SELECT flow_uid FROM stream_seen WHERE run_id = ? AND flow_uid IN "
                f"({_placeholders(chunk)})",
                [run_id, *chunk],
            )
        }
    return out


def seen_count(conn: sqlite3.Connection, run_id: str, max_seq: int) -> int:
    """Сколько РАЗНЫХ потоков сеанса с seq ≤ max_seq уже обработано — для «всё до end»."""
    return conn.execute(
        "SELECT COUNT(*) FROM stream_seen WHERE run_id = ? AND seq <= ?", (run_id, max_seq)
    ).fetchone()[0]


def _check_version(conn, incident_id: str, expected: int, action: dict | None) -> None:
    row = conn.execute(
        "SELECT i.version, a.state AS a_state, a.version AS a_version FROM incidents i "
        "LEFT JOIN actions a ON a.incident_id = i.incident_id WHERE i.incident_id = ?",
        (incident_id,),
    ).fetchone()
    if row is None:
        raise Conflict(f"инцидент {incident_id} пропал — план пачки устарел")
    if row["version"] != expected:
        raise Conflict(
            f"инцидент {incident_id} изменён, пока пачка готовилась (версия {expected} → "
            f"{row['version']}) — план будет пересчитан"
        )
    if action is not None and (row["a_state"], row["a_version"]) != (
        action["state"],
        action["version"],
    ):
        raise Conflict(f"действие инцидента {incident_id} изменено — план будет пересчитан")


def _action_details(a: dict) -> dict:
    return {
        "action_type": a["action_type"],
        "target": a["target"],
        "rule_id": a["rule_id"],
        "rule_text": a["rule_text"],
    }


def _stream_alert_row(a: dict, run_id: str, received_at: str) -> tuple:
    full = {**_alert_defaults(a), **a, "run_id": run_id, "alert_id": f"{run_id}/{a['flow_uid']}"}
    return (*(full[c] for c in ALERT_COLUMNS), int(a.get("late") or 0), received_at)


def _apply_plan(conn, plan, at: str) -> dict[str, int]:
    """Один сеанс пачки внутри уже открытой транзакции. Возвращает прибавки к счётчикам."""
    run_id = plan.run_id
    counts = {"n_merged": 0, "n_after_decision": 0}
    for u in plan.updates:
        _check_version(conn, u.incident_id, u.expected_version, u.action)
    for m in plan.merges:
        _check_version(conn, m.absorbed_id, m.expected_version, m.action)

    # 1. Новые инциденты (раньше слияний: поглотитель может быть новым)
    for n in plan.new_incidents:
        row = {
            **n.row,
            "run_id": run_id,
            "status": "new",
            "resolution": None,
            "version": 1,
            "created_at": at,
            "updated_at": at,
        }
        _insert_many(conn, "incidents", INCIDENT_COLUMNS, [row])

    # 2. Слияния: алерты поглощённого — в поглотителя, у поглощённого пометка и снятое
    #    предложение. Статус и решения аналитика не трогаются — их и не было: по инциденту с
    #    решением слияние не планируется вовсе (FR-017)
    for m in plan.merges:
        conn.execute(
            "UPDATE alerts SET incident_id = ? WHERE incident_id = ?", (m.into_id, m.absorbed_id)
        )
        cur = conn.execute(
            "UPDATE incidents SET merged_into = ?, n_alerts = 0, version = version + 1, "
            "updated_at = ? WHERE incident_id = ? AND version = ?",
            (m.into_id, at, m.absorbed_id, m.expected_version),
        )
        if cur.rowcount != 1:
            raise Conflict(f"инцидент {m.absorbed_id} изменён — план будет пересчитан")
        withdrawn = None
        if m.action is not None and m.action["state"] == "proposed":
            conn.execute(
                "UPDATE actions SET state = 'rejected', decided_by = ?, decided_at = ?, "
                "comment = ?, version = version + 1 WHERE action_id = ? AND version = ?",
                (
                    SYSTEM_ACTOR,
                    at,
                    f"инцидент объединён с {m.into_id} — предложение снято",
                    m.action["action_id"],
                    m.action["version"],
                ),
            )
            withdrawn = m.action["action_id"]
        append_audit(
            conn,
            SYSTEM_ACTOR,
            "incident_merged",
            run_id=run_id,
            incident_id=m.absorbed_id,
            action_id=withdrawn,
            details={
                "into": m.into_id,
                "moved_alerts": m.moved_alerts,
                "action_withdrawn": withdrawn,
            },
            at=at,
        )
        counts["n_merged"] += 1

    # 3. Алерты пачки: повтор той же пары (сеанс, поток) игнорируется (FR-015)
    conn.executemany(
        f"INSERT OR IGNORE INTO alerts ({', '.join(ALERT_COLUMNS)}, late, received_at) "
        f"VALUES ({', '.join('?' for _ in ALERT_COLUMNS)}, ?, ?)",
        [_stream_alert_row(a, run_id, at) for a in plan.alerts],
    )

    # 4. Дописанные инциденты: поля по всем алертам, серьёзность — в историю, предложение —
    #    пересчитать, если решения ещё нет (research R9)
    for u in plan.updates:
        f = u.fields
        cur = conn.execute(
            "UPDATE incidents SET targets = ?, first_seen_ms = ?, last_seen_ms = ?, "
            "last_alert_start_ms = ?, n_alerts = ?, max_score = ?, mean_score = ?, severity = ?, "
            "severity_reason = ?, alerts_after_decision = alerts_after_decision + ?, "
            "first_after_decision_ms = ?, version = version + 1, updated_at = ? "
            "WHERE incident_id = ? AND version = ?",
            (
                f["targets"],
                f["first_seen_ms"],
                f["last_seen_ms"],
                f["last_alert_start_ms"],
                f["n_alerts"],
                f["max_score"],
                f["mean_score"],
                f["severity"],
                f["severity_reason"],
                u.after_decision_added,
                u.first_after_decision_ms,
                at,
                u.incident_id,
                u.expected_version,
            ),
        )
        if cur.rowcount != 1:
            raise Conflict(f"инцидент {u.incident_id} изменён — план будет пересчитан")
        if f["severity"] != u.old_severity:
            conn.execute(
                "INSERT INTO incident_history (incident_id, at, analyst, field, old, new, comment) "
                "VALUES (?, ?, ?, 'severity', ?, ?, ?)",
                (
                    u.incident_id,
                    at,
                    SYSTEM_ACTOR,
                    u.old_severity,
                    f["severity"],
                    f["severity_reason"],
                ),
            )
        append_audit(
            conn,
            SYSTEM_ACTOR,
            "incident_updated",
            run_id=run_id,
            incident_id=u.incident_id,
            details={
                "added": u.added,
                "moved": u.moved,
                "n_alerts": f["n_alerts"],
                "severity_old": u.old_severity,
                "severity_new": f["severity"],
                "after_decision": u.decided,
            },
            at=at,
        )
        counts["n_after_decision"] += u.after_decision_added
        if u.new_action is not None and u.action is not None:
            cur = conn.execute(
                "UPDATE actions SET action_type = ?, target = ?, rule_id = ?, rule_text = ?, "
                "version = version + 1 WHERE action_id = ? AND version = ? AND state = 'proposed'",
                (
                    u.new_action["action_type"],
                    u.new_action["target"],
                    u.new_action["rule_id"],
                    u.new_action["rule_text"],
                    u.action["action_id"],
                    u.action["version"],
                ),
            )
            if cur.rowcount != 1:
                raise Conflict(f"действие {u.action['action_id']} изменено — план будет пересчитан")
            append_audit(
                conn,
                SYSTEM_ACTOR,
                "action_reproposed",
                run_id=run_id,
                incident_id=u.incident_id,
                action_id=u.action["action_id"],
                details={"old": _action_details(u.action), "new": _action_details(u.new_action)},
                at=at,
            )

    # 5. Предложения новых инцидентов — как в пакетном прогоне
    for n in plan.new_incidents:
        a = n.action
        _insert_many(conn, "actions", ACTION_COLUMNS, [{**a, "state": "proposed", "version": 1}])
        append_audit(
            conn,
            SYSTEM_ACTOR,
            "action_proposed",
            run_id=run_id,
            incident_id=a["incident_id"],
            action_id=a["action_id"],
            details=_action_details(a),
            at=at,
        )

    # 6. Известные причины расхождения с пакетным режимом (FR-021)
    conn.executemany(
        "INSERT INTO stream_divergences (run_id, kind, incident_id, other_incident_id, flow_uid, "
        "at, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (
                run_id,
                d["kind"],
                d.get("incident_id"),
                d.get("other_incident_id"),
                d.get("flow_uid"),
                at,
                _json(d.get("details") or {}),
            )
            for d in plan.divergences
        ],
    )
    return counts


def _add_counts(base: dict, delta: dict) -> dict:
    out = dict(base)
    for k, v in delta.items():
        out[k] = (out.get(k) or 0) + v
    return dict(sorted(out.items()))


def append_batch(
    conn: sqlite3.Connection,
    plans: list,
    *,
    offsets: dict[tuple[str, int], int],
    seen: dict[str, list[tuple[str, int]]] | None = None,
    sessions: dict[str, dict] | None = None,
    stats: list[dict] | None = None,
    at: str | None = None,
    extra: list | None = None,
) -> None:
    """Пачка потребителя ОДНОЙ транзакцией (FR-012, FR-015, FR-016, research R7).

    - `plans` — `stream.incremental.SessionPlan` по сеансам пачки (алерты, инциденты,
      слияния, действия). Версии инцидентов и действий сверяются с планом: если аналитик
      успел что-то решить, — `Conflict`, и потребитель пересчитает план (FR-020);
    - `seen` — обработанные потоки (flow_uid, seq) по сеансам;
    - `sessions` — по сеансам: `n_flows` (сколько новых потоков), `stream` (прибавки к
      счётчикам раздела stream сводки), `stream_set` (значения, которые заменяются),
      `summary` (прибавки к счётчикам сводки 004: alerts_by_expert, n_reversed),
      `status`/`reason` (новый статус сеанса);
    - `offsets` — позиции чтения (следующая позиция) по (топик, партиция);
    - `stats` — строки показателей (R11);
    - `extra` — дополнительные записи той же транзакции: функции `(conn, at)`. Фича 007
      пишет так незакрытые и закрытые окна сеанса (R13) — вместе с позицией, а не отдельно.

    Любая ошибка — ROLLBACK: ни алертов, ни позиции. Брокеру позиция подтверждается только
    после успешного возврата отсюда.
    """
    at = at or now_iso()
    sessions = sessions or {}
    seen = seen or {}
    with transaction(conn):
        per_run: dict[str, dict[str, int]] = {}
        for plan in plans:
            per_run[plan.run_id] = _apply_plan(conn, plan, at)
        for fn in extra or []:
            fn(conn, at)
        for run_id, items in seen.items():
            conn.executemany(
                "INSERT OR IGNORE INTO stream_seen (run_id, flow_uid, seq) VALUES (?, ?, ?)",
                [(run_id, uid, seq) for uid, seq in items],
            )
        for run_id in sorted({*per_run, *sessions, *seen}):
            s = sessions.get(run_id, {})
            row = conn.execute("SELECT summary FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            if row is None:
                raise NotFound(f"сеанс {run_id} не найден")
            summary = json.loads(row["summary"])
            stream = _add_counts(summary.get("stream") or {}, s.get("stream", {}))
            stream = _add_counts(stream, per_run.get(run_id, {}))
            stream.update(s.get("stream_set", {}))
            summary["stream"] = stream
            for k, v in s.get("summary", {}).items():
                if isinstance(v, dict):
                    summary[k] = _add_counts(summary.get(k) or {}, v)
                else:
                    summary[k] = (summary.get(k) or 0) + v
            conn.execute(
                "UPDATE runs SET n_flows = n_flows + ?, "
                "n_alerts = (SELECT COUNT(*) FROM alerts WHERE run_id = ?), "
                "n_incidents = (SELECT COUNT(*) FROM incidents WHERE run_id = ? "
                "AND merged_into IS NULL), summary = ?, last_activity_at = ?, finished_at = ? "
                "WHERE run_id = ?",
                (s.get("n_flows", 0), run_id, run_id, _json(summary), at, at, run_id),
            )
            if s.get("status"):
                _set_status(conn, run_id, s["status"], s.get("reason", ""), at)
        conn.executemany(
            "INSERT INTO stream_offsets (topic, partition, next_offset, updated_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT (topic, partition) DO UPDATE SET "
            "next_offset = MAX(next_offset, excluded.next_offset), "
            "updated_at = excluded.updated_at",
            [(t, p, o, at) for (t, p), o in sorted(offsets.items())],
        )
        if stats:
            write_stats(conn, stats, at=at)


def _iso_at(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _ts(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def write_stats(conn: sqlite3.Connection, rows: list[dict], *, at: str | None = None) -> None:
    """Показатели потока (R11). Это не аудит: строки старше суток удаляются."""
    at = at or now_iso()
    conn.executemany(
        "INSERT INTO stream_stats (at, run_id, processed, lag_messages, lag_seconds, "
        "latency_p50_ms, latency_p95_ms, rejected, late, rate_per_s, packets_per_s, "
        "flows_per_s, drops, buffer_fill, liveness) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                r.get("at", at),
                r["run_id"],
                r.get("processed", 0),
                r.get("lag_messages"),
                r.get("lag_seconds"),
                r.get("latency_p50_ms"),
                r.get("latency_p95_ms"),
                r.get("rejected", 0),
                r.get("late", 0),
                r.get("rate_per_s"),
                r.get("packets_per_s"),
                r.get("flows_per_s"),
                r.get("drops"),
                r.get("buffer_fill"),
                r.get("liveness"),
            )
            for r in rows
        ],
    )
    cutoff = _iso_at(_ts(at) - STATS_KEEP_HOURS * 3600)
    conn.execute("DELETE FROM stream_stats WHERE at < ?", (cutoff,))


def latest_sensor_stats(conn: sqlite3.Connection, run_id: str) -> dict | None:
    """Последняя строка показателей сенсора сеанса (фича 006): где заполнены packets_per_s.

    Показатели сенсора пишет сам сенсор, а стандартные показатели 005 — потребитель, разными
    строками; `latest_stats` вернул бы любую последнюю, поэтому для сенсор-полей отбираем
    последнюю строку, где они есть."""
    row = conn.execute(
        "SELECT packets_per_s, flows_per_s, drops, buffer_fill, liveness FROM stream_stats "
        "WHERE run_id = ? AND packets_per_s IS NOT NULL ORDER BY stat_id DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    return dict(row) if row else None


def mark_lossy(conn: sqlite3.Connection, run_id: str) -> None:
    """Сеанс «с потерями» (фича 006, R10): сенсор потерял пакеты или потоки при отказе
    брокера/перегрузке. Флаг только поднимается — потеря не «заживает» сама."""
    conn.execute("UPDATE runs SET lossy = 1 WHERE run_id = ?", (run_id,))


def latest_stats(conn: sqlite3.Connection, run_id: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM stream_stats WHERE run_id = ? ORDER BY stat_id DESC LIMIT 1", (run_id,)
    ).fetchone()
    return dict(row) if row else None


def list_sessions(conn: sqlite3.Connection) -> list[dict]:
    """Онлайн-сеансы, новые сверху."""
    return [
        _run_row(r)
        for r in conn.execute(
            "SELECT * FROM runs WHERE mode = 'stream' ORDER BY started_at DESC, run_id DESC"
        )
    ]


def divergences(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    out = []
    for r in conn.execute(
        "SELECT * FROM stream_divergences WHERE run_id = ? ORDER BY divergence_id", (run_id,)
    ):
        d = dict(r)
        d["details"] = json.loads(d["details"])
        out.append(d)
    return out


# ---------------------------------------------------------------- аренда потребителя (FR-019)


class LeaseHeld(StoreError):
    """Аренду держит другой живой потребитель."""

    code = "conflict"


def acquire_lease(conn: sqlite3.Connection, holder: str, ttl_s: float, *, now: float) -> None:
    """Взять аренду единственного потребителя (атомарно: BEGIN IMMEDIATE).

    Живая чужая аренда (продлена меньше `ttl_s` назад) → `LeaseHeld` с тем, кто и с какого
    времени держит. Истёкшая — забирается: прежний потребитель упал или завис.
    """
    with transaction(conn):
        row = conn.execute("SELECT * FROM stream_lease WHERE name = ?", (LEASE_NAME,)).fetchone()
        if row is not None and row["holder"] != holder:
            age = now - _ts(row["renewed_at"])
            if age < ttl_s:
                raise LeaseHeld(
                    f"уже работает потребитель {row['holder']} с {row['acquired_at']} (аренда "
                    f"продлена {age:.0f} с назад) — второй не запускаю (FR-019)"
                )
        at = _iso_at(now)
        conn.execute(
            "INSERT INTO stream_lease (name, holder, acquired_at, renewed_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT (name) DO UPDATE SET holder = excluded.holder, "
            "acquired_at = excluded.acquired_at, renewed_at = excluded.renewed_at",
            (LEASE_NAME, holder, at, at),
        )


def renew_lease(conn: sqlite3.Connection, holder: str, *, now: float) -> bool:
    """Продлить свою аренду. False — её уже забрал другой (эта истекла): надо остановиться."""
    with transaction(conn):
        cur = conn.execute(
            "UPDATE stream_lease SET renewed_at = ? WHERE name = ? AND holder = ?",
            (_iso_at(now), LEASE_NAME, holder),
        )
        return cur.rowcount == 1


def release_lease(conn: sqlite3.Connection, holder: str) -> None:
    with transaction(conn):
        conn.execute("DELETE FROM stream_lease WHERE name = ? AND holder = ?", (LEASE_NAME, holder))


def lease_info(conn: sqlite3.Connection, ttl_s: float, *, now: float) -> dict:
    """Кто держит аренду и жива ли она — для `stream status` и панели."""
    row = conn.execute("SELECT * FROM stream_lease WHERE name = ?", (LEASE_NAME,)).fetchone()
    if row is None:
        return {"alive": False, "holder": None, "renewed_at": None, "acquired_at": None}
    return {
        "alive": now - _ts(row["renewed_at"]) < ttl_s,
        "holder": row["holder"],
        "renewed_at": row["renewed_at"],
        "acquired_at": row["acquired_at"],
    }
