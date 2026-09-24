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
)
SYSTEM_ACTOR = "system"
# Версия схемы в PRAGMA user_version. База фичи 002 имеет 0 (единица зарезервирована как
# «схема 002», чтобы явно отличать её от пустого файла); фича 003 вводит версию 2
SCHEMA_VERSION = 2


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
    severity         TEXT NOT NULL CHECK (severity IN {_in(SEVERITY_LEVELS)}),
    severity_reason  TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'new' CHECK (status IN {_in(INCIDENT_STATUSES)}),
    resolution       TEXT CHECK (resolution IS NULL OR resolution IN {_in(RESOLUTIONS)}),
    version          INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    assignee         TEXT
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
{INDEXES_V2_DDL}"""

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
    f"PRAGMA user_version = {SCHEMA_VERSION}",
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

    Четыре случая по `PRAGMA user_version` и наличию таблиц:
    - пустой файл → сразу схема 2;
    - схема 002 (версия 0 или 1, таблицы есть) → миграция `MIGRATION_V2`;
    - схема 2 → только IF NOT EXISTS (ничего не меняется);
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
    """Схема 002 → 2 одной транзакцией (data-model «Миграция 0 → 2»)."""
    with transaction(conn):
        for step in MIGRATION_V2:
            conn.execute(step)


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
            "finished_at, n_flows, n_alerts, n_incidents, summary, warnings) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            ),
        )
        _insert_many(
            conn,
            "incidents",
            INCIDENT_COLUMNS,
            (
                {
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
            ({**a, "run_id": run_id, "alert_id": f"{run_id}/{a['flow_uid']}"} for a in alerts),
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
    return d


def list_runs(conn: sqlite3.Connection) -> list[dict]:
    """Прогоны, новые сверху, с числом инцидентов по статусам."""
    runs = [
        _run_row(r)
        for r in conn.execute("SELECT * FROM runs ORDER BY started_at DESC, run_id DESC")
    ]
    counts = conn.execute(
        "SELECT run_id, status, COUNT(*) AS n FROM incidents GROUP BY run_id, status"
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
        "SELECT i.*, a.action_id AS a_action_id, a.action_type AS a_action_type, "
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
    row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
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
    conn: sqlite3.Connection, incident_id: str, limit: int = 50, offset: int = 0
) -> tuple[int, list[dict]]:
    """Алерты инцидента постранично, по времени начала потока."""
    exists = conn.execute(
        "SELECT 1 FROM incidents WHERE incident_id = ?", (incident_id,)
    ).fetchone()
    if exists is None:
        raise NotFound(f"инцидент {incident_id} не найден")
    total = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE incident_id = ?", (incident_id,)
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT * FROM alerts WHERE incident_id = ? ORDER BY first_seen_ms, flow_uid "
        "LIMIT ? OFFSET ?",
        (incident_id, limit, offset),
    ).fetchall()
    return total, [dict(r) for r in rows]


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
    rows = conn.execute(
        "SELECT MAX(0, MIN((first_seen_ms - ?) / ?, ?)) AS b, COUNT(*) AS n FROM alerts "
        "WHERE incident_id = ? GROUP BY b",
        (start, bin_ms, n_bins - 1, incident_id),
    )
    for r in rows:
        counts[int(r["b"])] += r["n"]
    return {"start_ms": start, "end_ms": end, "bin_ms": bin_ms, "counts": counts}


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
                f"SELECT {column}, COUNT(*) FROM incidents WHERE run_id = ? GROUP BY {column}",
                (run_id,),
            )
        }

    by_status, by_severity = grouped("status"), grouped("severity")
    by_class = dict(sorted(grouped("attack_class").items(), key=lambda kv: (-kv[1], kv[0])))
    actions_pending = conn.execute(
        "SELECT COUNT(*) FROM actions a JOIN incidents i ON i.incident_id = a.incident_id "
        "WHERE i.run_id = ? AND a.state = 'proposed'",
        (run_id,),
    ).fetchone()[0]
    unassigned = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE run_id = ? AND assignee IS NULL "
        "AND status != 'closed'",
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
        dict(r)
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
