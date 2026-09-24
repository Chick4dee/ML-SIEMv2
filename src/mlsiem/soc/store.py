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
import json
import sqlite3
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
)
SYSTEM_ACTOR = "system"


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


# ---------------------------------------------------------------- схема


def _in(values: tuple[str, ...]) -> str:
    return "(" + ", ".join(f"'{v}'" for v in values) + ")"


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

CREATE TABLE IF NOT EXISTS audit_log (
    entry_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at               TEXT NOT NULL,
    actor            TEXT NOT NULL,
    event            TEXT NOT NULL CHECK (event IN {_in(AUDIT_EVENTS)}),
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
"""


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


def init_db(conn: sqlite3.Connection) -> None:
    """Создаёт таблицы, триггеры и индексы. Повторный вызов ничего не ломает (IF NOT EXISTS)."""
    conn.executescript(DDL)


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


def _require_analyst(analyst: str | None) -> str:
    if analyst is None or not str(analyst).strip():
        raise BadRequest("не указан аналитик: изменения без автора запрещены (заголовок X-Analyst)")
    return str(analyst).strip()


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
        run_id = conn.execute(
            "SELECT run_id FROM incidents WHERE incident_id = ?", (action["incident_id"],)
        ).fetchone()["run_id"]
        append_audit(
            conn,
            analyst,
            event,
            run_id=run_id,
            incident_id=action["incident_id"],
            action_id=action_id,
            details={
                "action_type": action["action_type"],
                "target": action["target"],
                "rule_id": action["rule_id"],
                "comment": comment,
                "simulation": simulation,
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
            },
            at=at,
        )
    return get_incident(conn, incident_id)


# ---------------------------------------------------------------- чтение

# Серьёзность по убыванию: critical первым
SEVERITY_RANK_SQL = (
    "CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
)


def _incident_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["targets"] = json.loads(d["targets"])
    return d


def _incident_filters(filters: dict) -> tuple[str, list]:
    where: list[str] = []
    params: list[Any] = []
    for key in ("status", "severity"):
        values = filters.get(key)
        if values:
            where.append(f"i.{key} IN ({', '.join('?' for _ in values)})")
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
    return (" WHERE " + " AND ".join(where)) if where else "", params


def list_incidents(
    conn: sqlite3.Connection, filters: dict, limit: int = 50, offset: int = 0
) -> tuple[int, list[dict]]:
    """(всего подходящих, страница). Порядок: серьёзность ↓, first_seen_ms ↑, incident_id."""
    where, params = _incident_filters(filters)
    total = conn.execute(f"SELECT COUNT(*) FROM incidents i{where}", params).fetchone()[0]
    rows = conn.execute(
        "SELECT i.*, a.action_id AS a_action_id, a.action_type AS a_action_type, "
        "a.target AS a_target, a.state AS a_state "
        f"FROM incidents i LEFT JOIN actions a ON a.incident_id = i.incident_id{where} "
        f"ORDER BY {SEVERITY_RANK_SQL}, i.first_seen_ms, i.incident_id LIMIT ? OFFSET ?",
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
    conn: sqlite3.Connection, filters: dict, limit: int = 50, offset: int = 0
) -> tuple[int, list[dict]]:
    """Аудит-журнал с фильтрами, по порядку записи."""
    where: list[str] = []
    params: list[Any] = []
    for key in ("incident_id", "actor", "event", "run_id", "action_id"):
        if filters.get(key):
            where.append(f"{key} = ?")
            params.append(filters[key])
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM audit_log{clause}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM audit_log{clause} ORDER BY entry_id LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["details"] = json.loads(d["details"])
        items.append(d)
    return total, items
