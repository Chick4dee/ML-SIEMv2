"""HTTP API аналитика v1 (contracts/api.md, research R12).

Тонкий слой над `soc.store`: вся логика (переходы, версии, аудит) — в хранилище, здесь только
разбор запроса, проверка заголовка `X-Analyst` и перевод исключений хранилища в ответы:

    NotFound → 404 not_found, InvalidTransition → 409 invalid_transition,
    Conflict → 409 conflict, BadRequest → 400 bad_request, ошибки валидации → 422 bad_request.

Все ошибки — JSON `{"error": "<код>", "message": "<по-русски>"}`.

Слушает только 127.0.0.1 (это проверяет `mlsiem soc serve`), аутентификации нет — имя
аналитика в `X-Analyst` нужно для журнала, а не для защиты. Заголовки HTTP передаются в
latin-1, поэтому имя пишется латиницей (например, `vlad`).

Аудит-журнал только читается: методов изменения для `/audit` нет вовсе (405).

Фича 003 только добавляет: параметры списка (`src_ip`, `assignee`, `action_state`, `flagged`,
`sort`, `dir`), поля `assignee` и `flags`, метод `POST /incidents/{id}/assign`
(contracts/api-v1-additions.md). CORS-заголовков по-прежнему нет — это часть защиты: запрос
с `X-Analyst` с чужого сайта браузер без разрешающего preflight не отправит.

Фича 004 — тоже только добавления (FR-018): у алерта атакующая сторона и ответы экспертов,
у карточки инцидента сводка «кто поднял алерты», у прогона — модель прогона. Для прогонов
до ансамбля новые поля — null (FR-020); берутся они из SQLite, а не из parquet-файлов.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from mlsiem.soc import flags as soc_flags
from mlsiem.soc import store
from mlsiem.soc.config import SEVERITY_LEVELS, SocConfig

PREFIX = "/api/v1"
MAX_LIMIT = 500


# ---------------------------------------------------------------- модели


class ActionShort(BaseModel):
    action_id: str
    action_type: str
    target: str | None
    state: str


class ActionFull(ActionShort):
    incident_id: str
    rule_id: str
    rule_text: str
    decided_by: str | None
    decided_at: str | None
    comment: str | None
    simulation: dict[str, Any] | None
    version: int


class HistoryEntry(BaseModel):
    at: str
    analyst: str
    field: str
    old: str | None
    new: str | None
    comment: str | None


class SourceFlag(BaseModel):
    """Метка подозрительного источника (фича 003) — подсказка, а не решение."""

    kind: str
    network_name: str | None
    role: str | None
    related_incidents: list[str]
    explanation: str


class IncidentItem(BaseModel):
    incident_id: str
    run_id: str
    src_ip: str
    attack_class: str
    targets: list[str]
    first_seen_ms: int
    last_seen_ms: int
    n_alerts: int
    severity: str
    status: str
    resolution: str | None
    action: ActionShort | None
    version: int
    # фича 003 — только добавления: клиенты 002 эти поля просто не читают
    assignee: str | None = None
    flags: list[SourceFlag] = []
    # фича 005: слияние и «новые алерты после решения» (у пакетных — null и 0)
    merged_into: str | None = None
    alerts_after_decision: int = 0
    first_after_decision_ms: int | None = None


class ExpertsCombination(BaseModel):
    experts: list[str]
    n_alerts: int


class ExpertsSummary(BaseModel):
    """Кто поднял алерты инцидента (фича 004): по экспертам и сочетаниям."""

    available: bool
    by_expert: dict[str, int] = {}
    combinations: list[ExpertsCombination] = []
    note: str


class IncidentCard(IncidentItem):
    severity_reason: str
    max_score: float
    mean_score: float
    created_at: str
    updated_at: str
    action: ActionFull | None
    history: list[HistoryEntry]
    # фича 004
    experts_summary: ExpertsSummary | None = None


class IncidentPage(BaseModel):
    total: int
    items: list[IncidentItem]


class Alert(BaseModel):
    alert_id: str
    run_id: str
    incident_id: str
    flow_uid: str
    capture_id: str
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: int | None
    first_seen_ms: int
    last_seen_ms: int
    predicted_class: str
    attack_score: float
    # фича 004 — только добавления; у прогонов до ансамбля experts/fired_experts/explanation = null
    attacker_ip: str | None = None
    victim_ip: str | None = None
    reversed: bool = False
    experts: dict[str, dict[str, Any]] | None = None
    fired_experts: list[str] | None = None
    explanation: str | None = None


class AlertPage(BaseModel):
    total: int
    items: list[Alert]


class AuditEntry(BaseModel):
    entry_id: int
    at: str
    actor: str
    event: str
    run_id: str | None
    incident_id: str | None
    action_id: str | None
    details: dict[str, Any]


class AuditPage(BaseModel):
    total: int
    items: list[AuditEntry]


class Run(BaseModel):
    run_id: str
    source: str
    input_hash: str
    detector_version: str
    limit: int | None
    started_at: str
    finished_at: str
    n_flows: int
    n_alerts: int
    n_incidents: int
    summary: dict[str, Any]
    warnings: list[str]
    incidents_by_status: dict[str, int]
    # фича 004: модель прогона (у старых — детектор с версией из detector_version)
    model: dict[str, Any] | None = None
    # фича 005: пакетный прогон или онлайн-сеанс (у пакетных — batch/completed/null)
    mode: str = "batch"
    status: str = "completed"
    source_id: str | None = None
    last_activity_at: str | None = None


class RunList(BaseModel):
    total: int
    items: list[Run]


class Health(BaseModel):
    status: str
    detector_version: str | None
    db: str


class StreamBroker(BaseModel):
    reachable: bool | None
    checked_at: str | None
    error: str | None = None


class StreamConsumer(BaseModel):
    alive: bool
    holder: str | None
    renewed_at: str | None


class StreamSession(BaseModel):
    run_id: str
    status: str
    source_id: str | None
    processed: int
    lag_messages: int | None
    lag_seconds: float | None
    latency_p50_ms: float | None
    latency_p95_ms: float | None
    rejected: int
    late: int
    rate_per_s: float | None
    last_activity_at: str | None


class StreamStatus(BaseModel):
    """Состояние потока (фича 005, contracts/api-ui-additions.md) — только чтение."""

    broker: StreamBroker
    consumer: StreamConsumer
    sessions: list[StreamSession]


class StatusChange(BaseModel):
    status: Literal["in_progress", "closed"]
    resolution: Literal["confirmed", "false_positive"] | None = None
    comment: str | None = None
    expected_version: int = Field(ge=1)


class AssignChange(BaseModel):
    assignee: str | None = None
    comment: str | None = None
    expected_version: int = Field(ge=1)


class ActionDecision(BaseModel):
    comment: str | None = None
    expected_version: int = Field(ge=1)


# ---------------------------------------------------------------- ошибки


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": code, "message": message})


STATUS_BY_CODE = {"not_found": 404, "invalid_transition": 409, "conflict": 409, "bad_request": 400}


def _validation_message(exc: RequestValidationError) -> str:
    parts = []
    for err in exc.errors():
        where = ".".join(str(x) for x in err.get("loc", ()) if x not in ("body", "query", "path"))
        parts.append(f"{where or 'запрос'}: {err.get('msg')}")
    return "неверные параметры запроса — " + "; ".join(parts)


# ---------------------------------------------------------------- приложение


def _csv(value: str | None, allowed: tuple[str, ...], name: str) -> list[str] | None:
    """`a,b` → ['a', 'b'] с проверкой допустимых значений."""
    if value is None or not value.strip():
        return None
    items = [v.strip() for v in value.split(",") if v.strip()]
    bad = [v for v in items if v not in allowed]
    if bad:
        raise store.BadRequest(
            f"параметр {name}: недопустимые значения {bad}; допустимы {list(allowed)}"
        )
    return items


# Проверка брокера из API (фича 005): короткий тайм-аут и кеш — страница и API не должны
# висеть на выключенной машине стенда
BROKER_CHECK_TIMEOUT_S = 2
BROKER_CHECK_CACHE_S = 10


def _default_stream_cfg():
    """configs/stream.yaml, если он есть и читается; иначе поток в API не настроен."""
    from mlsiem.data.config import ConfigError
    from mlsiem.stream.config import DEFAULT_STREAM_CONFIG, load_stream_config

    try:
        return load_stream_config(DEFAULT_STREAM_CONFIG)
    except ConfigError:
        return None


def create_app(
    cfg: SocConfig,
    *,
    detector_dir: Path = Path("models/detector"),
    stream_cfg=None,
) -> FastAPI:
    app = FastAPI(
        title="ML-SIEM v2 — API аналитика",
        version="1",
        description="Инциденты, предложения плейбуков (только симуляция) и аудит-журнал.",
    )
    stream_cfg = stream_cfg if stream_cfg is not None else _default_stream_cfg()
    conn0 = store.connect(cfg.db)
    # Миграция схемы (если база от 002) — здесь, до первого запроса; флаг нужен CLI для
    # сообщения «схема базы обновлена»
    app.state.migrated = store.init_db(conn0)
    conn0.close()

    @app.exception_handler(store.StoreError)
    async def _store_error(request: Request, exc: store.StoreError):
        return _error(STATUS_BY_CODE[exc.code], exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        return _error(422, "bad_request", _validation_message(exc))

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        # Вне /api/v1 — страницы консоли: там «не найдено» должно быть страницей, а не JSON
        page_error = getattr(app.state, "page_error", None)
        if page_error is not None and not request.url.path.startswith(PREFIX):
            return page_error(request, exc)
        if exc.status_code == 404:
            return _error(404, "not_found", "такого адреса в API нет")
        if exc.status_code == 405:
            return _error(405, "bad_request", "этот метод для адреса не поддерживается")
        return _error(exc.status_code, "bad_request", str(exc.detail))

    def db() -> Iterator:
        # Соединение на запрос: SQLite в WAL дешёво открывается, а общих курсоров нет
        conn = store.connect(cfg.db)
        try:
            yield conn
        finally:
            conn.close()

    def analyst(x_analyst: str | None = Header(default=None, alias="X-Analyst")) -> str:
        if x_analyst is None or not x_analyst.strip():
            raise store.BadRequest(
                "нужен заголовок X-Analyst с именем аналитика: изменения без автора запрещены"
            )
        return x_analyst.strip()

    # ---------------- инциденты

    def with_flags(conn, items: list[dict]) -> list[dict]:
        """Добавляет к инцидентам метки подозрительного источника (считаются по прогону)."""
        by_run: dict[str, dict] = {}
        for item in items:
            run_flags = by_run.setdefault(
                item["run_id"], soc_flags.run_flags(conn, item["run_id"], cfg.networks)
            )
            item["flags"] = [f.as_dict() for f in run_flags.get(item["incident_id"], [])]
        return items

    def flagged_ids(conn, run_id: str | None) -> list[str]:
        runs = [run_id] if run_id else [r["run_id"] for r in store.list_runs(conn)]
        return [i for r in runs for i in soc_flags.run_flags(conn, r, cfg.networks)]

    @app.get(PREFIX + "/incidents", response_model=IncidentPage)
    def list_incidents(
        status: str | None = None,
        severity: str | None = None,
        attack_class: str | None = None,
        run_id: str | None = None,
        from_ms: int | None = None,
        to_ms: int | None = None,
        src_ip: str | None = None,
        assignee: str | None = None,
        action_state: str | None = None,
        flagged: Literal["only", "hide"] | None = None,
        after_decision: Literal["only"] | None = None,
        show_merged: bool = False,
        sort: Literal["severity", "first_seen", "last_seen", "n_alerts"] | None = None,
        dir: Literal["asc", "desc"] | None = None,
        limit: int = Query(50, ge=1, le=MAX_LIMIT),
        offset: int = Query(0, ge=0),
        conn=Depends(db),
    ):
        filters = {
            "status": _csv(status, store.INCIDENT_STATUSES, "status"),
            "severity": _csv(severity, SEVERITY_LEVELS, "severity"),
            "attack_class": attack_class,
            "run_id": run_id,
            "from_ms": from_ms,
            "to_ms": to_ms,
            "src_ip": src_ip,
            "assignee": assignee,
            "action_state": _csv(action_state, store.ACTION_STATES, "action_state"),
            "after_decision": after_decision,
            "show_merged": show_merged,
        }
        if flagged == "only":
            filters["incident_ids"] = flagged_ids(conn, run_id)
        elif flagged == "hide":
            filters["exclude_ids"] = flagged_ids(conn, run_id)
        # По контракту: без sort — порядок 002; dir по умолчанию desc для серьёзности
        # (сначала критические) и asc для времени и числа алертов
        direction = dir or ("desc" if sort == "severity" else "asc")
        total, items = store.list_incidents(
            conn, filters, limit, offset, sort=sort, direction=direction
        )
        return {"total": total, "items": with_flags(conn, items)}

    def card(conn, inc: dict) -> dict:
        item = with_flags(conn, [inc])[0]
        item["experts_summary"] = store.experts_summary(conn, item["incident_id"])
        return item

    @app.get(PREFIX + "/incidents/{incident_id}", response_model=IncidentCard)
    def get_incident(incident_id: str, conn=Depends(db)):
        return card(conn, store.get_incident(conn, incident_id))

    @app.post(PREFIX + "/incidents/{incident_id}/assign", response_model=IncidentCard)
    def assign(incident_id: str, body: AssignChange, who: str = Depends(analyst), conn=Depends(db)):
        inc = store.assign(
            conn, incident_id, who, body.assignee, body.expected_version, body.comment
        )
        return card(conn, inc)

    @app.get(PREFIX + "/incidents/{incident_id}/alerts", response_model=AlertPage)
    def incident_alerts(
        incident_id: str,
        limit: int = Query(50, ge=1, le=MAX_LIMIT),
        offset: int = Query(0, ge=0),
        conn=Depends(db),
    ):
        total, items = store.list_alerts(conn, incident_id, limit, offset)
        return {"total": total, "items": items}

    @app.post(PREFIX + "/incidents/{incident_id}/status", response_model=IncidentCard)
    def change_status(
        incident_id: str, body: StatusChange, who: str = Depends(analyst), conn=Depends(db)
    ):
        inc = store.change_status(
            conn,
            incident_id,
            who,
            body.status,
            body.resolution,
            body.comment,
            body.expected_version,
        )
        return card(conn, inc)

    # ---------------- действия

    @app.post(PREFIX + "/actions/{action_id}/confirm", response_model=ActionFull)
    def confirm(
        action_id: str, body: ActionDecision, who: str = Depends(analyst), conn=Depends(db)
    ):
        return store.confirm_action(conn, action_id, who, body.expected_version, body.comment)

    @app.post(PREFIX + "/actions/{action_id}/reject", response_model=ActionFull)
    def reject(action_id: str, body: ActionDecision, who: str = Depends(analyst), conn=Depends(db)):
        return store.reject_action(conn, action_id, who, body.expected_version, body.comment)

    # ---------------- аудит, прогоны, служебное

    @app.get(PREFIX + "/audit", response_model=AuditPage)
    def audit(
        incident_id: str | None = None,
        actor: str | None = None,
        event: str | None = None,
        limit: int = Query(50, ge=1, le=MAX_LIMIT),
        offset: int = Query(0, ge=0),
        conn=Depends(db),
    ):
        if event is not None and event not in store.AUDIT_EVENTS:
            raise store.BadRequest(
                f"неизвестное событие {event!r}; допустимы {list(store.AUDIT_EVENTS)}"
            )
        filters = {"incident_id": incident_id, "actor": actor, "event": event}
        total, items = store.list_audit(conn, filters, limit, offset)
        return {"total": total, "items": items}

    @app.get(PREFIX + "/runs", response_model=RunList)
    def runs(conn=Depends(db)):
        items = store.list_runs(conn)
        return {"total": len(items), "items": items}

    broker_cache: dict[str, Any] = {"at": None, "state": None}

    def broker_state() -> dict | None:
        """Состояние брокера с тайм-аутом 2 с и кешем 10 с (FR-022)."""
        import dataclasses
        import time

        from mlsiem.stream import broker as broker_mod
        from mlsiem.stream.stats import check_broker_state

        if stream_cfg is None:
            return None
        now = time.monotonic()
        if broker_cache["at"] is not None and now - broker_cache["at"] < BROKER_CHECK_CACHE_S:
            return broker_cache["state"]
        quick = dataclasses.replace(
            stream_cfg,
            broker=dataclasses.replace(stream_cfg.broker, connect_timeout_s=BROKER_CHECK_TIMEOUT_S),
        )
        state = check_broker_state(quick, lambda: broker_mod.make_broker(quick, "api"))
        broker_cache.update(at=now, state=state)
        return state

    @app.get(PREFIX + "/stream/status", response_model=StreamStatus)
    def stream_status(conn=Depends(db)):
        from mlsiem.stream.stats import status_report

        if stream_cfg is None:
            raise store.NotFound(
                "поток не настроен: нет configs/stream.yaml (фича 005) — показателей нет"
            )
        state = broker_state()
        return status_report(conn, stream_cfg, broker_state=state)

    @app.get(PREFIX + "/health", response_model=Health)
    def health():
        version = None
        # Каталог модели — детектор 002 или ансамбль (фича 004): версия из той карточки, что есть
        for name, key in (
            ("ensemble_card.json", "ensemble_version"),
            ("model_card.json", "detector_version"),
        ):
            card = Path(detector_dir) / name
            if card.exists():
                try:
                    version = json.loads(card.read_text(encoding="utf-8")).get(key)
                except (json.JSONDecodeError, OSError):
                    version = None
                break
        return {"status": "ok", "detector_version": version, "db": Path(cfg.db).as_posix()}

    # Консоль аналитика (фича 003) — в том же процессе и на том же порту (FR-031). Импорт
    # внутри функции: ядро API ничего не знает о HTML, связь только здесь, в одну сторону
    from mlsiem.ui.routes import install

    install(app, cfg, Path(detector_dir), stream_cfg=stream_cfg)
    return app
