"""Страницы, фрагменты и формы консоли (contracts/ui.md).

Каждый обработчик — тонкий: собрать данные (`views`), отрисовать шаблон, а для форм — вызвать
функцию `soc.store`. Правила решений (переходы, версии, аудит) здесь не повторяются: ошибка
`store` приходит исключением с готовым русским текстом, и консоль показывает его рядом
с формой (FR-003, FR-017).

Одна страница — два ответа (research R2): обычный запрос получает полную страницу, запрос
htmx (`HX-Request` без `HX-Boosted`) — только изменившийся фрагмент. Поэтому всё работает и
без JS (ссылки и формы — настоящие), а с JS — без перезагрузки страницы.

Изменяющие запросы (POST) проходят `security.check_request` (источник + токен), требуют имени
аналитика и `expected_version`. Ответ htmx — перерисованный блок решений `#decisions` плюс
событие `incident-changed` (по нему карточка сама обновит хронологию и историю). Без htmx —
303 на карточку, как принято после отправки формы.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from mlsiem.soc import store
from mlsiem.soc.config import SEVERITY_LEVELS, SocConfig
from mlsiem.ui import labels, security, views
from mlsiem.ui.security import CSRF_FIELD, CsrfGuard, CsrfRejected

HERE = Path(__file__).parent
STATUS_BY_CODE = {"not_found": 404, "invalid_transition": 409, "conflict": 409, "bad_request": 400}

# Настройки htmx (читаются из <meta name="htmx-config">). Главное:
# - responseHandling: htmx 2 по умолчанию НЕ вставляет ответы 4xx — а нам нужно показать
#   сообщение об ошибке рядом с формой; 204 («ничего не изменилось») не трогает страницу;
# - includeIndicatorStyles: false — иначе htmx вставит <style>, который запрещает наша CSP;
# - allowEval / allowScriptTags: false — никакого исполнения кода из разметки.
HTMX_CONFIG = {
    "responseHandling": [
        {"code": "204", "swap": False},
        {"code": "[23]..", "swap": True},
        {"code": "[45]..", "swap": True, "error": True},
    ],
    "includeIndicatorStyles": False,
    "allowEval": False,
    "allowScriptTags": False,
    "historyCacheSize": 0,
    "refreshOnHistoryMiss": True,
}


def is_htmx(request: Request) -> bool:
    return (
        request.headers.get("hx-request") == "true" and request.headers.get("hx-boosted") != "true"
    )


def _safe_next(value: str | None) -> str:
    """Куда вернуться после «представиться»: только относительный путь внутри консоли.

    `//evil.example` и `/\\evil.example` браузер понимает как адрес чужого сайта — отсекаем,
    иначе форма имени превратилась бы в открытый редирект.
    """
    if not value or not value.startswith("/") or value.startswith(("//", "/\\")):
        return "/"
    return value


def static_version() -> str:
    """Короткий хеш содержимого статики — добавляется к адресам как ?v=…

    Браузер кеширует CSS и JS; без метки версии после обновления консоли аналитик видел бы
    новую разметку со старыми стилями. Хеш меняется ровно тогда, когда меняются файлы.
    """
    h = hashlib.sha256()
    for path in sorted((HERE / "static").rglob("*")):
        if path.is_file():
            h.update(path.read_bytes())
    return h.hexdigest()[:10]


def install(app: FastAPI, cfg: SocConfig, detector_dir: Path) -> None:
    """Подключает консоль к приложению API 002: статика, заголовки, страницы, ошибки."""
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals["static_v"] = static_version()
    labels.register(templates.env)
    guard = CsrfGuard()
    app.state.csrf = guard
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        if security.needs_security_headers(request.url.path):
            for k, v in security.SECURITY_HEADERS.items():
                response.headers.setdefault(k, v)
            if not request.url.path.startswith("/static/"):
                # Страницы и фрагменты не кешируем: иначе «назад» показал бы старый статус
                response.headers.setdefault("Cache-Control", "no-store")
        return response

    def db() -> Iterator[sqlite3.Connection]:
        conn = store.connect(cfg.db)
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------ отрисовка

    def render(
        request: Request,
        conn: sqlite3.Connection,
        page: str,
        ctx: dict[str, Any],
        *,
        fragment: str | None = None,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> HTMLResponse:
        """Полная страница или только фрагмент — по заголовкам htmx (research R2)."""
        session, new_session = guard.ensure_session(request)
        run_id = ctx.get("run_id")
        latest = store.latest_run_id(conn)
        full = {
            "analyst": security.read_analyst(request),
            "csrf_token": guard.issue(session),
            "refresh": cfg.ui.refresh_seconds,
            "htmx_config": HTMX_CONFIG,
            "runs": store.list_runs(conn),
            "run_id": run_id,
            "run_action": "/incidents",
            "new_run": store.get_run(conn, latest) if run_id and latest != run_id else None,
            "severities": SEVERITY_LEVELS,
            "statuses": store.INCIDENT_STATUSES,
            "action_states": store.ACTION_STATES,
            "resolutions": store.RESOLUTIONS,
            "transitions": store.TRANSITIONS,
            "no_assignee": store.NO_ASSIGNEE,
            "next_url": request.url.path + (f"?{request.url.query}" if request.url.query else ""),
            **ctx,
        }
        name = fragment if fragment and is_htmx(request) else page
        response = templates.TemplateResponse(
            request, name, full, status_code=status, headers=headers
        )
        if new_session:
            guard.set_session(response, session)
        return response

    def fragment_page(request, conn, fragment: str, ctx: dict, **kw) -> HTMLResponse:
        """Фрагмент для htmx; без htmx — тот же фрагмент в обёртке страницы (FR-032)."""
        return render(
            request,
            conn,
            "fragment_page.html",
            {**ctx, "fragment_name": fragment},
            fragment=fragment,
            **kw,
        )

    def not_found(request, conn, message: str) -> HTMLResponse:
        return render(request, conn, "not_found.html", {"message": message}, status=404)

    def page_error(request: Request, exc) -> HTMLResponse:
        """404/405 для адресов вне /api/v1 — HTML-страница, а не JSON API."""
        conn = store.connect(cfg.db)
        try:
            if exc.status_code == 404:
                return not_found(request, conn, "такой страницы в консоли нет")
            return render(
                request,
                conn,
                "error.html",
                {"message": "этот метод для адреса не поддерживается"},
                status=exc.status_code,
            )
        finally:
            conn.close()

    app.state.page_error = page_error

    def etag_matches(request: Request, etag: str) -> bool:
        return request.headers.get("if-none-match") == etag

    def run_or_latest(conn, request) -> tuple[str | None, list[str]]:
        runs = views.run_ids(conn)
        run = request.query_params.get("run")
        if run and run in runs:
            return run, []
        warnings = [f"прогон {run!r} не найден — показан последний"] if run else []
        return (runs[0] if runs else None), warnings

    router = APIRouter(include_in_schema=False)

    # ------------------------------------------------------------ панель (US4)

    @router.get("/")
    def dashboard_page(request: Request, conn=Depends(db)):
        run_id, warnings = run_or_latest(conn, request)
        ctx: dict[str, Any] = {"run_id": run_id, "warnings": warnings, "run_action": "/"}
        if run_id:
            ctx["d"] = views.dashboard(conn, cfg, run_id)
            ctx["recent"] = store.recent_alerts(conn, run_id, cfg.ui.recent_alerts)
            ctx["recent_etag"] = ctx["d"]["etag"]
        return render(request, conn, "dashboard.html", ctx)

    @router.get("/fragments/dashboard")
    def dashboard_fragment(request: Request, run: str, conn=Depends(db)):
        try:
            d = views.dashboard(conn, cfg, run)
        except store.NotFound as exc:
            return not_found(request, conn, exc.message)
        if etag_matches(request, d["etag"]):
            return Response(status_code=204)
        return fragment_page(
            request,
            conn,
            "fragments/_dashboard_counters.html",
            {"run_id": run, "d": d},
            headers={"ETag": d["etag"]},
        )

    @router.get("/fragments/recent-alerts")
    def recent_fragment(request: Request, run: str, conn=Depends(db)):
        etag = '"' + store.list_state(conn, run) + '"'
        if etag_matches(request, etag):
            return Response(status_code=204)
        ctx = {
            "run_id": run,
            "recent": store.recent_alerts(conn, run, cfg.ui.recent_alerts),
            "recent_etag": etag,
        }
        return fragment_page(
            request, conn, "fragments/_recent_alerts.html", ctx, headers={"ETag": etag}
        )

    @router.get("/fragments/runs-banner")
    def runs_banner(request: Request, run: str, conn=Depends(db)):
        # Выбранный прогон зашит в адрес опроса: новый прогон только объявляется баннером,
        # а переключается аналитик сам (FR-023)
        return fragment_page(request, conn, "fragments/_runs_banner.html", {"run_id": run})

    # ------------------------------------------------------------ список и карточка (US1)

    @router.get("/incidents")
    def incidents_page(request: Request, conn=Depends(db)):
        view, warnings = views.IncidentListView.parse(request.query_params, views.run_ids(conn))
        ctx: dict[str, Any] = {"run_id": view.run, "view": view, "warnings": warnings}
        if view.run:
            data = views.list_page(conn, cfg, view)
            if is_htmx(request) and etag_matches(request, data["etag"]):
                return Response(status_code=204)
            ctx.update(data)
            ctx["assignees"] = store.run_assignees(conn, view.run)
            headers = {"ETag": data["etag"]}
        else:
            headers = None
        return render(
            request,
            conn,
            "incidents.html",
            ctx,
            fragment="fragments/_incident_table.html" if view.run else None,
            headers=headers,
        )

    def card_ctx(conn, incident_id: str, alerts_page: int = 1) -> dict:
        card = views.incident_card(conn, cfg, incident_id, alerts_page)
        return {**card, "run_id": card["inc"]["run_id"], "errors": {}, "values": {}}

    @router.get("/incidents/{incident_id}")
    def incident_page(request: Request, incident_id: str, conn=Depends(db)):
        page = request.query_params.get("alerts_page", "1")
        try:
            ctx = card_ctx(conn, incident_id, int(page) if page.isdigit() else 1)
        except store.NotFound as exc:
            return not_found(request, conn, exc.message)
        return render(request, conn, "incident.html", ctx)

    @router.get("/fragments/incidents/{incident_id}/alerts")
    def alerts_fragment(request: Request, incident_id: str, page: int = 1, conn=Depends(db)):
        try:
            inc = store.get_incident(conn, incident_id)
            alerts = views.alerts_page_data(conn, cfg, incident_id, page)
        except store.NotFound as exc:
            return not_found(request, conn, exc.message)
        ctx = {"inc": inc, "alerts": alerts, "run_id": inc["run_id"]}
        return fragment_page(request, conn, "fragments/_alerts.html", ctx)

    # flow_uid содержит «/» ("unsw_17-2-2015_23/30013"), поэтому конвертер path
    @router.get("/fragments/alerts/{run_id}/{flow_uid:path}/probs")
    def probs_fragment(request: Request, run_id: str, flow_uid: str, conn=Depends(db)):
        # Прогон берём из базы, а не из адреса как есть: путь к файлу вердиктов строится
        # только для существующего прогона — никакого «../» в путь не попадёт
        try:
            run = store.get_run(conn, run_id)
        except store.NotFound as exc:
            return not_found(request, conn, exc.message)
        probs = views.alert_probs(
            cfg, run, flow_uid, detector_dir, alert=store.get_alert(conn, run_id, flow_uid)
        )
        return fragment_page(request, conn, "fragments/_probs.html", {"p": probs, "run_id": run_id})

    @router.get("/fragments/incidents/{incident_id}/timeline")
    def timeline_fragment(request: Request, incident_id: str, conn=Depends(db)):
        try:
            ctx = card_ctx(conn, incident_id)
        except store.NotFound as exc:
            return not_found(request, conn, exc.message)
        return fragment_page(request, conn, "fragments/_timeline.html", ctx)

    @router.get("/fragments/incidents/{incident_id}/stamp")
    def stamp_fragment(
        request: Request, incident_id: str, v: str = "", av: str = "", conn=Depends(db)
    ):
        try:
            version, action_version = store.incident_versions(conn, incident_id)
        except store.NotFound as exc:
            return not_found(request, conn, exc.message)
        changed = v != str(version) or av != ("" if action_version is None else str(action_version))
        ctx = {"stamp": {"incident_id": incident_id, "v": v, "av": av, "changed": changed}}
        return fragment_page(request, conn, "fragments/_stamp.html", ctx)

    # ------------------------------------------------------------ журнал (US5)

    @router.get("/audit")
    def audit_page(request: Request, conn=Depends(db)):
        view = views.AuditView.parse(request.query_params)
        ctx = {**views.audit_page(conn, cfg, view), "run_id": view.run}
        ctx["details"] = views.audit_details
        return render(request, conn, "audit.html", ctx, fragment="fragments/_audit_table.html")

    # ------------------------------------------------------------ имя аналитика

    @router.get("/analyst")
    def analyst_page(request: Request, conn=Depends(db)):
        ctx = {"next": _safe_next(request.query_params.get("next")), "error": None}
        return render(request, conn, "analyst.html", ctx)

    @router.post("/analyst")
    async def analyst_set(request: Request, conn=Depends(db)):
        try:
            await security.check_request(request, guard)
        except CsrfRejected as exc:
            ctx = {"next": "/", "error": exc.message, "name": exc.form.get("name", "")}
            return render(request, conn, "analyst.html", ctx, status=403)
        form = await request.form()
        name, target = str(form.get("name", "")), _safe_next(str(form.get("next", "")))
        try:
            clean = store.clean_name(name)
        except store.BadRequest as exc:
            ctx = {"next": target, "error": exc.message, "name": name}
            return render(request, conn, "analyst.html", ctx, status=400)
        response = RedirectResponse(target, status_code=303)
        security.set_analyst(response, clean)
        return response

    # ------------------------------------------------------------ решения (US2)

    def decisions(
        request: Request,
        conn: sqlite3.Connection,
        incident_id: str,
        *,
        status: int = 200,
        errors: dict | None = None,
        values: dict | None = None,
        question: dict | None = None,
        headers: dict | None = None,
    ) -> HTMLResponse:
        """Блок решений карточки (htmx) или вся карточка (без JS) — с ошибками и вопросами."""
        ctx = card_ctx(conn, incident_id)
        ctx.update(errors=errors or {}, values=values or {}, question=question)
        return render(
            request,
            conn,
            "incident.html",
            ctx,
            fragment="fragments/_decisions.html",
            status=status,
            headers=headers,
        )

    async def decide(
        request: Request,
        conn: sqlite3.Connection,
        incident_id: str,
        section: str,
        apply,
        *,
        ask_action: dict | None = None,
        check_assignee: bool = True,
    ):
        """Общий путь всех решений: защита → имя → вопросы → store → ответ."""
        try:
            store.get_incident(conn, incident_id)
        except store.NotFound as exc:
            return not_found(request, conn, exc.message)
        try:
            await security.check_request(request, guard)
        except CsrfRejected as exc:
            return decisions(
                request,
                conn,
                incident_id,
                status=403,
                errors={section: exc.message},
                values={section: exc.form},
            )
        form = await request.form()
        values = {k: v for k, v in form.items() if isinstance(v, str) and k != CSRF_FIELD}
        analyst = security.read_analyst(request)
        if analyst is None:
            return decisions(
                request,
                conn,
                incident_id,
                status=401,
                errors={section: "сначала представьтесь: решения без имени аналитика запрещены"},
                values={section: values},
            )
        url = request.url.path
        # Ответственный — свежий, из базы: пока карточка была открыта, его могли сменить
        inc = store.get_incident(conn, incident_id)
        assignee = inc["assignee"]
        if (
            check_assignee
            and assignee is not None
            and assignee != analyst
            and values.get("ack_not_assignee") != "1"
        ):
            question = {"kind": "not_assignee", "url": url, "values": values, "assignee": assignee}
            return decisions(request, conn, incident_id, question=question)
        if ask_action is not None and values.get("ack_action") != "1":
            question = {"kind": "confirm", "url": url, "values": values, "action": ask_action}
            return decisions(request, conn, incident_id, question=question)
        try:
            version = values.get("expected_version", "")
            if not version.isdigit():
                raise store.BadRequest(
                    "в форме нет версии инцидента — обновите страницу и повторите"
                )
            apply(analyst, values, int(version))
        except store.StoreError as exc:
            message = exc.message
            if exc.code == "conflict":
                message += ". Ниже — актуальное состояние; проверьте его и повторите решение."
            return decisions(
                request,
                conn,
                incident_id,
                status=STATUS_BY_CODE[exc.code],
                errors={section: message, "_conflict": section if exc.code == "conflict" else None},
                values={section: values},
            )
        if is_htmx(request):
            return decisions(request, conn, incident_id, headers={"HX-Trigger": "incident-changed"})
        return RedirectResponse(f"/incidents/{quote(incident_id, safe='')}", status_code=303)

    @router.post("/incidents/{incident_id}/assign")
    async def assign(request: Request, incident_id: str, conn=Depends(db)):
        def apply(analyst: str, v: dict, version: int) -> None:
            who = analyst if v.get("take") == "1" else v.get("assignee", "")
            store.assign(conn, incident_id, analyst, who, version, v.get("comment"))

        # Назначение — не решение по инциденту: предупреждение «вы не ответственный» здесь
        # не нужно (иначе «взять себе» чужой инцидент требовало бы лишнего подтверждения)
        return await decide(request, conn, incident_id, "assign", apply, check_assignee=False)

    @router.post("/incidents/{incident_id}/status")
    async def change_status(request: Request, incident_id: str, conn=Depends(db)):
        def apply(analyst: str, v: dict, version: int) -> None:
            comment = (v.get("comment") or "").strip() or None
            store.change_status(
                conn,
                incident_id,
                analyst,
                v.get("status", ""),
                v.get("resolution") or None,
                comment,
                version,
            )

        return await decide(request, conn, incident_id, "status", apply)

    def action_route(kind: str):
        async def handler(request: Request, action_id: str, conn=Depends(db)):
            try:
                action = store.get_action(conn, action_id)
            except store.NotFound as exc:
                return not_found(request, conn, exc.message)

            def apply(analyst: str, v: dict, version: int) -> None:
                comment = (v.get("comment") or "").strip() or None
                fn = store.confirm_action if kind == "confirm" else store.reject_action
                fn(conn, action_id, analyst, version, comment)

            return await decide(
                request,
                conn,
                action["incident_id"],
                "action",
                apply,
                ask_action=action if kind == "confirm" else None,
            )

        return handler

    router.post("/actions/{action_id}/confirm")(action_route("confirm"))
    router.post("/actions/{action_id}/reject")(action_route("reject"))

    app.include_router(router)
