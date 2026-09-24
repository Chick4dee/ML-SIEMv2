"""Сборка данных для шаблонов консоли: вид списка, карточка, хронология, панель, журнал.

Здесь нет SQL и нет правил решений — только чтение через `soc.store` и `soc.flags` и
раскладка результата так, как удобно шаблону. Благодаря этому шаблоны остаются «глупыми»
(вывод и циклы), а всё, что можно проверить тестом без браузера, проверяется здесь.

Главная идея вида списка (`IncidentListView`): адрес страницы и есть вид. Фильтры, сортировка
и страница разбираются из параметров адреса и собираются обратно в адрес — поэтому ссылкой на
отфильтрованный список можно поделиться, а счётчик панели ведёт ровно в тот список, который
дал его число (SC-004). Некорректный параметр не роняет страницу: он игнорируется, а над
таблицей появляется предупреждение, что именно не применено.
"""

from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import polars as pl

from mlsiem.soc import flags as soc_flags
from mlsiem.soc import store
from mlsiem.soc.config import SEVERITY_LEVELS, SocConfig
from mlsiem.ui.labels import label, utc_iso, utc_ms

LIST_PARAMS = (
    "run",
    "status",
    "severity",
    "attack_class",
    "src",
    "assignee",
    "action_state",
    "flagged",
    "sort",
    "dir",
    "page",
)
FLAGGED = ("only", "hide")
PARAM_NAMES = {
    "run": "прогон",
    "status": "статус",
    "severity": "серьёзность",
    "attack_class": "класс атаки",
    "src": "источник",
    "assignee": "ответственный",
    "action_state": "состояние действия",
    "flagged": "подозрительный источник",
    "sort": "сортировка",
    "dir": "направление",
    "page": "страница",
    "actor": "аналитик",
    "event": "событие",
    "incident": "инцидент",
}


def _values(params, name: str) -> list[str]:
    """Значения параметра: и `status=new,closed`, и `status=new&status=closed` (так шлёт
    GET-форма с флажками). Пустые строки — «не задано»."""
    raw = params.getlist(name) if hasattr(params, "getlist") else [params.get(name)]
    out: list[str] = []
    for chunk in raw:
        if chunk:
            out += [v.strip() for v in str(chunk).split(",") if v.strip()]
    return list(dict.fromkeys(out))


def _one(params, name: str) -> str | None:
    vals = _values(params, name)
    return ",".join(vals) if vals else None


def _page(params, warnings: list[str]) -> int:
    raw = _one(params, "page")
    if raw is None:
        return 1
    if raw.isdigit() and int(raw) >= 1:
        return int(raw)
    warnings.append(f"параметр «страница» не применён: {raw!r} — нужно целое число от 1")
    return 1


def _multi(params, name: str, allowed: tuple[str, ...], warnings: list[str]) -> tuple[str, ...]:
    vals = _values(params, name)
    good = tuple(v for v in vals if v in allowed)
    bad = [v for v in vals if v not in allowed]
    if bad:
        warnings.append(
            f"фильтр «{PARAM_NAMES[name]}» не применён для значений {', '.join(bad)}: "
            f"допустимы {', '.join(allowed)}"
        )
    return good


# ---------------------------------------------------------------- вид списка


@dataclass(frozen=True)
class IncidentListView:
    run: str | None = None
    status: tuple[str, ...] = ()
    severity: tuple[str, ...] = ()
    attack_class: str | None = None
    src: str | None = None
    assignee: str | None = None
    action_state: tuple[str, ...] = ()
    flagged: str | None = None
    sort: str = "severity"
    dir: str = "desc"
    page: int = 1

    @classmethod
    def parse(cls, params, runs: list[str]) -> tuple[IncidentListView, list[str]]:
        """Вид из параметров адреса + предупреждения о непринятых значениях.

        `runs` — идентификаторы прогонов, новые первыми: без параметра `run` (или с
        неизвестным) берётся последний.
        """
        warnings: list[str] = []
        run = _one(params, "run")
        if run is not None and run not in runs:
            warnings.append(f"прогон {run!r} не найден — показан последний")
            run = None
        run = run or (runs[0] if runs else None)

        src = _one(params, "src")
        if src is not None:
            try:
                store.parse_ip_filter(src)
            except store.BadRequest as exc:
                warnings.append(f"фильтр «источник» не применён: {exc.message}")
                src = None

        assignee = _one(params, "assignee")
        if assignee is not None and assignee != store.NO_ASSIGNEE:
            try:
                assignee = store.clean_name(assignee, "имя ответственного")
            except store.BadRequest as exc:
                warnings.append(f"фильтр «ответственный» не применён: {exc.message}")
                assignee = None

        flagged = _one(params, "flagged")
        if flagged is not None and flagged not in FLAGGED:
            warnings.append(
                f"фильтр «подозрительный источник» не применён: {flagged!r} — "
                "допустимы only (только) и hide (скрыть)"
            )
            flagged = None

        sort = _one(params, "sort") or "severity"
        if sort not in store.SORTS:
            warnings.append(
                f"сортировка {sort!r} не применена — допустимы {', '.join(store.SORTS)}"
            )
            sort = "severity"
        direction = _one(params, "dir") or "desc"
        if direction not in store.DIRECTIONS:
            warnings.append(f"направление {direction!r} не применено — допустимы asc и desc")
            direction = "desc"

        view = cls(
            run=run,
            status=_multi(params, "status", store.INCIDENT_STATUSES, warnings),
            severity=_multi(params, "severity", SEVERITY_LEVELS, warnings),
            attack_class=_one(params, "attack_class"),
            src=src,
            assignee=assignee,
            action_state=_multi(params, "action_state", store.ACTION_STATES, warnings),
            flagged=flagged,
            sort=sort,
            dir=direction,
            page=_page(params, warnings),
        )
        return view, warnings

    def params(self, **overrides: Any) -> dict[str, str]:
        """Параметры адреса без значений по умолчанию (короткие и читаемые ссылки)."""
        v = replace(self, **overrides) if overrides else self
        out: dict[str, str] = {}
        if v.run:
            out["run"] = v.run
        for name in ("status", "severity", "action_state"):
            if getattr(v, name):
                out[name] = ",".join(getattr(v, name))
        for name in ("attack_class", "src", "assignee", "flagged"):
            if getattr(v, name):
                out[name] = getattr(v, name)
        if v.sort != "severity":
            out["sort"] = v.sort
        if v.dir != "desc":
            out["dir"] = v.dir
        if v.page != 1:
            out["page"] = str(v.page)
        return out

    def to_query(self, **overrides: Any) -> str:
        return urlencode(self.params(**overrides))

    def url(self, **overrides: Any) -> str:
        q = self.to_query(**overrides)
        return f"/incidents?{q}" if q else "/incidents"

    def page_url(self, n: int) -> str:
        return self.url(page=n)

    def sort_url(self, key: str) -> str:
        """Ссылка заголовка столбца: тот же ключ — сменить направление, другой — по убыванию."""
        direction = ("asc" if self.dir == "desc" else "desc") if key == self.sort else "desc"
        return self.url(sort=key, dir=direction, page=1)

    @property
    def filtered(self) -> bool:
        return any(
            (self.status, self.severity, self.attack_class, self.src, self.assignee)
            + (self.action_state, self.flagged)
        )

    def store_filters(self) -> dict:
        return {
            "run_id": self.run,
            "status": list(self.status) or None,
            "severity": list(self.severity) or None,
            "attack_class": self.attack_class,
            "src_ip": self.src,
            "assignee": self.assignee,
            "action_state": list(self.action_state) or None,
        }


def run_ids(conn: sqlite3.Connection) -> list[str]:
    return [r["run_id"] for r in store.list_runs(conn)]


def list_page(conn: sqlite3.Connection, cfg: SocConfig, view: IncidentListView) -> dict:
    """Страница списка: строки с метками, число найденных, страницы, классы для фильтра."""
    size = cfg.ui.page_size
    filters = view.store_filters()
    run_flags = soc_flags.run_flags(conn, view.run, cfg.networks) if view.run else {}
    if view.flagged == "only":
        filters["incident_ids"] = list(run_flags)
    elif view.flagged == "hide":
        filters["exclude_ids"] = list(run_flags)
    total, items = store.list_incidents(
        conn, filters, size, (view.page - 1) * size, sort=view.sort, direction=view.dir
    )
    for item in items:
        item["flags"] = run_flags.get(item["incident_id"], [])
    pages = max(1, math.ceil(total / size))
    summary = store.dashboard_summary(conn, view.run) if view.run else None
    return {
        "view": view,
        "total": total,
        "items": items,
        "pages": pages,
        "classes": list(summary["by_class"]) if summary else [],
        "run_total": summary["total"] if summary else 0,
        "etag": list_etag(conn, view),
    }


def list_etag(conn: sqlite3.Connection, view: IncidentListView) -> str:
    """ETag фрагмента таблицы: состояние прогона + сам вид (другие фильтры — другой ответ)."""
    return '"' + store.input_digest(store.list_state(conn, view.run), view.to_query())[:20] + '"'


# ---------------------------------------------------------------- карточка


@dataclass
class TimelineEvent:
    """Строка хронологии (data-model TimelineEvent). `sort_ms` — для упорядочивания:
    время трафика и время решений — разные часы, но оба сводятся к epoch UTC."""

    sort_ms: float
    at: str
    clock: str  # traffic | decision
    kind: str
    actor: str | None
    text: str
    non_assignee: bool = False
    comment: str | None = None


def _iso_ms(iso: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000


def _alert_text(a: dict) -> str:
    return (
        f"{a['src_ip']}:{a['src_port']} → {a['dst_ip']}:{a['dst_port']}, "
        f"класс {a['predicted_class']}, уверенность {a['attack_score']:.3f}"
    )


def _audit_text(e: dict) -> str:
    d = e["details"]
    event = e["event"]
    if event == "action_proposed":
        return (
            f"плейбук предложил: {label(d.get('action_type'), 'action_type')}"
            f" ({d.get('target') or 'без объекта'}) по правилу {d.get('rule_id')}"
        )
    if event == "incident_assigned":
        return f"ответственный: {d.get('old') or '—'} → {d.get('new') or '—'}"
    if event == "incident_status_changed":
        parts = [
            f"{label(c['field'], 'field')}: {label(c['old'], c['field'])} → "
            f"{label(c['new'], c['field'])}"
            for c in d.get("changes", [])
        ]
        return "; ".join(parts) or "смена статуса"
    if event == "action_executed":
        return (
            f"действие подтверждено: {label(d.get('action_type'), 'action_type')}"
            f" ({d.get('target') or 'без объекта'}) — выполнено в симуляции"
        )
    if event == "action_rejected":
        return f"действие отклонено: {label(d.get('action_type'), 'action_type')}"
    return label(event, "event")


def timeline(inc: dict, audit: list[dict], first: dict | None, last: dict | None) -> list:
    """Хронология инцидента одной лентой (FR-011a): трафик + создание + все решения."""
    events: list[TimelineEvent] = []
    if first:
        events.append(
            TimelineEvent(
                first["first_seen_ms"],
                utc_ms(first["first_seen_ms"]),
                "traffic",
                "first_alert",
                None,
                "первый алерт: " + _alert_text(first),
            )
        )
    if last and (not first or last["alert_id"] != first["alert_id"]):
        events.append(
            TimelineEvent(
                last["first_seen_ms"],
                utc_ms(last["first_seen_ms"]),
                "traffic",
                "last_alert",
                None,
                "последний алерт: " + _alert_text(last),
            )
        )
    events.append(
        TimelineEvent(
            _iso_ms(inc["created_at"]),
            utc_iso(inc["created_at"]),
            "decision",
            "incident_created",
            store.SYSTEM_ACTOR,
            f"инцидент создан прогоном {inc['run_id']}",
        )
    )
    for e in audit:
        d = e["details"]
        events.append(
            TimelineEvent(
                _iso_ms(e["at"]),
                utc_iso(e["at"]),
                "decision",
                e["event"],
                e["actor"],
                _audit_text(e),
                non_assignee=bool(d.get("by_non_assignee")),
                comment=d.get("comment"),
            )
        )
    # sorted устойчив: при равном времени сохраняется порядок источника (создание раньше
    # предложения плейбука — оба пишутся с одной меткой времени)
    events.sort(key=lambda ev: ev.sort_ms)
    return events


def incident_card(
    conn: sqlite3.Connection, cfg: SocConfig, incident_id: str, alerts_page: int = 1
) -> dict:
    """Всё для карточки: инцидент, метки, алерты (страница), гистограмма, хронология, аудит."""
    inc = store.get_incident(conn, incident_id)
    run_flags = soc_flags.run_flags(conn, inc["run_id"], cfg.networks)
    inc["flags"] = run_flags.get(incident_id, [])
    audit = store.incident_audit(conn, incident_id)
    total, first = store.list_alerts(conn, incident_id, limit=1)
    last = store.list_alerts(conn, incident_id, limit=1, offset=max(total - 1, 0))[1]
    return {
        "inc": inc,
        "run": store.get_run(conn, inc["run_id"]),
        "audit": audit,
        "histogram": store.alert_histogram(conn, incident_id),
        "timeline": timeline(inc, audit, first[0] if first else None, last[0] if last else None),
        "alerts": alerts_page_data(conn, cfg, incident_id, alerts_page),
        "related_flags": [f for f in inc["flags"] if f.kind == "target_elsewhere"],
    }


def alerts_page_data(conn: sqlite3.Connection, cfg: SocConfig, incident_id: str, page: int):
    size = cfg.ui.alerts_page_size
    total, items = store.list_alerts(conn, incident_id, size, (max(page, 1) - 1) * size)
    card = f"/incidents/{quote(incident_id, safe='')}"
    return {
        "incident_id": incident_id,
        "total": total,
        "items": items,
        "page": max(page, 1),
        "pages": max(1, math.ceil(total / size)),
        # ссылки пагинации: без JS — вся карточка на нужной странице, с htmx — только таблица
        "href": lambda n: f"{card}?alerts_page={n}#alerts",
        "hx": lambda n: f"/fragments/incidents/{quote(incident_id, safe='')}/alerts?page={n}",
    }


def alert_probs(cfg: SocConfig, run: dict, flow_uid: str, detector_dir: Path) -> dict:
    """Вероятности детектора по классам для одного потока и порог (FR-010, research R10).

    Вероятности не хранятся в SQLite — их сотни тысяч; они в `verdicts.parquet` прогона.
    Читается одна строка через ленивый скан с фильтром — это десятки миллисекунд.
    Любая беда с файлом — не ошибка страницы, а честное «вероятности недоступны».
    """
    out: dict[str, Any] = {"available": False, "flow_uid": flow_uid, "run_id": run["run_id"]}
    path = Path(cfg.runs_dir) / run["run_id"] / "verdicts.parquet"
    if not path.exists():
        out["reason"] = "вероятности недоступны: файл вердиктов прогона не найден"
        return out
    try:
        row = pl.scan_parquet(path).filter(pl.col("flow_uid") == flow_uid).collect()
    except (OSError, pl.exceptions.PolarsError) as exc:
        out["reason"] = f"вероятности недоступны: файл вердиктов не читается ({exc})"
        return out
    if row.height == 0:
        out["reason"] = "вероятности недоступны: потока нет в файле вердиктов"
        return out
    rec = row.row(0, named=True)
    probs = sorted(
        ((c[2:], float(rec[c])) for c in row.columns if c.startswith("p_")),
        key=lambda kv: -kv[1],
    )
    threshold, note = run_threshold(run, detector_dir)
    out.update(
        available=True,
        probs=probs,
        attack_score=float(rec["attack_score"]),
        predicted_class=rec["predicted_class"],
        threshold=threshold,
        threshold_note=note,
        is_alert=bool(rec["is_alert"]),
    )
    return out


def run_threshold(run: dict, detector_dir: Path) -> tuple[float | None, str]:
    """Порог детектора, которым сделан прогон.

    С фичи 003 прогон сам записывает порог в сводку. Для старых прогонов берём карточку
    текущего детектора, но только если это тот же детектор (совпала версия): порог чужого
    детектора рядом с вероятностями ввёл бы аналитика в заблуждение.
    """
    summary = run.get("summary") or {}
    if summary.get("threshold") is not None:
        return float(summary["threshold"]), "порог детектора прогона"
    card_path = Path(detector_dir) / "model_card.json"
    try:
        card = json.loads(card_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        card = {}
    if card.get("detector_version") == run["detector_version"] and "threshold" in card:
        return float(card["threshold"]), "порог из карточки детектора (та же версия)"
    return None, "порог неизвестен: детектор прогона заменён, а прогон сделан до фичи 003"


# ---------------------------------------------------------------- панель


def dashboard(conn: sqlite3.Connection, cfg: SocConfig, run_id: str) -> dict:
    """Сводка прогона + для каждого счётчика готовая ссылка в список (FR-022, SC-004)."""
    s = store.dashboard_summary(conn, run_id)
    run_flags = soc_flags.run_flags(conn, run_id, cfg.networks)
    base = IncidentListView(run=run_id)
    counters = {
        "total": (s["total"], base.url()),
        "actions_pending": (s["actions_pending"], base.url(action_state=("proposed",))),
        "unassigned": (
            s["unassigned"],
            base.url(assignee=store.NO_ASSIGNEE, status=("new", "in_progress")),
        ),
        "flagged": (len(run_flags), base.url(flagged="only")),
    }
    return {
        "summary": s,
        "counters": counters,
        "by_status": [(k, n, base.url(status=(k,))) for k, n in s["by_status"].items()],
        "by_severity": [(k, n, base.url(severity=(k,))) for k, n in s["by_severity"].items()],
        "by_class": [(k, n, base.url(attack_class=k)) for k, n in s["by_class"].items()],
        "run": store.get_run(conn, run_id),
        "etag": '"' + store.list_state(conn, run_id) + '"',
    }


# ---------------------------------------------------------------- журнал аудита


@dataclass(frozen=True)
class AuditView:
    actor: str | None = None
    event: str | None = None
    incident: str | None = None
    run: str | None = None
    page: int = 1
    warnings: tuple[str, ...] = field(default=(), compare=False)

    @classmethod
    def parse(cls, params) -> AuditView:
        warnings: list[str] = []
        event = _one(params, "event")
        if event is not None and event not in store.AUDIT_EVENTS:
            warnings.append(f"фильтр «событие» не применён: неизвестное событие {event!r}")
            event = None
        return cls(
            actor=_one(params, "actor"),
            event=event,
            incident=_one(params, "incident"),
            run=_one(params, "run"),
            page=_page(params, warnings),
            warnings=tuple(warnings),
        )

    def params(self, **overrides: Any) -> dict[str, str]:
        v = replace(self, **overrides) if overrides else self
        out = {k: getattr(v, k) for k in ("actor", "event", "incident", "run") if getattr(v, k)}
        if v.page != 1:
            out["page"] = str(v.page)
        return out

    def url(self, **overrides: Any) -> str:
        q = urlencode(self.params(**overrides))
        return f"/audit?{q}" if q else "/audit"

    def page_url(self, n: int) -> str:
        return self.url(page=n)

    def store_filters(self) -> dict:
        return {
            "actor": self.actor,
            "event": self.event,
            "incident_id": self.incident,
            "run_id": self.run,
        }


def audit_page(conn: sqlite3.Connection, cfg: SocConfig, view: AuditView) -> dict:
    size = cfg.ui.page_size
    total, items = store.list_audit(
        conn, view.store_filters(), size, (view.page - 1) * size, newest_first=True
    )
    return {
        "view": view,
        "total": total,
        "items": items,
        "pages": max(1, math.ceil(total / size)),
        "events": store.AUDIT_EVENTS,
    }


def audit_details(e: dict) -> list[tuple[str, str]]:
    """Детали записи аудита по-русски: пары «что — значение» для таблицы журнала."""
    d = e["details"]
    rows: list[tuple[str, str]] = []
    if e["event"] in ("incident_status_changed", "incident_assigned", "action_proposed"):
        rows.append(("изменение", _audit_text(e)))
    if e["event"] in ("action_executed", "action_rejected"):
        rows.append(("действие", _audit_text(e)))
        sim = d.get("simulation")
        if sim:
            rows.append(("симуляция", str(sim.get("description") or sim)))
    if e["event"] == "run_loaded":
        rows.append(
            (
                "прогон",
                f"{d.get('source')}: потоков {d.get('n_flows')}, алертов {d.get('n_alerts')}, "
                f"инцидентов {d.get('n_incidents')}, детектор {d.get('detector_version')}",
            )
        )
    if d.get("comment"):
        rows.append(("комментарий", str(d["comment"])))
    if d.get("by_non_assignee"):
        rows.append(
            ("внимание", f"решение принято не ответственным (ответственный — {d.get('assignee')})")
        )
    return rows
