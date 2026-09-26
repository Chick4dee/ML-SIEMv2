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
    "after_decision",
    "show_merged",
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
    "after_decision": "новые алерты после решения",
    "show_merged": "показать объединённые",
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
    # фича 005: только инциденты с алертами после решения; показывать поглощённые слиянием
    after_decision: str | None = None
    show_merged: bool = False
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

        after_decision = _one(params, "after_decision")
        if after_decision is not None and after_decision != "only":
            warnings.append(
                f"фильтр «новые алерты после решения» не применён: {after_decision!r} — "
                "допустимо only"
            )
            after_decision = None
        show_merged = _one(params, "show_merged")
        if show_merged is not None and show_merged not in ("1", "0"):
            warnings.append(f"параметр «показать объединённые» не применён: {show_merged!r}")
            show_merged = None

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
            after_decision=after_decision,
            show_merged=show_merged == "1",
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
        for name in ("attack_class", "src", "assignee", "flagged", "after_decision"):
            if getattr(v, name):
                out[name] = getattr(v, name)
        if v.show_merged:
            out["show_merged"] = "1"
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
            + (self.action_state, self.flagged, self.after_decision)
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
            "after_decision": self.after_decision,
            "show_merged": self.show_merged,
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
    run = store.get_run(conn, view.run) if view.run else None
    return {
        # фича 005: фильтры потока показываются только у онлайн-сеанса
        "stream_run": bool(run and run.get("mode") == "stream"),
        "view": view,
        "total": total,
        "items": items,
        "pages": pages,
        # Класс «аномалия» в фильтре есть всегда (фича 004): его выдаёт только ансамбль
        "classes": filter_classes(list(summary["by_class"]) if summary else []),
        "run_total": summary["total"] if summary else 0,
        "etag": list_etag(conn, view),
    }


def filter_classes(present: list[str]) -> list[str]:
    """Варианты фильтра «Класс атаки»: классы прогона и всегда `anomaly` (в конце)."""
    return [c for c in present if c != "anomaly"] + ["anomaly"]


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
    # ---- фича 005
    if event == "incident_updated":
        text = f"поток дописал алертов: {d.get('added', 0)}"
        if d.get("moved"):
            text += f", перенесено при слиянии: {d['moved']}"
        text += f"; всего {d.get('n_alerts')}"
        if d.get("severity_old") != d.get("severity_new"):
            text += (
                f"; серьёзность {label(d.get('severity_old'), 'severity')} → "
                f"{label(d.get('severity_new'), 'severity')}"
            )
        if d.get("after_decision"):
            text += " (после решения аналитика — решение не изменено)"
        return text
    if event == "incident_merged":
        text = (
            f"инцидент объединён с {d.get('into')}: перенесено алертов {d.get('moved_alerts', 0)}"
        )
        if d.get("action_withdrawn"):
            text += "; предложенное действие снято"
        return text
    if event == "action_reproposed":
        old, new = d.get("old") or {}, d.get("new") or {}
        return (
            f"предложение пересчитано: {label(old.get('action_type'), 'action_type')} "
            f"({old.get('target') or 'без объекта'}) → "
            f"{label(new.get('action_type'), 'action_type')} "
            f"({new.get('target') or 'без объекта'}) по правилу {new.get('rule_id')}"
        )
    if event == "session_status_changed":
        return (
            f"сеанс: {label(d.get('old'), 'session_status')} → "
            f"{label(d.get('new'), 'session_status')}"
            + (f" ({d['reason']})" if d.get("reason") else "")
        )
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
        # фича 004: кто поднял алерты инцидента
        "experts_summary": store.experts_summary(conn, incident_id),
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


def model_title(run: dict) -> str:
    """Модель прогона словами: «ансамбль <версия> (<вариант>)» или «детектор <версия>»."""
    m = run.get("model") or store.run_model(run)
    if m["kind"] == "ensemble":
        return f"ансамбль {m['version']} ({m['selected']})"
    return f"детектор {m['version']}"


def _expert_value(kind: str, x: float | None) -> str:
    """Скор эксперта так, как его понимает аналитик: у аномалий — перцентиль нормы."""
    if x is None:
        return "—"
    if kind == "anomaly":
        return f"{x * 100:.1f}-й перцентиль нормы"
    return f"{x:.4f}"


def experts_block(run: dict, alert: dict | None) -> dict:
    """Блок «Эксперты» деталей алерта (фича 004, contracts/ui.md, FR-019).

    Всё берётся из SQLite (ответы экспертов и объяснение пишутся в алерт при прогоне) —
    поэтому блок есть, даже если файл вердиктов прогона потерян. У прогонов до ансамбля
    ответов экспертов нет: вместо таблицы — честная пометка с версией детектора.
    """
    if alert is None:
        return {"available": False, "note": "поток не стал алертом — ответов экспертов нет"}
    if alert.get("experts") is None:
        return {
            "available": False,
            "note": (
                f"Прогон сделан до появления ансамбля: один детектор {run['detector_version']}"
            ),
        }
    meta = (run.get("summary") or {}).get("experts_meta") or {}
    rows = []
    order = sorted(alert["experts"], key=lambda n: (n != "classifier", n))
    for name in order:
        e = alert["experts"][name]
        kind = (meta.get(name) or {}).get("kind", name)
        rows.append(
            {
                "name": name,
                "score": _expert_value(kind, e.get("score")),
                "threshold": _expert_value(kind, e.get("threshold")),
                "fired": bool(e.get("fired")),
            }
        )
    summary = run.get("summary") or {}
    return {
        "available": True,
        "explanation": alert.get("explanation"),
        "rows": rows,
        "model": model_title(run),
        "final_score": alert["attack_score"],
        "final_threshold": summary.get("threshold"),
        "final_class": alert["predicted_class"],
        "reversed": bool(alert.get("reversed")),
        "attacker_ip": alert.get("attacker_ip"),
        "original": (
            f"{alert['src_ip']}:{alert['src_port']} → {alert['dst_ip']}:{alert['dst_port']}"
        ),
    }


def alert_probs(
    cfg: SocConfig, run: dict, flow_uid: str, detector_dir: Path, alert: dict | None = None
) -> dict:
    """Вероятности по классам для одного потока и порог (FR-010, research R10) + блок экспертов.

    Вероятности не хранятся в SQLite — их сотни тысяч; они в `verdicts.parquet` прогона.
    Читается одна строка через ленивый скан с фильтром — это десятки миллисекунд.
    Любая беда с файлом — не ошибка страницы, а честное «вероятности недоступны».
    Блок экспертов (фича 004) — из SQLite, от файла не зависит.
    """
    out: dict[str, Any] = {
        "available": False,
        "flow_uid": flow_uid,
        "run_id": run["run_id"],
        "experts": experts_block(run, alert),
    }
    run_dir = Path(cfg.runs_dir) / run["run_id"]
    path = run_dir / "verdicts.parquet"
    # Фича 005: у онлайн-сеанса вердикты — каталог файлов по пачкам (verdicts/part-*.parquet)
    parts = sorted((run_dir / "verdicts").glob("part-*.parquet")) if not path.exists() else []
    if not path.exists() and not parts:
        out["reason"] = "вероятности недоступны: файл вердиктов прогона не найден"
        return out
    try:
        source = path if path.exists() else [str(x) for x in parts]
        row = (
            pl.scan_parquet(source)
            .filter(pl.col("flow_uid") == flow_uid)
            .collect()
            .unique(subset="flow_uid", keep="first")
        )
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
    run = store.get_run(conn, run_id)
    summary = run.get("summary") or {}
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
        "run": run,
        "etag": '"' + store.list_state(conn, run_id) + '"',
        # фича 004: модель прогона и вклад экспертов
        "model": model_title(run),
        "alerts_by_expert": summary.get("alerts_by_expert") or {},
        "n_reversed": summary.get("n_reversed"),
        "direction_mode": summary.get("direction_mode"),
        "before_ensemble": "model" not in summary,
        # фича 005: онлайн-сеанс — блок «Поток» на панели
        "stream": run.get("mode") == "stream",
    }


def stream_panel(conn: sqlite3.Connection, run_id: str, lease_ttl_s: float) -> dict:
    """Блок «Поток» панели сеанса (FR-022, contracts/api-ui-additions): статус сеанса, живость
    потребителя и последние показатели. Только чтение из SQLite — брокер не опрашивается,
    чтобы панель не зависала на выключенной машине."""
    import time

    run = store.get_run(conn, run_id)
    stats = store.latest_stats(conn, run_id) or {}
    stream = (run.get("summary") or {}).get("stream") or {}
    lease = store.lease_info(conn, lease_ttl_s, now=time.time())
    return {
        "run": run,
        "status": run["status"],
        "consumer_alive": lease["alive"],
        "consumer": lease["holder"],
        "rate_per_s": stats.get("rate_per_s"),
        "lag_messages": stats.get("lag_messages"),
        "lag_seconds": stats.get("lag_seconds"),
        "latency_p50_ms": stats.get("latency_p50_ms"),
        "latency_p95_ms": stats.get("latency_p95_ms"),
        "rejected": stream.get("n_rejected", 0),
        "late": stream.get("n_late", 0),
        "merged": stream.get("n_merged", 0),
        "after_decision": stream.get("n_after_decision", 0),
        "end_received": bool(stream.get("end_received")),
        "last_activity_at": run.get("last_activity_at"),
        "etag": '"'
        + store.input_digest(
            run_id,
            str(run.get("last_activity_at")),
            run["status"],
            str(lease["alive"]),
            str(stats.get("stat_id")),
        )[:20]
        + '"',
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
    if e["event"] in (
        "incident_status_changed",
        "incident_assigned",
        "action_proposed",
        # фича 005
        "incident_updated",
        "incident_merged",
        "action_reproposed",
        "session_status_changed",
    ):
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
