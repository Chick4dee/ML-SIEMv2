"""Русские подписи значений и форматы времени для шаблонов (FR-028, research R13).

Одна точка перевода вместо строк, разбросанных по шаблонам: в базе и API значения остаются
кодами (`in_progress`, `block_source_ip`), а аналитик видит «в работе», «заблокировать адрес
источника». Классы атак не переводим — как в датасете, чтобы их можно было сверить с
литературой по UNSW-NB15.

Время везде в UTC с подписью «UTC»: время трафика из датасета (2015 год) и время решений
аналитиков — это разные «часы», и путать их с местным временем опасно.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from jinja2 import Environment

LABELS: dict[str, dict[str, str]] = {
    "status": {"new": "новый", "in_progress": "в работе", "closed": "закрыт"},
    "resolution": {"confirmed": "подтверждён", "false_positive": "ложное срабатывание"},
    "severity": {
        "low": "низкая",
        "medium": "средняя",
        "high": "высокая",
        "critical": "критическая",
    },
    "action_type": {
        "block_source_ip": "заблокировать адрес источника",
        "isolate_host": "изолировать хост",
        "observe": "наблюдать",
        "manual_review": "ручной разбор",
    },
    "action_state": {
        "proposed": "ждёт решения",
        "executed": "выполнено (симуляция)",
        "rejected": "отклонено",
    },
    "event": {
        "action_proposed": "плейбук предложил действие",
        "action_executed": "действие подтверждено (симуляция)",
        "action_rejected": "действие отклонено",
        "incident_status_changed": "смена статуса",
        "run_loaded": "загружен прогон",
        "incident_assigned": "назначение ответственного",
        # события хронологии карточки, которых нет в аудите
        "first_alert": "первый алерт",
        "last_alert": "последний алерт",
        "incident_created": "инцидент создан",
    },
    "role": {
        "victims": "жертвы",
        "background": "фон",
        "infrastructure": "инфраструктура",
        "other": "другое",
    },
    "field": {"status": "статус", "resolution": "резолюция", "assignee": "ответственный"},
    "clock": {"traffic": "время трафика", "decision": "время решения"},
    "flag": {"network": "сеть", "target_elsewhere": "цель в других инцидентах"},
    # фича 004: эксперты ансамбля (contracts/ui.md)
    "expert": {
        "classifier": "классификатор атак",
        "anomaly": "детектор аномалий",
        "meta": "мета-слой",
        "meta_only": "только мета-слой",
    },
}

# Класс «аномалия» — единственный, который переводим: это не класс датасета, а честное
# «что это за атака, неизвестно» (сработал только детектор аномалий, FR-017)
ANOMALY_CLASS_TITLE = "аномалия (класс неизвестен)"
# Короткие метки экспертов для таблицы алертов — с расшифровкой в легенде
EXPERT_SHORT = {"classifier": "К", "anomaly": "А"}
META_SHORT = "М"
REVERSED_BADGE = "ответный"

EMPTY = "—"


def label(value: object, kind: str) -> str:
    """Подпись значения; неизвестное значение показываем как есть (лучше код, чем пусто)."""
    if value is None or value == "":
        return EMPTY
    return LABELS.get(kind, {}).get(str(value), str(value))


def utc_ms(ms: int | None) -> str:
    """Миллисекунды epoch (время трафика) → `2015-02-18 06:50:34 UTC`."""
    if ms is None:
        return EMPTY
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def utc_iso(iso: str | None) -> str:
    """ISO-8601 (время решений в базе) → тот же вид, что у `utc_ms`."""
    if not iso:
        return EMPTY
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def short_list(items: Iterable[object] | None, n: int = 3) -> str:
    """`a, b, c и ещё 5` — длинные списки целей не ломают строку таблицы."""
    items = [str(i) for i in (items or [])]
    if not items:
        return EMPTY
    head = ", ".join(items[:n])
    rest = len(items) - n
    return f"{head} и ещё {rest}" if rest > 0 else head


# Номера IP-протоколов в потоках 001 — подписываем самые частые, остальные показываем числом
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 132: "SCTP"}


def proto(number: int | None) -> str:
    if number is None:
        return EMPTY
    name = PROTOCOLS.get(int(number))
    return f"{name} ({number})" if name else str(number)


def percent(x: float | None, digits: int = 1) -> str:
    return EMPTY if x is None else f"{x * 100:.{digits}f}%"


def attack_class(value: object) -> str:
    """Класс атаки для показа: классы датасета — как есть, `anomaly` — по-русски."""
    if value == "anomaly":
        return ANOMALY_CLASS_TITLE
    return EMPTY if value in (None, "") else str(value)


def experts_short(fired: list[str] | None) -> str:
    """Сработавшие эксперты коротко: «К», «А», «К+А»; «М» — алерт поднял только мета-слой;
    пусто — прогон до ансамбля (ответов экспертов нет)."""
    if fired is None:
        return EMPTY
    if not fired:
        return META_SHORT
    return "+".join(EXPERT_SHORT.get(n, n) for n in sorted(fired, key=_expert_order))


def _expert_order(name: str) -> tuple[int, str]:
    # Классификатор первым — так «К+А» читается одинаково во всех таблицах
    return (0 if name == "classifier" else 1, name)


def register(env: Environment) -> None:
    env.filters.update(
        cls=attack_class,
        experts_short=experts_short,
        label=label,
        utc_ms=utc_ms,
        utc_iso=utc_iso,
        short_list=short_list,
        percent=percent,
        proto=proto,
    )
