"""Журнал сценариев стенда (фича 006, data-model «Запуск сценария — запись журнала», FR-014;
расширен фичей 008: версия записи 2, маркеры начала запуска, прерванные запуски).

JSONL: одна строка — один запуск сценария (или интервал фоновой нормы). По журналу позже
размечается набор стенда (R12): «поток с источника на цель в окне запуска → класс сценария».

ВАЖНО: модуль только на стандартной библиотеке — его же файл копируется на атакующую машину
(seed-ISO, `mlsiem stand seed-iso --role attacker`), где нет ни mlsiem, ни polars. Поэтому
здесь нет импортов из пакета, а записи — обычные словари.

Времена — UTC ISO-8601 с миллисекундами и `Z`, как в хранилище 002–005: так окна журнала
и времена потоков (мс от эпохи) сопоставимы без пересчёта часовых поясов.

Версия записи 2 (008) добавляет необязательные поля варианта, источника, повтора и плана
(`EXTRA_FIELDS`); записи версии 1 читаются как есть. Кроме итоговых записей в журнал пишутся
маркеры начала запуска (`event: "started"`): если итоговой записи с тем же `run_uid` нет,
запуск считается прерванным (обрыв питания, закрытое окно) — `pending_markers` их находит,
а `close_pending` превращает в записи `aborted`.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

OUTCOMES = ("completed", "aborted", "rejected")
BENIGN = "benign"
RECORD_VERSION = 2
FIELDS = (
    "run_uid",
    "name",
    "version",
    "attacker_ip",
    "targets",
    "expected_class",
    "started_at",
    "ended_at",
    "outcome",
    "reject_reason",
)
# Необязательные поля версии 2 (008): ни одно не обязательно, лишних ключей запись не принимает
EXTRA_FIELDS = (
    "record_version",
    "variant",
    "tool",
    "tool_version",
    "params",
    "source",
    "source_ip",
    "repeat",
    "part",
    "concurrent",
    "reserve_unknown",
    "plan_run_uid",
    "attempt",
    "session_id",
    "hard_normal",
)
START_EVENT = "started"


class JournalError(ValueError):
    """Запись журнала не по формату или файл повреждён; текст — по-русски."""


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def to_ms(value: str) -> int:
    """Время записи журнала → миллисекунды от эпохи (как `bidirectional_first_seen_ms`)."""
    return int(round(parse_iso(value).timestamp() * 1000))


def new_run_uid() -> str:
    return "sc-" + uuid.uuid4().hex[:12]


def make_record(
    *,
    name: str,
    version: str,
    attacker_ip: str,
    targets: list[str],
    expected_class: str,
    started_at: str,
    ended_at: str,
    outcome: str,
    reject_reason: str | None = None,
    run_uid: str | None = None,
    **extra,
) -> dict:
    """Итоговая запись запуска. `extra` — необязательные поля версии 2 (`EXTRA_FIELDS`)."""
    if outcome not in OUTCOMES:
        raise JournalError(f"outcome {outcome!r}: допустимы {list(OUTCOMES)}")
    if outcome == "rejected" and not reject_reason:
        raise JournalError("у отклонённого запуска нужна причина reject_reason")
    unknown = sorted(set(extra) - set(EXTRA_FIELDS))
    if unknown:
        raise JournalError(f"неизвестные поля записи журнала: {', '.join(unknown)}")
    rec = {
        "run_uid": run_uid or new_run_uid(),
        "name": name,
        "version": str(version),
        "attacker_ip": attacker_ip,
        "targets": list(targets),
        "expected_class": expected_class,
        "started_at": started_at,
        "ended_at": ended_at,
        "outcome": outcome,
        "reject_reason": reject_reason,
    }
    if extra:
        rec["record_version"] = RECORD_VERSION
        rec.update({k: v for k, v in extra.items() if v is not None})
    return validate(rec)


def make_start_marker(
    *,
    run_uid: str,
    started_at: str,
    name: str,
    source_ip: str,
    version: str | None = None,
    targets: list[str] | None = None,
    expected_class: str | None = None,
    **extra,
) -> dict:
    """Маркер начала запуска: пишется ДО запуска инструмента и сбрасывается на диск.
    Версия, цели и класс нужны, чтобы по одному маркеру построить запись `aborted`."""
    unknown = sorted(set(extra) - set(EXTRA_FIELDS))
    if unknown:
        raise JournalError(f"неизвестные поля маркера: {', '.join(unknown)}")
    marker = {
        "event": START_EVENT,
        "run_uid": run_uid,
        "name": name,
        "source_ip": source_ip,
        "started_at": started_at,
    }
    for key, value in (
        ("version", version),
        ("targets", targets),
        ("expected_class", expected_class),
    ):
        if value is not None:
            marker[key] = (
                list(value) if key == "targets" else str(value) if key == "version" else value
            )
    marker.update({k: v for k, v in extra.items() if v is not None})
    return marker


def validate(record: dict) -> dict:
    """Проверяет форму записи (все поля, outcome, порядок времён) и возвращает её же."""
    missing = [f for f in FIELDS if f not in record]
    if missing:
        raise JournalError(f"в записи журнала нет полей: {', '.join(missing)}")
    if record["outcome"] not in OUTCOMES:
        raise JournalError(f"outcome {record['outcome']!r}: допустимы {list(OUTCOMES)}")
    if not isinstance(record["targets"], list):
        raise JournalError("поле targets должно быть списком адресов")
    try:
        start, end = to_ms(record["started_at"]), to_ms(record["ended_at"])
    except (ValueError, TypeError) as exc:
        raise JournalError(f"время записи {record.get('run_uid')}: {exc}") from exc
    if end < start:
        raise JournalError(f"запись {record['run_uid']}: конец раньше начала")
    return record


def _write_line(path: str | Path, obj: dict) -> None:
    line = json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n"
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def append(path: str | Path, record: dict) -> None:
    """Дописывает запись одной строкой. Строка пишется целиком одним вызовом и сбрасывается на
    диск — обрыв питания оставит журнал без последней записи, но не с половиной строки."""
    validate(record)
    _write_line(path, record)


def append_marker(path: str | Path, marker: dict) -> None:
    """Дописывает маркер начала запуска (с немедленным сбросом на диск)."""
    if marker.get("event") != START_EVENT or "run_uid" not in marker or "started_at" not in marker:
        raise JournalError("маркер начала: нужны event=started, run_uid и started_at")
    _write_line(path, marker)


def _read_lines(path: str | Path) -> list[tuple[int, dict]]:
    path = Path(path)
    if not path.exists():
        return []
    out: list[tuple[int, dict]] = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            out.append((n, json.loads(line)))
        except json.JSONDecodeError as exc:
            raise JournalError(f"{path.name}, строка {n}: не JSON ({exc.msg})") from exc
    return out


def read(path: str | Path) -> list[dict]:
    """Все итоговые записи журнала по порядку. Пустой/отсутствующий файл — пустой список; битая
    строка — JournalError с номером (молча пропускать нельзя: разметка набора стала бы неверной).
    Маркеры начала запуска пропускаются — их читает `pending_markers`."""
    name = Path(path).name
    out: list[dict] = []
    for n, rec in _read_lines(path):
        if rec.get("event") == START_EVENT:
            continue
        try:
            out.append(validate(rec))
        except JournalError as exc:
            raise JournalError(f"{name}, строка {n}: {exc}") from exc
    return out


def pending_markers(path: str | Path) -> list[dict]:
    """Маркеры начала без итоговой записи с тем же run_uid — прерванные запуски."""
    lines = _read_lines(path)
    done = {
        rec["run_uid"] for _, rec in lines if rec.get("event") != START_EVENT and "run_uid" in rec
    }
    return [
        rec for _, rec in lines if rec.get("event") == START_EVENT and rec["run_uid"] not in done
    ]


def close_pending(path: str | Path, ended_at: str, *, limit_s: float | None = None) -> list[dict]:
    """Превращает прерванные запуски в итоговые записи `aborted` и дописывает их в журнал.

    Конец запуска — `ended_at` (последний известный момент работы) или, если задан `limit_s`,
    не позже чем начало + предел длительности: инструмент на машине мог работать до предела, и
    окно должно покрывать весь возможный след (потоки в нём станут неоднозначными)."""
    closed = []
    for m in pending_markers(path):
        end = ended_at
        if limit_s is not None:
            end = max(ended_at, _plus_seconds(m["started_at"], limit_s))
        extra = {k: v for k, v in m.items() if k in EXTRA_FIELDS}
        rec = make_record(
            name=m.get("name", "?"),
            version=str(m.get("version", "?")),
            attacker_ip=m.get("source_ip", ""),
            targets=m.get("targets", []),
            expected_class=m.get("expected_class", "?"),
            started_at=m["started_at"],
            ended_at=end,
            outcome="aborted",
            run_uid=m["run_uid"],
            **extra,
        )
        append(path, rec)
        closed.append(rec)
    return closed


def _plus_seconds(iso: str, seconds: float) -> str:
    from datetime import timedelta

    t = parse_iso(iso) + timedelta(seconds=seconds)
    return t.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def find(records: list[dict], run_uid: str) -> dict:
    for rec in records:
        if rec["run_uid"] == run_uid:
            return rec
    raise JournalError(f"в журнале нет запуска {run_uid}")


def windows(records: list[dict]) -> list[tuple[int, int, dict]]:
    """Запуски как окна (начало_мс, конец_мс, запись) — для разметки набора.
    Отклонённые запуски трафика не создавали и окон не дают; прерванные (`aborted`) окна дают:
    разметка набора помечает их потоки неоднозначными, а не нормой."""
    out = [(to_ms(r["started_at"]), to_ms(r["ended_at"]), r) for r in records]
    return sorted((w for w in out if w[2]["outcome"] != "rejected"), key=lambda w: (w[0], w[1]))
