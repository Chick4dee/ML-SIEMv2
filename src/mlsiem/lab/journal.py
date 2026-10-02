"""Журнал сценариев стенда (фича 006, data-model «Запуск сценария — запись журнала», FR-014).

JSONL: одна строка — один запуск сценария (или интервал фоновой нормы). По журналу позже
размечается набор стенда (R12): «поток с атакующего на цель в окне запуска → класс сценария».

ВАЖНО: модуль только на стандартной библиотеке — его же файл копируется на атакующую машину
(seed-ISO, `mlsiem stand seed-iso --role attacker`), где нет ни mlsiem, ни polars. Поэтому
здесь нет импортов из пакета, а записи — обычные словари.

Времена — UTC ISO-8601 с миллисекундами и `Z`, как в хранилище 002–005: так окна журнала
и времена потоков (мс от эпохи) сопоставимы без пересчёта часовых поясов.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

OUTCOMES = ("completed", "aborted", "rejected")
BENIGN = "benign"
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
) -> dict:
    if outcome not in OUTCOMES:
        raise JournalError(f"outcome {outcome!r}: допустимы {list(OUTCOMES)}")
    if outcome == "rejected" and not reject_reason:
        raise JournalError("у отклонённого запуска нужна причина reject_reason")
    return validate(
        {
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
    )


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


def append(path: str | Path, record: dict) -> None:
    """Дописывает запись одной строкой. Строка пишется целиком одним вызовом и сбрасывается на
    диск — обрыв питания оставит журнал без последней записи, но не с половиной строки."""
    validate(record)
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def read(path: str | Path) -> list[dict]:
    """Все записи журнала по порядку. Пустой/отсутствующий файл — пустой список; битая строка —
    JournalError с номером (молча пропускать нельзя: разметка набора стала бы неверной)."""
    path = Path(path)
    if not path.exists():
        return []
    out: list[dict] = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            raise JournalError(f"{path.name}, строка {n}: не JSON ({exc.msg})") from exc
        try:
            out.append(validate(rec))
        except JournalError as exc:
            raise JournalError(f"{path.name}, строка {n}: {exc}") from exc
    return out


def find(records: list[dict], run_uid: str) -> dict:
    for rec in records:
        if rec["run_uid"] == run_uid:
            return rec
    raise JournalError(f"в журнале нет запуска {run_uid}")


def windows(records: list[dict]) -> list[tuple[int, int, dict]]:
    """Завершённые запуски как окна (начало_мс, конец_мс, запись) — для разметки набора.
    Отклонённые запуски трафика не создавали и окон не дают."""
    out = [(to_ms(r["started_at"]), to_ms(r["ended_at"]), r) for r in records]
    return sorted((w for w in out if w[2]["outcome"] != "rejected"), key=lambda w: (w[0], w[1]))
