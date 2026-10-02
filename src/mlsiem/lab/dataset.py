"""Размеченный набор стенда из записи сеанса и журнала сценариев (фича 006, US4, R12).

Потоки записи считаются тем же экстрактором 001 (единство признаков), затем размечаются по
журналу: поток с адреса атакующего на цель сценария, целиком лежащий в окне запуска → класс
сценария; поток, пересекающий границу окна (начался раньше или кончился позже плюс допуск) →
`ambiguous` (из метрик исключается, но считается — FR-020); остальное → `benign`.

Набор сохраняется под `data/lab/<версия>/` в схеме признаков 001 (колонка `label` рядом),
версионируется DVC, сопровождается манифестом и отчётом. Разметка — чистая функция
`label_flows`, на ней стоят тесты; сам `build_dataset` ещё и собирает артефакты.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import polars as pl

from mlsiem.data.schema import SCHEMA
from mlsiem.lab import journal

AMBIGUOUS = "ambiguous"
BENIGN = "benign"
# Допуск на границе окна: поток, кончившийся не позже чем на столько после конца запуска,
# считаем принадлежащим запуску, а не «пересекающим границу» (idle-таймаут экстрактора сам
# сдвигает конец потока). По умолчанию — как idle_timeout nfstream
DEFAULT_MARGIN_MS = SCHEMA.extractor["idle_timeout"] * 1000

FIRST = "bidirectional_first_seen_ms"
LAST = "bidirectional_last_seen_ms"


def label_flow(
    first_ms: int, last_ms: int, src_ip: str, dst_ip: str, windows, margin_ms: int
) -> str:
    """Метка одного потока по окнам журнала (список (start, end, запись)).

    Берём первое окно сценария, под которое поток подходит по адресам и времени. Нормальные
    интервалы (benign) рамки не навязывают: поток вне всех сценарных окон — benign.
    """
    for start, end, rec in windows:
        if rec["expected_class"] == BENIGN:
            continue
        if src_ip != rec["attacker_ip"] or dst_ip not in rec["targets"]:
            continue
        # Поток пересекается с окном по времени?
        if last_ms < start or first_ms > end + margin_ms:
            continue
        inside = first_ms >= start and last_ms <= end + margin_ms
        return rec["expected_class"] if inside else AMBIGUOUS
    return BENIGN


def label_flows(
    flows: pl.DataFrame, records: list[dict], *, margin_ms: int = DEFAULT_MARGIN_MS
) -> pl.DataFrame:
    """Добавляет колонку `label` к потокам по журналу (data-model, FR-020)."""
    windows = journal.windows(records)
    labels = [
        label_flow(r[FIRST], r[LAST], r["src_ip"], r["dst_ip"], windows, margin_ms)
        for r in flows.iter_rows(named=True)
    ]
    return flows.with_columns(pl.Series("label", labels, dtype=pl.String))


def dataset_report(
    labeled: pl.DataFrame, records: list[dict], counters: dict | None = None
) -> dict:
    """Сводка набора: объём, классы, доля ambiguous, сценарии, потери сенсора (data-model)."""
    counts = labeled["label"].value_counts().sort("label")
    by_class = {r["label"]: r["count"] for r in counts.iter_rows(named=True)}
    total = labeled.height
    ambiguous = by_class.get(AMBIGUOUS, 0)
    scenario_flows = sum(v for k, v in by_class.items() if k not in (BENIGN, AMBIGUOUS)) + ambiguous
    return {
        "total_flows": total,
        "by_class": by_class,
        "ambiguous": ambiguous,
        # Доля ambiguous среди потоков сценариев (SC-007): целевое ≤ 5%
        "ambiguous_share_of_scenarios": (ambiguous / scenario_flows) if scenario_flows else 0.0,
        "scenarios": sorted(
            {(r["name"], r["version"]) for r in records if r["expected_class"] != BENIGN}
        ),
        "runs": len(records),
        "sensor_losses": counters or {},
    }


def write_report_md(report: dict, version: str) -> str:
    lines = [
        f"# Набор стенда {version}",
        "",
        f"- потоков: {report['total_flows']}",
        f"- ambiguous: {report['ambiguous']} "
        f"({report['ambiguous_share_of_scenarios'] * 100:.1f}% потоков сценариев)",
        "",
        "## Классы",
        "",
        "| класс | потоков |",
        "|---|---|",
    ]
    for cls, n in sorted(report["by_class"].items()):
        lines.append(f"| {cls} | {n} |")
    lines += ["", "## Сценарии", ""]
    for name, ver in report["scenarios"]:
        lines.append(f"- {name}@{ver}")
    if report["sensor_losses"]:
        lines += [
            "",
            "## Потери сенсора",
            "",
            f"```\n{json.dumps(report['sensor_losses'], ensure_ascii=False, indent=2)}\n```",
        ]
    return "\n".join(lines) + "\n"


def build_dataset(
    flows: pl.DataFrame,
    records: list[dict],
    out_dir: Path,
    version: str,
    *,
    margin_ms: int = DEFAULT_MARGIN_MS,
    sensor_counters: dict | None = None,
    sources: list[str] | None = None,
) -> dict:
    """Собирает набор под `out_dir` (flows.parquet + label, manifest.json, report.md).

    `flows` — потоки записи сеанса экстрактором 001 (все колонки схемы). Возвращает сводку
    отчёта. Запись атомарна покаталожно (каталог версии создаётся заново).
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    labeled = label_flows(flows, records, margin_ms=margin_ms)
    labeled.write_parquet(out_dir / "flows.parquet")
    report = dataset_report(labeled, records, sensor_counters)
    manifest = {
        "version": version,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "schema_version": SCHEMA.version,
        "margin_ms": margin_ms,
        "n_flows": labeled.height,
        "by_class": report["by_class"],
        "scenarios": report["scenarios"],
        "sources": sources or [],
        "sensor_losses": sensor_counters or {},
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "report.md").write_text(write_report_md(report, version), encoding="utf-8")
    return report
