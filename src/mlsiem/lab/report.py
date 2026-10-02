"""Отчёт по одному запуску сценария (фича 006, US3, FR-016).

По записи журнала (`run_uid`) и состоянию хранилища сеанса сенсора отчёт показывает, что
увидела цепочка от этого запуска: сколько алертов пришлось на окно сценария (адрес атакующего
→ цель, время в окне плюс допуск), какие классы и эксперты сработали (включая алерты окон 007),
какие инциденты задеты и с какими задержками до первого алерта и первого инцидента.

Полного числа потоков сценария у сенсора в хранилище нет (онлайн-сеанс хранит вердикты без
адресов и не хранит не-алертные потоки), поэтому «долю с алертом» отчёт берёт из набора стенда,
если он собран, а здесь — честно отдаёт счётчики алертов и инцидентов за окно. Запрос к
хранилищу — только чтение; задержки считаются по `received_at`/`created_at` относительно начала
запуска из журнала.
"""

from __future__ import annotations

import json
import sqlite3

from mlsiem.lab import journal
from mlsiem.lab.dataset import DEFAULT_MARGIN_MS


def _parse_experts(value: str | None) -> list[str]:
    """`fired_experts` алерта — JSON-список имён или None (прогон до ансамбля)."""
    if not value:
        return []
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return []
    return list(data) if isinstance(data, list) else list(data.keys())


def scenario_alerts(
    conn: sqlite3.Connection, run_id: str, record: dict, *, margin_ms: int = DEFAULT_MARGIN_MS
) -> list[dict]:
    """Алерты сеанса, попадающие в окно запуска: атакующий → цель, время в [start, end+допуск].

    Атакующий сверяется и с `src_ip`, и с `attacker_ip` (для ответного потока атакующая сторона
    — в `attacker_ip`, research R8). Цель — `dst_ip`/`victim_ip` в списке целей записи.
    """
    start, end = journal.to_ms(record["started_at"]), journal.to_ms(record["ended_at"]) + margin_ms
    atk, targets = record["attacker_ip"], set(record["targets"])
    rows = conn.execute(
        "SELECT * FROM alerts WHERE run_id = ? AND first_seen_ms >= ? AND first_seen_ms <= ? "
        "ORDER BY first_seen_ms",
        (run_id, start, end),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        src = d.get("attacker_ip") or d.get("src_ip")
        dst = d.get("victim_ip") or d.get("dst_ip")
        if src == atk and (not targets or dst in targets):
            out.append(d)
    return out


def _latency_s(from_iso: str, to_iso: str | None) -> float | None:
    if not to_iso:
        return None
    return max(0.0, journal.parse_iso(to_iso).timestamp() - journal.parse_iso(from_iso).timestamp())


def run_report(
    conn: sqlite3.Connection,
    run_id: str,
    record: dict,
    *,
    margin_ms: int = DEFAULT_MARGIN_MS,
    dataset_flows: int | None = None,
) -> dict:
    """Отчёт по запуску сценария (FR-016). `dataset_flows` — всего потоков сценария в наборе
    (если собран), для «доли с алертом»; иначе доля не считается."""
    alerts = scenario_alerts(conn, run_id, record, margin_ms=margin_ms)
    by_class: dict[str, int] = {}
    experts: dict[str, int] = {}
    incidents: set[str] = set()
    window_alerts = 0
    first_alert_at = None
    for a in alerts:
        by_class[a["predicted_class"]] = by_class.get(a["predicted_class"], 0) + 1
        for e in _parse_experts(a.get("fired_experts")):
            experts[e] = experts.get(e, 0) + 1
        if a.get("alert_kind") == "window":
            window_alerts += 1
        if a.get("incident_id"):
            incidents.add(a["incident_id"])
        if a.get("received_at") and (first_alert_at is None or a["received_at"] < first_alert_at):
            first_alert_at = a["received_at"]

    # Первый инцидент из задетых — для задержки «запуск → инцидент»
    first_incident_at = None
    if incidents:
        marks = ",".join("?" * len(incidents))
        row = conn.execute(
            f"SELECT MIN(created_at) AS c FROM incidents WHERE incident_id IN ({marks})",
            tuple(incidents),
        ).fetchone()
        first_incident_at = row["c"] if row else None

    start_iso = record["started_at"]
    n = len(alerts)
    return {
        "run_uid": record["run_uid"],
        "scenario": record["name"],
        "version": record["version"],
        "expected_class": record["expected_class"],
        "outcome": record["outcome"],
        "attacker_ip": record["attacker_ip"],
        "targets": record["targets"],
        "n_alerts": n,
        "n_flow_alerts": n - window_alerts,
        "n_window_alerts": window_alerts,
        "by_class": by_class,
        "fired_experts": experts,
        "incidents": sorted(incidents),
        "n_incidents": len(incidents),
        "dataset_flows": dataset_flows,
        "alert_share": (n / dataset_flows) if dataset_flows else None,
        "first_alert_latency_s": _latency_s(start_iso, first_alert_at),
        "first_incident_latency_s": _latency_s(start_iso, first_incident_at),
    }


def report_md(rep: dict) -> str:
    def f(x, fmt="{:.1f}"):
        return "—" if x is None else fmt.format(x)

    lines = [
        f"# Запуск сценария {rep['scenario']}@{rep['version']} ({rep['run_uid']})",
        "",
        f"- ожидаемый класс: {rep['expected_class']}; исход: {rep['outcome']}",
        f"- атакующий: {rep['attacker_ip']} → {', '.join(rep['targets'])}",
        f"- алертов: {rep['n_alerts']} (потоков {rep['n_flow_alerts']}, "
        f"окон {rep['n_window_alerts']})"
        + (f"; доля с алертом: {rep['alert_share'] * 100:.1f}%" if rep["alert_share"] else ""),
        f"- инцидентов: {rep['n_incidents']}",
        f"- задержка до первого алерта: {f(rep['first_alert_latency_s'])} с; "
        f"до инцидента: {f(rep['first_incident_latency_s'])} с",
        "",
        "## Классы алертов",
        "",
    ]
    for cls, k in sorted(rep["by_class"].items()):
        lines.append(f"- {cls}: {k}")
    if rep["fired_experts"]:
        lines += ["", "## Сработавшие эксперты", ""]
        for e, k in sorted(rep["fired_experts"].items()):
            lines.append(f"- {e}: {k}")
    return "\n".join(lines) + "\n"
