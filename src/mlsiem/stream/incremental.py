"""Инкрементальная группировка алертов в инциденты со слиянием (FR-013, FR-014, research R8).

Пакетная группировка (`soc.incidents.group_alerts`) видит все алерты сразу: сортирует алерты
ключа (атакующий, класс) по времени начала и режет там, где разрыв больше окна W. Поток видит
алерты пачками и не обязательно по порядку. Здесь — то же правило в форме, которая не зависит
от порядка прихода:

    алерт с временем начала t присоединяется к инциденту ключа, если
    first_seen − W ≤ t ≤ last_alert_start + W          (границы включительные, как «≤ W»)

Инцидент — это отрезок [first_seen, last_alert_start] на оси времени трафика, а пакетные
инциденты — компоненты связности «соседи не дальше W». Если алерт попал в окна ДВУХ
инцидентов, он их связал: поздний сливается в ранний. Так результат после всех алертов
совпадает с пакетным при любом порядке и размере пачек — это и проверяет property-тест.

Важно: правая граница — время НАЧАЛА последнего алерта (`last_alert_start_ms`), а не время
конца его потока (`last_seen_ms`): пакетная группировка мерит разрыв по времени начала.

Исключение одно (FR-017): если по позднему инциденту аналитик уже что-то решил (статус не
`new` или действие не `proposed`), автоматика его не трогает — слияния нет, алерт уходит в
ранний, а пара записывается в `stream_divergences` (FR-021).

Модуль только ПЛАНИРУЕТ: читает состояние сеанса из SQLite и считает, что должно измениться
(`SessionPlan`). Записывает план `store.append_batch` одной транзакцией, проверяя версии —
если аналитик успел что-то решить между планом и записью, план считается заново (FR-020).
Поля инцидента считаются общей с пакетным режимом функцией `incident_fields`, серьёзность —
`severity`, предложения — `propose_action`.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

import polars as pl

from mlsiem.soc.incidents import incident_fields, incident_id
from mlsiem.soc.playbooks import propose_action

KEY = ("attacker_ip", "predicted_class")
# Колонки алертов, нужные для пересчёта полей инцидента
FIELD_INPUT = ("flow_uid", "first_seen_ms", "last_seen_ms", "attack_score", "victim_ip")


def decided(status: str | None, action_state: str | None) -> bool:
    """«Решение принято» (FR-017): статус не `new` или действие не `proposed`."""
    return (status or "new") != "new" or (action_state is not None and action_state != "proposed")


def mark_late(
    times: list[int], max_seen_ms: int | None, lateness_ms: int
) -> tuple[list[bool], int | None]:
    """Флаги «опоздал» для времён начала в порядке прихода и новый максимум сеанса.

    Опоздавший — начался раньше максимума, уже виденного в сеансе, больше чем на
    `allowed_lateness_ms`. Обрабатывается он так же (слияние делает результат независимым
    от порядка), флаг нужен для показателей и отчёта сравнения.
    """
    flags = []
    current = max_seen_ms
    for t in times:
        flags.append(current is not None and t < current - lateness_ms)
        current = t if current is None else max(current, t)
    return flags, current


@dataclass
class ExistingIncident:
    incident_id: str
    key: tuple[str, str]
    first_seen_ms: int
    last_alert_start_ms: int
    status: str
    version: int
    n_alerts: int
    severity: str
    severity_reason: str
    targets: str
    alerts_after_decision: int
    first_after_decision_ms: int | None
    action: dict | None

    @property
    def decided(self) -> bool:
        return decided(self.status, (self.action or {}).get("state"))


@dataclass
class IncidentUpdate:
    """Существующий инцидент, который дописан (и/или поглотил другой)."""

    incident_id: str
    fields: dict
    added: int
    moved: int
    expected_version: int
    old_severity: str
    old_n_alerts: int
    decided: bool
    after_decision_added: int
    first_after_decision_ms: int | None
    action: dict | None
    new_action: dict | None  # переписанное предложение (только если решения ещё нет)


@dataclass
class NewIncident:
    row: dict  # поля таблицы incidents (без служебных status/version/…)
    action: dict


@dataclass
class Merge:
    absorbed_id: str
    into_id: str
    moved_alerts: int
    expected_version: int
    action: dict | None


@dataclass
class SessionPlan:
    run_id: str
    alerts: list[dict] = field(default_factory=list)
    new_incidents: list[NewIncident] = field(default_factory=list)
    updates: list[IncidentUpdate] = field(default_factory=list)
    merges: list[Merge] = field(default_factory=list)
    divergences: list[dict] = field(default_factory=list)
    n_late: int = 0


# ---------------------------------------------------------------- чтение состояния


def load_open_incidents(conn: sqlite3.Connection, run_id: str) -> list[ExistingIncident]:
    """Непоглощённые инциденты сеанса с их действиями."""
    rows = conn.execute(
        "SELECT i.*, a.action_id AS a_action_id, a.action_type AS a_action_type, "
        "a.target AS a_target, a.rule_id AS a_rule_id, a.rule_text AS a_rule_text, "
        "a.state AS a_state, a.version AS a_version "
        "FROM incidents i LEFT JOIN actions a ON a.incident_id = i.incident_id "
        "WHERE i.run_id = ? AND i.merged_into IS NULL",
        (run_id,),
    ).fetchall()
    out = []
    for r in rows:
        action = None
        if r["a_action_id"] is not None:
            action = {
                "action_id": r["a_action_id"],
                "action_type": r["a_action_type"],
                "target": r["a_target"],
                "rule_id": r["a_rule_id"],
                "rule_text": r["a_rule_text"],
                "state": r["a_state"],
                "version": r["a_version"],
            }
        out.append(
            ExistingIncident(
                incident_id=r["incident_id"],
                key=(r["src_ip"], r["attack_class"]),
                first_seen_ms=r["first_seen_ms"],
                last_alert_start_ms=(
                    r["last_alert_start_ms"]
                    if r["last_alert_start_ms"] is not None
                    else r["first_seen_ms"]
                ),
                status=r["status"],
                version=r["version"],
                n_alerts=r["n_alerts"],
                severity=r["severity"],
                severity_reason=r["severity_reason"],
                targets=r["targets"],
                alerts_after_decision=r["alerts_after_decision"],
                first_after_decision_ms=r["first_after_decision_ms"],
                action=action,
            )
        )
    return out


def _db_alerts(conn: sqlite3.Connection, incident_ids: list[str]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {i: [] for i in incident_ids}
    for chunk_start in range(0, len(incident_ids), 500):
        chunk = incident_ids[chunk_start : chunk_start + 500]
        marks = ", ".join("?" for _ in chunk)
        for r in conn.execute(
            f"SELECT incident_id, {', '.join(FIELD_INPUT)} FROM alerts "
            f"WHERE incident_id IN ({marks})",
            chunk,
        ):
            out[r["incident_id"]].append({c: r[c] for c in FIELD_INPUT})
    return out


# ---------------------------------------------------------------- планирование


@dataclass
class _Group:
    """Инцидент в памяти планировщика: существующий или новый в этой пачке."""

    gid: str
    key: tuple[str, str]
    lo: int
    hi: int
    existing: ExistingIncident | None
    alerts: list[dict] = field(default_factory=list)
    absorbed: list[_Group] = field(default_factory=list)
    merged_into: _Group | None = None

    @property
    def decided(self) -> bool:
        return self.existing is not None and self.existing.decided

    def root(self) -> _Group:
        g = self
        while g.merged_into is not None:
            g = g.merged_into
        return g


def _fields_frame(rows: list[dict]) -> pl.DataFrame:
    return pl.DataFrame(
        {c: [r[c] for r in rows] for c in FIELD_INPUT},
        schema={
            "flow_uid": pl.String,
            "first_seen_ms": pl.Int64,
            "last_seen_ms": pl.Int64,
            "attack_score": pl.Float64,
            "victim_ip": pl.String,
        },
    )


def _action_key(a: dict | None) -> tuple | None:
    return None if a is None else (a["action_type"], a["target"], a["rule_id"])


def plan_batch(
    conn: sqlite3.Connection,
    run_id: str,
    alerts: pl.DataFrame,
    soc_cfg,
    *,
    lateness_ms: int = 0,
    max_seen_ms: int | None = None,
) -> SessionPlan:
    """План изменений инцидентов сеанса от новых алертов пачки.

    `alerts` — кадр `alerts_from_verdicts` в порядке прихода (для флага `late`; если
    колонка `late` уже есть — берётся она). Алерты, уже записанные в сеансе, сюда приходить
    не должны (их отсекает `stream_seen` раньше).
    """
    plan = SessionPlan(run_id=run_id)
    if alerts.height == 0:
        return plan
    W = soc_cfg.window_ms
    rows = alerts.to_dicts()
    # Страховка к `stream_seen`: алерт, уже записанный в сеансе, второй раз не считается —
    # иначе пересчёт полей учёл бы его дважды (FR-015)
    uids = [r["flow_uid"] for r in rows]
    known: set[str] = set()
    for i in range(0, len(uids), 500):
        chunk = uids[i : i + 500]
        marks = ", ".join("?" for _ in chunk)
        known |= {
            x[0]
            for x in conn.execute(
                f"SELECT flow_uid FROM alerts WHERE run_id = ? AND flow_uid IN ({marks})",
                [run_id, *chunk],
            )
        }
    if known:
        rows = [r for r in rows if r["flow_uid"] not in known]
        if not rows:
            return plan
    if "late" not in alerts.columns:
        flags, _ = mark_late([r["first_seen_ms"] for r in rows], max_seen_ms, lateness_ms)
        for r, f in zip(rows, flags, strict=True):
            r["late"] = int(f)
    plan.n_late = sum(int(r["late"]) for r in rows)

    existing = load_open_incidents(conn, run_id)
    by_key: dict[tuple[str, str], list[_Group]] = {}
    for inc in existing:
        by_key.setdefault(inc.key, []).append(
            _Group(inc.incident_id, inc.key, inc.first_seen_ms, inc.last_alert_start_ms, inc)
        )
    taken_ids = {g.gid for gs in by_key.values() for g in gs}

    def new_id(key, t) -> str:
        base = incident_id(run_id, key[0], key[1], t)
        iid, n = base, 1
        while (
            iid in taken_ids
            or conn.execute("SELECT 1 FROM incidents WHERE incident_id = ?", (iid,)).fetchone()
        ):
            n += 1
            iid = f"{base}-{n}"
        taken_ids.add(iid)
        return iid

    # Алерты — по времени начала: так новые инциденты получают id от первого алерта, как в 002
    for r in sorted(rows, key=lambda x: (x["first_seen_ms"], x["flow_uid"])):
        key = (r["attacker_ip"], r["predicted_class"])
        t = r["first_seen_ms"]
        groups = [g for g in by_key.get(key, []) if g.merged_into is None]
        hits = sorted((g for g in groups if g.lo - W <= t <= g.hi + W), key=lambda g: (g.lo, g.gid))
        if not hits:
            target = _Group(new_id(key, t), key, t, t, None)
            by_key.setdefault(key, []).append(target)
            hits = [target]
        target = hits[0]
        for other in hits[1:]:
            if other.decided:
                plan.divergences.append(
                    {
                        "kind": "merge_blocked_by_decision",
                        "incident_id": target.gid,
                        "other_incident_id": other.gid,
                        "flow_uid": r["flow_uid"],
                        "details": {
                            "text": (
                                f"алерт {r['flow_uid']} связал инциденты {target.gid} и "
                                f"{other.gid}, но по {other.gid} уже принято решение — "
                                "слияния нет (FR-017)"
                            )
                        },
                    }
                )
                continue
            other.merged_into = target
            target.absorbed.append(other)
            target.lo = min(target.lo, other.lo)
            target.hi = max(target.hi, other.hi)
        target.alerts.append(r)
        target.lo = min(target.lo, t)
        target.hi = max(target.hi, t)
        if r["late"]:
            plan.divergences.append(
                {
                    "kind": "late_beyond_allowed",
                    "incident_id": target.gid,
                    "other_incident_id": None,
                    "flow_uid": r["flow_uid"],
                    "details": {"first_seen_ms": t, "lateness_ms": lateness_ms},
                }
            )

    # Итоговые группы, их алерты и поля
    all_groups = [g for gs in by_key.values() for g in gs]
    touched_roots: dict[str, _Group] = {}
    for g in all_groups:
        if g.alerts or g.absorbed:
            root = g.root()
            touched_roots[root.gid] = root
    for g in all_groups:
        if g.merged_into is not None:
            touched_roots.setdefault(g.root().gid, g.root())

    def members(root: _Group) -> list[_Group]:
        out, stack = [], [root]
        while stack:
            x = stack.pop()
            out.append(x)
            stack.extend(x.absorbed)
        return out

    need_db = [
        m.gid for root in touched_roots.values() for m in members(root) if m.existing is not None
    ]
    db_alerts = _db_alerts(conn, need_db)

    for root in touched_roots.values():
        group = members(root)
        new_rows = [a for m in group for a in m.alerts]
        moved_db = [a for m in group if m is not root and m.existing for a in db_alerts[m.gid]]
        own_db = db_alerts.get(root.gid, []) if root.existing else []
        for a in new_rows:
            a["incident_id"] = root.gid
        plan.alerts += new_rows
        fields = incident_fields(
            _fields_frame(own_db + moved_db + new_rows),
            root.key[1],
            soc_cfg.severity_base,
            soc_cfg.bump_at,
        )
        row = {
            "incident_id": root.gid,
            "src_ip": root.key[0],
            "attack_class": root.key[1],
            **fields,
        }
        for m in group:
            if m is not root and m.existing is not None:
                plan.merges.append(
                    Merge(
                        absorbed_id=m.gid,
                        into_id=root.gid,
                        moved_alerts=len(db_alerts[m.gid]),
                        expected_version=m.existing.version,
                        action=m.existing.action,
                    )
                )
        if root.existing is None:
            plan.new_incidents.append(
                NewIncident(
                    row=row, action=propose_action(row, soc_cfg.rules, soc_cfg.protected_ips)
                )
            )
            continue
        inc = root.existing
        is_decided = inc.decided
        added = len(new_rows)
        moved = len(moved_db)
        after_added = added + moved if is_decided else 0
        first_after = inc.first_after_decision_ms
        if is_decided and (new_rows or moved_db):
            t_min = min(a["first_seen_ms"] for a in new_rows + moved_db)
            first_after = t_min if first_after is None else min(first_after, t_min)
        new_action = None
        if not is_decided and inc.action is not None:
            proposed = propose_action(row, soc_cfg.rules, soc_cfg.protected_ips)
            if _action_key(proposed) != _action_key(inc.action):
                new_action = proposed
        plan.updates.append(
            IncidentUpdate(
                incident_id=root.gid,
                fields=fields,
                added=added,
                moved=moved,
                expected_version=inc.version,
                old_severity=inc.severity,
                old_n_alerts=inc.n_alerts,
                decided=is_decided,
                after_decision_added=after_added,
                first_after_decision_ms=first_after,
                action=inc.action,
                new_action=new_action,
            )
        )
    plan.alerts.sort(key=lambda a: a["flow_uid"])
    return plan


def summary_of(plan: SessionPlan) -> dict[str, Any]:
    """Короткая сводка плана — для журнала потребителя и тестов."""
    return {
        "alerts": len(plan.alerts),
        "new_incidents": len(plan.new_incidents),
        "updated": len(plan.updates),
        "merged": len(plan.merges),
        "divergences": len(plan.divergences),
        "late": plan.n_late,
    }
