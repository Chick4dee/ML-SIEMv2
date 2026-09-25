"""Разбор инцидентов «с адресов жертв и фона» и сравнение прогонов «до/после» (фича 004, R9).

Откуда задача. В прогоне 002 14 инцидентов «атаковали» с адресов жертв (149.171.126.x) и
фонового трафика (59.166.0.x) UNSW-NB15. Фича 004 добавила правило атакующей стороны
(soc/direction.py); этот модуль одной командой отвечает на два вопроса:

1. Почему каждый такой инцидент появился — по каждому его потоку причина:
   - `response_direction` — правило направления признаёт поток ответным (атакующий — другая
     сторона), то есть инцидент — следствие записи потока «от ответчика»;
   - `detector_error` — по разметке поток нормальный и прямой: ошибся детектор;
   - `labeled_attack` — по разметке это атака, и поток прямой (редкий случай «атака с адреса
     жертвы» — такое тоже честно показываем).
2. Что стало после исправления (`--after`): сколько таких инцидентов осталось и не потерян ли
   ни один настоящий атакующий. Атакующий «до» — пара (IP, класс) инцидента, у которого IP
   ВНЕ сетей жертв и фона, а среди алертов есть атаки по разметке; каждая такая пара должна
   найтись среди (атакующая сторона, класс) инцидентов «после» (SC-007).

ВАЖНО (FR-023). Знание сетей жертв/фона и метки потоков используются ТОЛЬКО здесь, в
отчёте-оценке. Само правило направления их не видит (и тест это проверяет): иначе оно бы
«подглядывало» в ответ и сломалось бы на стенде с другими адресами.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from pathlib import Path

import polars as pl

from mlsiem.data.captures import atomic_path
from mlsiem.detect.metrics import BENIGN
from mlsiem.soc import store
from mlsiem.soc.config import SocConfig
from mlsiem.soc.direction import DIRECTION_COLUMNS, attacker_side

# Роли сетей, «атаки» из которых разбираются (как у меток подозрительного источника 003)
REVIEW_ROLES = ("victims", "background")
REASONS = ("response_direction", "detector_error", "labeled_attack")
REASON_TITLES = {
    "response_direction": "ответное направление (атакующий — вторая сторона)",
    "detector_error": "ошибка детектора (по разметке норма)",
    "labeled_attack": "атака по разметке, поток прямой",
}


def network_of(ip: str | None, cfg: SocConfig) -> dict | None:
    """Сеть с ролью «жертвы»/«фон», в которую входит адрес, — или None."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    for n in cfg.networks:
        if n.role in REVIEW_ROLES and any(addr in c for c in n.cidrs):
            return {"name": n.name, "role": n.role}
    return None


def _run_flows(cfg: SocConfig, run: dict, flow_uids: list[str], data_dir: Path) -> pl.DataFrame:
    """Поля потоков для правила направления — оттуда же, откуда их брал прогон."""
    from mlsiem.detect.dataset import scan_part

    kind, _, rest = run["source"].partition(":")
    if kind == "split":
        split, _, part = rest.partition("/")
        lazy = scan_part(split, part, data_dir=data_dir, columns=list(DIRECTION_COLUMNS))
    else:
        path = Path(cfg.runs_dir) / run["run_id"] / "flows.parquet"
        if not path.exists():
            raise ValueError(f"у прогона {run['run_id']} нет {path} — потоки PCAP не найти")
        lazy = pl.scan_parquet(path).select(list(DIRECTION_COLUMNS))
    return lazy.filter(pl.col("flow_uid").is_in(flow_uids)).collect()


def _labels(cfg: SocConfig, run_id: str) -> pl.DataFrame:
    path = Path(cfg.runs_dir) / run_id / "verdicts.parquet"
    if not path.exists():
        raise ValueError(
            f"у прогона {run_id} нет файла вердиктов {path} — разбор причин без него невозможен"
        )
    cols = pl.read_parquet_schema(path)
    if "true_label" not in cols:
        raise ValueError(
            f"прогон {run_id} сделан на неразмеченном входе (нет true_label) — причины "
            "«ошибка детектора / атака» без разметки не определить"
        )
    return pl.read_parquet(path, columns=["flow_uid", "true_label"])


def _incidents(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    return [
        {**dict(r), "targets": json.loads(r["targets"])}
        for r in conn.execute(
            "SELECT incident_id, src_ip, attack_class, targets, n_alerts FROM incidents "
            "WHERE run_id = ? ORDER BY first_seen_ms, incident_id",
            (run_id,),
        )
    ]


def _alerts(conn: sqlite3.Connection, run_id: str) -> pl.DataFrame:
    rows = conn.execute(
        "SELECT incident_id, flow_uid, src_ip, src_port, dst_ip, dst_port, protocol "
        "FROM alerts WHERE run_id = ?",
        (run_id,),
    ).fetchall()
    schema = {
        "incident_id": pl.String,
        "flow_uid": pl.String,
        "src_ip": pl.String,
        "src_port": pl.Int64,
        "dst_ip": pl.String,
        "dst_port": pl.Int64,
        "protocol": pl.Int64,
    }
    return pl.DataFrame([dict(r) for r in rows], schema=schema, orient="row")


def review_sources(
    conn: sqlite3.Connection,
    cfg: SocConfig,
    run_before: str,
    run_after: str | None = None,
    *,
    data_dir: Path = Path("data"),
) -> dict:
    """Отчёт разбора (data-model «Отчёт разбора источников»); ничего не пишет в базу."""
    before = store.get_run(conn, run_before)
    after = store.get_run(conn, run_after) if run_after else None
    labels = _labels(cfg, run_before)
    incidents = _incidents(conn, run_before)
    alerts = _alerts(conn, run_before).join(labels, on="flow_uid", how="left")

    suspicious = [(i, net) for i in incidents if (net := network_of(i["src_ip"], cfg))]
    uids = alerts.filter(pl.col("incident_id").is_in([i["incident_id"] for i, _ in suspicious]))[
        "flow_uid"
    ].to_list()
    flows = _run_flows(cfg, before, uids, Path(data_dir))
    side = attacker_side(flows) if flows.height else None

    rows = []
    for inc, net in suspicious:
        part = alerts.filter(pl.col("incident_id") == inc["incident_id"]).sort("flow_uid")
        if side is not None:
            part = part.join(side, on="flow_uid", how="left")
        flow_rows = []
        for a in part.iter_rows(named=True):
            reversed_ = bool(a.get("reversed"))
            label = a.get("true_label")
            if reversed_:
                reason = "response_direction"
            elif label == BENIGN:
                reason = "detector_error"
            else:
                reason = "labeled_attack"
            flow_rows.append(
                {
                    "flow_uid": a["flow_uid"],
                    "flow": f"{a['src_ip']}:{a['src_port']} → {a['dst_ip']}:{a['dst_port']}",
                    "protocol": a["protocol"],
                    "true_label": label,
                    "reversed": reversed_,
                    "direction_rule": a.get("direction_rule"),
                    "attacker_ip": a.get("attacker_ip"),
                    "reason": reason,
                }
            )
        reasons = sorted({f["reason"] for f in flow_rows})
        rows.append(
            {
                "incident_id": inc["incident_id"],
                "src_ip": inc["src_ip"],
                "network": net,
                "attack_class": inc["attack_class"],
                "n_alerts": inc["n_alerts"],
                "reasons": reasons,
                # Инцидент «только из-за направления» — все его потоки ответные
                "only_direction": reasons == ["response_direction"],
                "flows": flow_rows,
            }
        )

    counts = {
        "before": len(rows),
        "only_direction": sum(r["only_direction"] for r in rows),
        "detector_error": sum(r["reasons"] == ["detector_error"] for r in rows),
        "labeled_attack": sum("labeled_attack" in r["reasons"] for r in rows),
        "after": None,
    }
    report: dict = {
        "run_before": run_before,
        "run_after": run_after,
        "model_before": before["model"],
        "model_after": after["model"] if after else None,
        "direction_after": (after["summary"] or {}).get("direction_mode") if after else None,
        "incidents": rows,
        "counts": counts,
        "attackers_kept": None,
    }
    if after is not None:
        after_incidents = _incidents(conn, run_after)
        after_suspicious = [i for i in after_incidents if network_of(i["src_ip"], cfg)]
        counts["after"] = len(after_suspicious)
        report["incidents_after"] = [
            {
                "incident_id": i["incident_id"],
                "src_ip": i["src_ip"],
                "attack_class": i["attack_class"],
            }
            for i in after_suspicious
        ]
        attacked = set(
            alerts.filter(pl.col("true_label").is_not_null() & (pl.col("true_label") != BENIGN))[
                "incident_id"
            ].to_list()
        )
        attackers = sorted(
            {
                (i["src_ip"], i["attack_class"])
                for i in incidents
                if i["incident_id"] in attacked and network_of(i["src_ip"], cfg) is None
            }
        )
        after_pairs = {(i["src_ip"], i["attack_class"]) for i in after_incidents}
        kept = [{"ip": ip, "class": c, "kept": (ip, c) in after_pairs} for ip, c in attackers]
        report["attackers_kept"] = {
            "pairs": kept,
            "lost": [{"ip": k["ip"], "class": k["class"]} for k in kept if not k["kept"]],
        }
    return report


def summary_line(report: dict) -> str:
    """Одна строка для stdout: «было N → стало M, из-за направления K, …»."""
    c = report["counts"]
    after = "—" if c["after"] is None else str(c["after"])
    line = (
        f"инцидентов с адресов жертв/фона: было {c['before']} → стало {after}; "
        f"только из-за направления {c['only_direction']}, ошибок детектора {c['detector_error']}"
    )
    kept = report.get("attackers_kept")
    if kept is not None:
        line += f", потеряно атакующих {len(kept['lost'])}"
    return line


def render_review(report: dict) -> str:
    """Markdown-отчёт разбора по-русски."""
    c = report["counts"]
    lines = [
        f"# Разбор инцидентов с адресов жертв и фона: прогон {report['run_before']}",
        "",
        f"- Модель прогона: {report['model_before']['kind']} `{report['model_before']['version']}`",
        f"- Сравнение с прогоном: {report['run_after'] or '— (не задан)'}",
        "",
        "Знание сетей жертв/фона и метки потоков здесь используются только для оценки; правило "
        "атакующей стороны (soc/direction.py) их не видит (FR-023).",
        "",
        "## Итог",
        "",
        f"- Инцидентов с адресов жертв/фона: {c['before']}"
        + ("" if c["after"] is None else f" → после: {c['after']}"),
        f"- Только из-за ответного направления: {c['only_direction']}",
        f"- Только ошибки детектора (норма по разметке): {c['detector_error']}",
        f"- С атаками по разметке (поток прямой): {c['labeled_attack']}",
    ]
    kept = report.get("attackers_kept")
    if kept is not None:
        lost = kept["lost"]
        lines.append(
            f"- Атакующих «до»: {len(kept['pairs'])}, потеряно после: {len(lost)}"
            + (
                " — **ПОТЕРЯНЫ АТАКУЮЩИЕ**: " + ", ".join(f"{x['ip']}/{x['class']}" for x in lost)
                if lost
                else ""
            )
        )
    lines += ["", "## Инциденты «до»", ""]
    if not report["incidents"]:
        lines.append("Таких инцидентов нет.")
    for r in report["incidents"]:
        lines += [
            f"### {r['incident_id']} — {r['src_ip']} ({r['network']['name']}), "
            f"класс {r['attack_class']}, алертов {r['n_alerts']}",
            "",
            "| Поток | Протокол | Метка | Правило направления | Атакующий по правилу | Причина |",
            "|---|---|---|---|---|---|",
        ]
        for f in r["flows"]:
            lines.append(
                f"| {f['flow']} | {f['protocol']} | {f['true_label']} | {f['direction_rule']} | "
                f"{f['attacker_ip']} | {REASON_TITLES[f['reason']]} |"
            )
        lines.append("")
    if report.get("incidents_after"):
        lines += ["## Осталось «после»", ""]
        for i in report["incidents_after"]:
            lines.append(f"- {i['incident_id']} — {i['src_ip']}, класс {i['attack_class']}")
        lines.append("")
    return "\n".join(lines) + "\n"


def write_review(report: dict, reports_dir: Path) -> tuple[Path, Path]:
    """Пишет `source_review_<run>.md` и `.json` атомарно."""
    reports_dir = Path(reports_dir)
    base = f"source_review_{report['run_before']}"
    md, js = reports_dir / f"{base}.md", reports_dir / f"{base}.json"
    with atomic_path(md) as tmp:
        tmp.write_text(render_review(report), encoding="utf-8")
    with atomic_path(js) as tmp:
        tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return md, js
