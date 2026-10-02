"""Сравнение онлайн-сеанса с пакетным прогоном того же входа (FR-021, SC-004, research R12).

Это доказательство главного обещания фичи: поток даёт то же, что `soc run`. Сравниваются:

- вердикты всех потоков — по `flow_uid`, все колонки, что есть у обоих (числа — с допуском
  1e-9: одна и та же модель, но матричные операции над пачками разного размера могут
  отличаться в последнем бите);
- инциденты — по содержанию: (атакующий, класс, first_seen, last_seen, n_alerts,
  серьёзность, цели). Идентификаторы не сравниваются: в потоке id даётся по первому
  ПРИШЕДШЕМУ алерту, в пакете — по самому раннему;
- предложенные действия — (тип, объект, правило) у совпавших инцидентов.

Каждое расхождение получает причину:
- `merge_blocked_by_decision` — слияние не сделано, потому что по инциденту уже решал
  аналитик (FR-017);
- `late_beyond_allowed` — в инциденте есть поток, опоздавший сильнее допустимого;
- `decided_by_analyst` — предложение не пересчитывалось: решение уже принято (R9);
- `window_late_dropped` (фича 007) — поток пришёл в уже закрытое окно (опоздал сильнее
  допустимого) и в онлайне в окно не попал, а в пакете — попал;
- `other` — необъяснённое. Результат «эквивалентно» — когда `other` нет вовсе.

Фича 007 (research R16): дополнительно сравниваются вердикты окон (`windows.parquet` пакета
против частей `windows/` сеанса) и в подписи инцидента — число алертов окон.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from pathlib import Path

import polars as pl

from mlsiem.data.captures import atomic_path
from mlsiem.soc import store

FLOAT_TOL = 1e-9
MAX_EXAMPLES = 20
KNOWN_REASONS = (
    "merge_blocked_by_decision",
    "late_beyond_allowed",
    "decided_by_analyst",
    "window_late_dropped",
)


class CompareError(ValueError):
    """Сравнивать нечего или нельзя (нет прогона, разные модели) — код 1 у команды."""


def session_verdicts(runs_dir: Path, run_id: str) -> pl.DataFrame:
    """Вердикты сеанса — все файлы каталога `verdicts/`, повторы потока отброшены."""
    d = Path(runs_dir) / run_id / "verdicts"
    files = sorted(d.glob("part-*.parquet"))
    if not files:
        return pl.DataFrame({"flow_uid": []}, schema={"flow_uid": pl.String})
    return (
        pl.concat([pl.read_parquet(f) for f in files], how="diagonal_relaxed")
        .unique(subset="flow_uid", keep="first", maintain_order=True)
        .sort("flow_uid")
    )


def batch_verdicts(runs_dir: Path, run_id: str) -> pl.DataFrame:
    path = Path(runs_dir) / run_id / "verdicts.parquet"
    if not path.exists():
        raise CompareError(f"у прогона {run_id} нет файла вердиктов {path}")
    return pl.read_parquet(path).sort("flow_uid")


def session_windows(runs_dir: Path, run_id: str) -> pl.DataFrame:
    """Вердикты окон сеанса — все файлы `windows/part-*.parquet` (фича 007)."""
    files = sorted((Path(runs_dir) / run_id / "windows").glob("part-*.parquet"))
    if not files:
        return pl.DataFrame({"window_id": []}, schema={"window_id": pl.String})
    return (
        pl.concat([pl.read_parquet(f) for f in files], how="diagonal_relaxed")
        .unique(subset="window_id", keep="first", maintain_order=True)
        .sort("window_id")
    )


def batch_windows(runs_dir: Path, run_id: str) -> pl.DataFrame:
    path = Path(runs_dir) / run_id / "windows.parquet"
    if not path.exists():
        return pl.DataFrame({"window_id": []}, schema={"window_id": pl.String})
    return pl.read_parquet(path).sort("window_id")


def _dropped_windows(conn, run_id: str) -> set[str]:
    """Окна сеанса, в которые не попал поток, опоздавший в уже закрытое окно."""
    return {
        d["details"].get("window_id")
        for d in store.divergences(conn, run_id)
        if d["kind"] == "window_late_dropped"
    }


def _model_version(run: dict) -> str:
    return run.get("model_version") or run["detector_version"]


def _compare_verdicts(sv: pl.DataFrame, bv: pl.DataFrame) -> dict:
    common = [c for c in sv.columns if c in bv.columns and c not in ("flow_uid", "explanation")]
    s_ids, b_ids = set(sv["flow_uid"].to_list()), set(bv["flow_uid"].to_list())
    joined = sv.select(["flow_uid", *common]).join(
        bv.select(["flow_uid", *common]), on="flow_uid", how="inner", suffix="__b"
    )
    bad = pl.lit(False)
    for c in common:
        a, b = pl.col(c), pl.col(f"{c}__b")
        if joined[c].dtype.is_float():
            differ = ((a - b).abs() > FLOAT_TOL) | (a.is_null() != b.is_null())
        else:
            differ = a.ne_missing(b)
        bad = bad | differ.fill_null(True)
    mismatched = joined.filter(bad)
    examples = []
    for row in mismatched.head(MAX_EXAMPLES).iter_rows(named=True):
        diff = {
            c: {"session": row[c], "batch": row[f"{c}__b"]}
            for c in common
            if row[c] != row[f"{c}__b"]
        }
        examples.append({"flow_uid": row["flow_uid"], "diff": diff})
    return {
        "session": len(s_ids),
        "batch": len(b_ids),
        "both": joined.height,
        "matched": joined.height - mismatched.height,
        "mismatched": mismatched.height,
        "only_session": sorted(s_ids - b_ids)[:MAX_EXAMPLES],
        "only_batch": sorted(b_ids - s_ids)[:MAX_EXAMPLES],
        "n_only_session": len(s_ids - b_ids),
        "n_only_batch": len(b_ids - s_ids),
        "columns": common,
        "examples": examples,
    }


def _incidents(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT i.*, a.action_type AS a_type, a.target AS a_target, a.rule_id AS a_rule, "
        "a.state AS a_state, (SELECT COUNT(*) FROM alerts w WHERE w.incident_id = i.incident_id "
        "AND w.alert_kind = 'window') AS n_window_alerts "
        "FROM incidents i LEFT JOIN actions a ON a.incident_id = i.incident_id "
        "WHERE i.run_id = ? AND i.merged_into IS NULL",
        (run_id,),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["sig"] = (
            d["src_ip"],
            d["attack_class"],
            d["first_seen_ms"],
            d["last_seen_ms"],
            d["n_alerts"],
            d["severity"],
            tuple(json.loads(d["targets"])),
            # фича 007: сколько из n_alerts — алерты окон (разбивка по видам, R16)
            d["n_window_alerts"],
        )
        d["action_sig"] = (d["a_type"], d["a_target"], d["a_rule"])
        out.append(d)
    return out


def _sig_dict(sig: tuple) -> dict:
    keys = ("src_ip", "attack_class", "first_seen_ms", "last_seen_ms", "n_alerts", "severity")
    return {
        **dict(zip(keys, sig[:6], strict=True)),
        "targets": list(sig[6]),
        "n_window_alerts": sig[7],
    }


def _incident_reasons(conn, run_id: str) -> tuple[set[str], set[str]]:
    """(инциденты сеанса с заблокированным слиянием, инциденты с сильно опоздавшим алертом)."""
    blocked, late = set(), set()
    for d in store.divergences(conn, run_id):
        if d["kind"] == "merge_blocked_by_decision":
            blocked |= {d["incident_id"], d["other_incident_id"]}
    for (iid,) in conn.execute(
        "SELECT DISTINCT incident_id FROM alerts WHERE run_id = ? AND late = 1", (run_id,)
    ):
        late.add(iid)
    return blocked, late


def compare(conn: sqlite3.Connection, runs_dir: Path, session_id: str, batch_id: str) -> dict:
    """Отчёт сравнения сеанса `session_id` с пакетным прогоном `batch_id` (data-model)."""
    try:
        session = store.get_run(conn, session_id)
        batch = store.get_run(conn, batch_id)
    except store.NotFound as exc:
        raise CompareError(exc.message) from exc
    if session["mode"] != "stream":
        raise CompareError(f"{session_id} — не онлайн-сеанс (mode = {session['mode']})")
    if _model_version(session) != _model_version(batch):
        raise CompareError(
            f"модели прогонов различаются: сеанс — {_model_version(session)}, пакетный — "
            f"{_model_version(batch)}; сравнивать можно только одну и ту же модель"
        )

    divergences: list[dict] = []
    verdicts = _compare_verdicts(
        session_verdicts(runs_dir, session_id), batch_verdicts(runs_dir, batch_id)
    )
    if verdicts["mismatched"] or verdicts["n_only_session"] or verdicts["n_only_batch"]:
        divergences.append(
            {
                "reason": "other",
                "what": "verdicts",
                "text": (
                    f"вердикты: различаются {verdicts['mismatched']}, только в сеансе "
                    f"{verdicts['n_only_session']}, только в пакетном {verdicts['n_only_batch']}"
                ),
            }
        )

    # Фича 007: вердикты окон
    dropped = _dropped_windows(conn, session_id)
    sw, bw = session_windows(runs_dir, session_id), batch_windows(runs_dir, batch_id)
    windows = None
    if sw.height or bw.height:
        windows = _compare_verdicts(
            sw.rename({"window_id": "flow_uid"}), bw.rename({"window_id": "flow_uid"})
        )
        bad_ids = {e["flow_uid"] for e in windows["examples"]} | set(windows["only_batch"])
        bad_ids |= set(windows["only_session"])
        if windows["mismatched"] or windows["n_only_session"] or windows["n_only_batch"]:
            explained = bool(dropped) and bad_ids <= dropped
            divergences.append(
                {
                    "reason": "window_late_dropped" if explained else "other",
                    "what": "windows",
                    "text": (
                        f"окна: различаются {windows['mismatched']}, только в сеансе "
                        f"{windows['n_only_session']}, только в пакетном {windows['n_only_batch']}"
                    ),
                }
            )
    dropped_incidents = {
        r[0]
        for w in dropped
        for r in conn.execute(
            "SELECT incident_id FROM alerts WHERE run_id = ? AND flow_uid = ?", (session_id, w)
        )
    }

    s_inc, b_inc = _incidents(conn, session_id), _incidents(conn, batch_id)
    s_count, b_count = Counter(i["sig"] for i in s_inc), Counter(i["sig"] for i in b_inc)
    only_s = s_count - b_count
    only_b = b_count - s_count
    blocked, late = _incident_reasons(conn, session_id)
    by_sig_s: dict[tuple, list[dict]] = {}
    for i in s_inc:
        by_sig_s.setdefault(i["sig"], []).append(i)
    # Для инцидента пакетного прогона — в какие инциденты сеанса попали его алерты
    session_of_flow = dict(
        conn.execute("SELECT flow_uid, incident_id FROM alerts WHERE run_id = ?", (session_id,))
    )

    def reason_of_session(iid: str) -> str:
        if iid in blocked:
            return "merge_blocked_by_decision"
        if iid in late:
            return "late_beyond_allowed"
        if iid in dropped_incidents:
            return "window_late_dropped"
        return "other"

    for sig in only_s.elements():
        inc = by_sig_s[sig][0]
        divergences.append(
            {
                "reason": reason_of_session(inc["incident_id"]),
                "what": "incident_only_in_session",
                "incident_id": inc["incident_id"],
                "incident": _sig_dict(sig),
            }
        )
    b_by_sig: dict[tuple, list[dict]] = {}
    for i in b_inc:
        b_by_sig.setdefault(i["sig"], []).append(i)
    for sig in only_b.elements():
        inc = b_by_sig[sig][0]
        flows = [
            r[0]
            for r in conn.execute(
                "SELECT flow_uid FROM alerts WHERE incident_id = ?", (inc["incident_id"],)
            )
        ]
        reasons = {reason_of_session(session_of_flow[f]) for f in flows if f in session_of_flow}
        known = [r for r in KNOWN_REASONS if r in reasons]
        divergences.append(
            {
                "reason": known[0] if known else "other",
                "what": "incident_only_in_batch",
                "incident_id": inc["incident_id"],
                "incident": _sig_dict(sig),
            }
        )

    # Действия — у инцидентов, совпавших по содержанию
    actions_matched = actions_total = 0
    b_actions = {sig: sorted(i["action_sig"] for i in lst) for sig, lst in b_by_sig.items()}
    for sig, lst in by_sig_s.items():
        if sig not in b_actions:
            continue
        for inc, b_action in zip(lst, b_actions[sig], strict=False):
            actions_total += 1
            if inc["action_sig"] == b_action:
                actions_matched += 1
                continue
            decided = inc["status"] != "new" or inc["a_state"] not in (None, "proposed")
            divergences.append(
                {
                    "reason": "decided_by_analyst" if decided else "other",
                    "what": "action",
                    "incident_id": inc["incident_id"],
                    "session": list(inc["action_sig"]),
                    "batch": list(b_action),
                }
            )

    by_reason = Counter(d["reason"] for d in divergences)
    return {
        "session": {
            "run_id": session_id,
            "source_id": session["source_id"],
            "status": session["status"],
            "model": _model_version(session),
        },
        "batch": {"run_id": batch_id, "source": batch["source"], "model": _model_version(batch)},
        "verdicts": verdicts,
        "windows": windows,
        "n_window_late_dropped": len(dropped),
        "incidents": {
            "session": len(s_inc),
            "batch": len(b_inc),
            "matched": sum((s_count & b_count).values()),
        },
        "actions": {"compared": actions_total, "matched": actions_matched},
        "divergences": divergences,
        "divergences_by_reason": dict(sorted(by_reason.items())),
        "equivalent": by_reason.get("other", 0) == 0,
    }


def _windows_text(report: dict) -> str:
    w = report.get("windows")
    if not w:
        return "Эксперта окон нет ни в сеансе, ни в пакетном прогоне."
    return (
        f"Окон в сеансе {w['session']}, в пакетном {w['batch']}, у обоих {w['both']}; совпало "
        f"{w['matched']}, различается {w['mismatched']}; только в сеансе {w['n_only_session']}, "
        f"только в пакетном {w['n_only_batch']}; потоков, опоздавших в закрытое окно, — "
        f"{report.get('n_window_late_dropped', 0)}."
    )


def render_compare(report: dict) -> str:
    v, i, a = report["verdicts"], report["incidents"], report["actions"]
    s, b = report["session"], report["batch"]
    lines = [
        f"# Сравнение сеанса {s['run_id']} с пакетным прогоном {b['run_id']}",
        "",
        f"- Сеанс: `{s['source_id']}` (статус {s['status']}), модель {s['model']}",
        f"- Пакетный прогон: `{b['source']}`, модель {b['model']}",
        f"- Итог: **{'эквивалентно' if report['equivalent'] else 'НЕ эквивалентно'}**",
        "",
        "## Вердикты",
        "",
        f"Потоков в сеансе {v['session']}, в пакетном {v['batch']}, у обоих {v['both']}; "
        f"совпало {v['matched']}, различается {v['mismatched']}; только в сеансе "
        f"{v['n_only_session']}, только в пакетном {v['n_only_batch']}.",
        "",
        "## Окна",
        "",
        _windows_text(report),
        "",
        "## Инциденты",
        "",
        f"В сеансе {i['session']}, в пакетном {i['batch']}, совпало по содержанию "
        f"{i['matched']} (ключ, границы, число алертов и из них алертов окон, серьёзность, цели).",
        "",
        "## Действия",
        "",
        f"Сравнено у совпавших инцидентов {a['compared']}, совпало {a['matched']}.",
        "",
        "## Расхождения",
        "",
    ]
    if not report["divergences"]:
        lines.append("Нет.")
    else:
        lines.append(
            "По причинам: "
            + ", ".join(f"{k} — {n}" for k, n in report["divergences_by_reason"].items())
        )
        lines.append("")
        for d in report["divergences"][:100]:
            what = d.get("text") or json.dumps(
                {k: d[k] for k in d if k not in ("reason",)}, ensure_ascii=False
            )
            lines.append(f"- `{d['reason']}` {what}")
    if v["examples"]:
        lines += ["", "## Примеры расхождения вердиктов", ""]
        for e in v["examples"]:
            lines.append(f"- `{e['flow_uid']}`: {json.dumps(e['diff'], ensure_ascii=False)}")
    return "\n".join(lines) + "\n"


def write_compare(report: dict, reports_dir: Path) -> tuple[Path, Path]:
    reports_dir = Path(reports_dir)
    name = f"stream_compare_{report['session']['run_id']}"
    md, js = reports_dir / f"{name}.md", reports_dir / f"{name}.json"
    with atomic_path(md) as tmp:
        tmp.write_text(render_compare(report), encoding="utf-8")
    with atomic_path(js) as tmp:
        tmp.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8"
        )
    return md, js
