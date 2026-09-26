"""Инкрементальная группировка = пакетная (FR-013, research R8) — property-тест и крайние случаи.

Одни и те же алерты группируются дважды: пакетной `group_alerts` (как `soc run`) и потоковой
`plan_batch` + `store.append_batch` пачками разного размера и в разном порядке прихода.
Итоговые инциденты обязаны совпасть по (ключ, first_seen, last_seen, n_alerts, severity,
targets) — идентификаторы не сравниваются: в потоке id даётся по первому ПРИШЕДШЕМУ алерту.
"""

import json
import random
from pathlib import Path

import polars as pl
import pytest

from mlsiem.soc import store
from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.soc.incidents import group_alerts
from mlsiem.stream.incremental import mark_late, plan_batch

REPO = Path(__file__).parents[2]
W = 900_000
LATENESS = 120_000
CLASSES = ("dos", "exploits", "fuzzers", "reconnaissance")


@pytest.fixture(scope="module")
def soc_cfg():
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    # Маленький порог повышения серьёзности — чтобы рост инцидента её реально менял
    return parse_soc_config({**raw, "severity": {**raw["severity"], "bump_at": 5}})


def _alert(uid: str, attacker: str, cls: str, t: int, *, dur: int = 1000, victim=None) -> dict:
    return {
        "flow_uid": uid,
        "capture_id": "c",
        "src_ip": attacker,
        "src_port": 40000,
        "dst_ip": victim or "149.171.126.10",
        "dst_port": 80,
        "protocol": 6,
        "first_seen_ms": t,
        "last_seen_ms": t + dur,
        "predicted_class": cls,
        "attack_score": 0.5 + (hash(uid) % 1000) / 2000,
        "attacker_ip": attacker,
        "victim_ip": victim or f"149.171.126.{10 + hash(uid) % 3}",
        "reversed": 0,
        "direction_rule": "default",
        "fired_experts": "classifier",
        "experts": None,
        "explanation": None,
    }


def _frame(rows: list[dict]) -> pl.DataFrame:
    return pl.DataFrame(rows, schema_overrides={"experts": pl.String, "explanation": pl.String})


def random_alerts(seed: int, n: int = 300) -> list[dict]:
    """Всплески алертов нескольких ключей с паузами и меньше, и больше окна."""
    rng = random.Random(seed)
    rows, t = [], 1_424_000_000_000
    for i in range(n):
        t += rng.choice([1_000, 30_000, 200_000, 800_000, 900_000, 950_000, 2_000_000])
        attacker = rng.choice(["175.45.176.1", "175.45.176.2", "175.45.176.3"])
        rows.append(
            _alert(f"f{i:04d}", attacker, rng.choice(CLASSES), t, dur=rng.choice([10, 5_000_000]))
        )
    return rows


def _session(tmp_path, name="s") -> tuple:
    conn = store.connect(tmp_path / f"{name}.db")
    store.init_db(conn)
    run = store.create_session(conn, f"replay:test:{name}", model_version="m1", summary={})
    return conn, run["run_id"]


def _signature(rows) -> list[tuple]:
    return sorted(
        (
            r["src_ip"],
            r["attack_class"],
            r["first_seen_ms"],
            r["last_seen_ms"],
            r["n_alerts"],
            r["severity"],
            json.loads(r["targets"]) if isinstance(r["targets"], str) else list(r["targets"]),
        )
        for r in rows
    )


def batch_result(alerts: list[dict], soc_cfg) -> list[tuple]:
    _, incidents = group_alerts(
        _frame(alerts),
        window_ms=soc_cfg.window_ms,
        run_id="batch",
        severity_base=soc_cfg.severity_base,
        bump_at=soc_cfg.bump_at,
    )
    return _signature(incidents.to_dicts())


def stream_result(conn, run_id, arrivals: list[dict], sizes: int, soc_cfg) -> list[tuple]:
    max_seen = None
    for i in range(0, len(arrivals), sizes):
        chunk = arrivals[i : i + sizes]
        flags, max_seen_new = mark_late([a["first_seen_ms"] for a in chunk], max_seen, LATENESS)
        frame = _frame(chunk).with_columns(pl.Series("late", [int(f) for f in flags]))
        plan = plan_batch(conn, run_id, frame, soc_cfg, lateness_ms=LATENESS, max_seen_ms=max_seen)
        store.append_batch(conn, [plan], offsets={})
        max_seen = max_seen_new
    rows = conn.execute(
        "SELECT * FROM incidents WHERE run_id = ? AND merged_into IS NULL", (run_id,)
    ).fetchall()
    # Каждый алерт — ровно в одном непоглощённом инциденте, счётчики сходятся с алертами
    n = conn.execute("SELECT COUNT(*) FROM alerts WHERE run_id = ?", (run_id,)).fetchone()[0]
    assert n == len({a["flow_uid"] for a in arrivals})
    assert sum(r["n_alerts"] for r in rows) == n
    return _signature([dict(r) for r in rows])


@pytest.mark.parametrize("seed", [0, 1, 2])
@pytest.mark.parametrize("size", [1, 7, 100, 10_000])
def test_in_order_equals_batch(tmp_path, soc_cfg, seed, size):
    alerts = random_alerts(seed)
    conn, run_id = _session(tmp_path)
    assert stream_result(conn, run_id, alerts, size, soc_cfg) == batch_result(alerts, soc_cfg)


@pytest.mark.parametrize("seed", [0, 3])
@pytest.mark.parametrize("size", [1, 7, 100])
def test_shuffled_within_lateness_equals_batch(tmp_path, soc_cfg, seed, size):
    alerts = random_alerts(seed)
    rng = random.Random(seed + 100)
    arrivals = sorted(alerts, key=lambda a: a["first_seen_ms"] + rng.randint(0, LATENESS))
    conn, run_id = _session(tmp_path)
    got = stream_result(conn, run_id, arrivals, size, soc_cfg)
    assert got == batch_result(alerts, soc_cfg)
    # в пределах допустимого опоздания — ни одного флага late
    assert conn.execute("SELECT SUM(late) FROM alerts").fetchone()[0] == 0


@pytest.mark.parametrize("size", [1, 50])
def test_fully_shuffled_still_equals_batch(tmp_path, soc_cfg, size):
    """Слияние делает результат независимым даже от сильного опоздания — оно лишь помечается."""
    alerts = random_alerts(5, n=200)
    arrivals = alerts[:]
    random.Random(9).shuffle(arrivals)
    conn, run_id = _session(tmp_path)
    assert stream_result(conn, run_id, arrivals, size, soc_cfg) == batch_result(alerts, soc_cfg)
    assert conn.execute("SELECT SUM(late) FROM alerts").fetchone()[0] > 0


def test_on_chain_alerts(tmp_path, soc_cfg, synthetic_split, tiny_detector):
    """Алерты настоящей цепочки на синтетике (как `soc run`), пачками по 37."""
    from mlsiem.detect.ensemble import load_model
    from mlsiem.soc.run import load_split_flows
    from mlsiem.soc.verdicts import alerts_from_verdicts, compute_verdicts

    model = load_model(tiny_detector)
    flows, _ = load_split_flows("unsw_time", "test", model, data_dir=synthetic_split)
    flows = flows.sort("flow_uid")
    alerts = alerts_from_verdicts(compute_verdicts(model, flows), flows).drop("true_label")
    assert alerts.height > 20
    rows = alerts.sort(["first_seen_ms", "flow_uid"]).to_dicts()
    conn, run_id = _session(tmp_path)
    got = stream_result(conn, run_id, rows, 37, soc_cfg)
    assert got == batch_result(rows, soc_cfg)


# ---------------------------------------------------------------- крайние случаи


def _apply(conn, run_id, soc_cfg, rows):
    plan = plan_batch(conn, run_id, _frame(rows), soc_cfg, lateness_ms=LATENESS)
    store.append_batch(conn, [plan], offsets={})
    return plan


def _open(conn, run_id):
    return conn.execute(
        "SELECT * FROM incidents WHERE run_id = ? AND merged_into IS NULL ORDER BY first_seen_ms",
        (run_id,),
    ).fetchall()


A = "175.45.176.1"


def test_exactly_window_is_same_incident(tmp_path, soc_cfg):
    conn, run_id = _session(tmp_path)
    _apply(conn, run_id, soc_cfg, [_alert("a", A, "dos", 0)])
    _apply(conn, run_id, soc_cfg, [_alert("b", A, "dos", W)])
    _apply(conn, run_id, soc_cfg, [_alert("c", A, "dos", 2 * W + 1)])
    assert [r["n_alerts"] for r in _open(conn, run_id)] == [2, 1]


def test_window_measured_from_alert_start_not_flow_end(tmp_path, soc_cfg):
    conn, run_id = _session(tmp_path)
    _apply(conn, run_id, soc_cfg, [_alert("long", A, "dos", 0, dur=10 * W)])
    _apply(conn, run_id, soc_cfg, [_alert("next", A, "dos", W + 1)])
    rows = _open(conn, run_id)
    assert len(rows) == 2
    assert rows[0]["last_seen_ms"] == 10 * W and rows[0]["last_alert_start_ms"] == 0


def test_late_alert_merges_later_into_earlier(tmp_path, soc_cfg):
    conn, run_id = _session(tmp_path)
    _apply(conn, run_id, soc_cfg, [_alert("a", A, "dos", 0), _alert("b", A, "dos", 2 * W)])
    first, second = _open(conn, run_id)
    plan = _apply(conn, run_id, soc_cfg, [_alert("mid", A, "dos", W)])
    assert [(m.absorbed_id, m.into_id) for m in plan.merges] == [
        (second["incident_id"], first["incident_id"])
    ]
    (only,) = _open(conn, run_id)
    assert only["incident_id"] == first["incident_id"] and only["n_alerts"] == 3
    absorbed = store.get_incident(conn, second["incident_id"])
    assert absorbed["merged_into"] == first["incident_id"] and absorbed["n_alerts"] == 0
    assert absorbed["action"]["state"] == "rejected"
    assert absorbed["action"]["decided_by"] == "system"
    assert "объединён" in absorbed["action"]["comment"]
    events = [e["event"] for e in store.incident_audit(conn, second["incident_id"])]
    assert "incident_merged" in events


def test_merge_blocked_by_decision(tmp_path, soc_cfg):
    conn, run_id = _session(tmp_path)
    _apply(conn, run_id, soc_cfg, [_alert("a", A, "dos", 0), _alert("b", A, "dos", 2 * W)])
    first, second = _open(conn, run_id)
    store.change_status(conn, second["incident_id"], "vlad", "in_progress", None, None, 1)
    _apply(conn, run_id, soc_cfg, [_alert("mid", A, "dos", W)])
    rows = _open(conn, run_id)
    assert len(rows) == 2
    assert rows[0]["n_alerts"] == 2  # алерт ушёл в ранний
    assert store.get_incident(conn, second["incident_id"])["status"] == "in_progress"
    div = store.divergences(conn, run_id)
    assert [d["kind"] for d in div] == ["merge_blocked_by_decision"]
    assert div[0]["other_incident_id"] == second["incident_id"]


def test_late_flag(tmp_path, soc_cfg):
    conn, run_id = _session(tmp_path)
    plan = plan_batch(
        conn,
        run_id,
        _frame([_alert("new", A, "dos", 10 * LATENESS), _alert("old", A, "dos", 0)]),
        soc_cfg,
        lateness_ms=LATENESS,
    )
    late = {a["flow_uid"]: a["late"] for a in plan.alerts}
    assert late == {"new": 0, "old": 1}
    assert plan.n_late == 1
    store.append_batch(conn, [plan], offsets={})
    assert conn.execute("SELECT late FROM alerts WHERE flow_uid = 'old'").fetchone()[0] == 1
    assert any(d["kind"] == "late_beyond_allowed" for d in store.divergences(conn, run_id))
