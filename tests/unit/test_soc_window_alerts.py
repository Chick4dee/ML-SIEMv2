"""Алерты окон (фича 007, R12, data-model «Алерт окна») и их группировка вместе с алертами
потоков: один инцидент на (атакующий, класс), алерт окна = 1 в n_alerts."""

import json

import polars as pl
import pytest

from mlsiem.detect import windows as W
from mlsiem.detect.windows_expert import load_window_expert
from mlsiem.soc.direction import sides
from mlsiem.soc.incidents import group_alerts
from mlsiem.soc.verdicts import (
    alerts_from_window_verdicts,
    window_flow_context,
    with_flow_kind,
)


@pytest.fixture(scope="module")
def setup(tiny_windows, synthetic_flows):
    ex = load_window_expert(tiny_windows, force=True)
    flows = pl.concat(list(synthetic_flows.values()))
    side = sides(flows, "auto").select(W.SIDE_COLUMNS)
    res = ex.verdicts(flows, side)
    # Скор потока для таблицы подозрительных потоков: здесь — просто число по flow_uid
    fv = flows.select("flow_uid").with_columns(
        (pl.int_range(pl.len()) / pl.len()).alias("attack_score")
    )
    ctx = window_flow_context(flows, side, fv)
    return ex, flows, res, alerts_from_window_verdicts(res, ctx, ex)


def test_rows_by_data_model(setup):
    ex, flows, res, alerts = setup
    assert alerts.height == int(res.verdicts["is_alert"].sum()) > 0
    a = alerts.row(0, named=True)
    win = res.windows.filter(pl.col("window_id") == a["flow_uid"]).row(0, named=True)
    assert a["src_ip"] == a["attacker_ip"] == win["attacker_ip"]
    assert a["dst_ip"] == a["victim_ip"] == win["targets"][0]["ip"]
    assert a["src_port"] is None and a["dst_port"] is None and a["protocol"] is None
    assert a["first_seen_ms"] == win["first_seen_ms"] and a["last_seen_ms"] == win["last_seen_ms"]
    assert a["fired_experts"] == "windows" and a["alert_kind"] == "window"
    experts = json.loads(a["experts"])
    assert experts["windows"]["fired"] and experts["windows"]["threshold"] == ex.threshold
    info = json.loads(a["window_info"])
    assert info["window_id"] == a["flow_uid"] and info["n_flows"] == win["n_flows"]
    assert len(info["top_flows"]) == min(20, win["n_flows"])
    scores = [f["flow_score"] for f in info["top_flows"]]
    assert scores == sorted(scores, reverse=True)
    assert 0 < len(info["top_features"]) <= 5
    assert "эксперт окон lgbm" in a["explanation"]


def test_grouped_with_flow_alerts(setup):
    """Алерт окна и алерты потоков того же атакующего и класса — один инцидент."""
    ex, flows, res, walerts = setup
    w = walerts.row(0, named=True)
    flow_alert = {
        "flow_uid": "f-x",
        "capture_id": "c",
        "src_ip": w["attacker_ip"],
        "src_port": 40000,
        "dst_ip": "9.9.9.9",
        "dst_port": 80,
        "protocol": 6,
        "first_seen_ms": w["first_seen_ms"] + 1,
        "last_seen_ms": w["first_seen_ms"] + 2,
        "predicted_class": w["predicted_class"],
        "attack_score": 0.99,
        "attacker_ip": w["attacker_ip"],
        "victim_ip": "9.9.9.9",
        "reversed": 0,
        "fired_experts": "classifier",
        "experts": None,
        "explanation": None,
    }
    other = {**flow_alert, "flow_uid": "f-y", "predicted_class": "__другой_класс__"}
    flow_alerts = with_flow_kind(pl.DataFrame([flow_alert, other]))
    both = pl.concat([flow_alerts, walerts.head(1)], how="diagonal_relaxed")
    base = dict.fromkeys([w["predicted_class"], "__другой_класс__"], "low")
    out, incidents = group_alerts(
        both, window_ms=900_000, run_id="r", severity_base=base, bump_at=100
    )
    same = out.filter(pl.col("predicted_class") == w["predicted_class"])
    assert same["incident_id"].n_unique() == 1
    inc = incidents.filter(pl.col("attack_class") == w["predicted_class"]).row(0, named=True)
    assert inc["n_alerts"] == 2  # алерт окна считается одним алертом
    assert incidents.height == 2  # разные классы — разные инциденты
