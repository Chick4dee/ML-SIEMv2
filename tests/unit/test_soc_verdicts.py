"""Вердикты и алерты: поля, порог, класс алерта, контекст, метка не подаётся в детектор."""

import numpy as np
import polars as pl
import pytest

from mlsiem.detect.artifact import load_detector
from mlsiem.soc.verdicts import alerts_from_verdicts, compute_verdicts


@pytest.fixture(scope="module")
def flows(synthetic_flows):
    return pl.concat(list(synthetic_flows.values()))


@pytest.fixture(scope="module")
def detector(tiny_detector):
    return load_detector(tiny_detector)


def test_verdict_fields(detector, flows):
    v = compute_verdicts(detector, flows)
    assert v.height == flows.height
    for col in ("flow_uid", "predicted_class", "attack_score", "is_alert", "true_label"):
        assert col in v.columns
    for c in detector.classes:
        assert f"p_{c}" in v.columns
    assert v["attack_score"].is_between(0, 1).all()


def test_alert_iff_score_above_threshold(detector, flows):
    v = compute_verdicts(detector, flows)
    assert (v["is_alert"] == (v["attack_score"] >= detector.threshold)).all()
    assert v["is_alert"].sum() > 0


def test_alert_class_is_top_attack(detector, flows):
    v = compute_verdicts(detector, flows)
    attack = [c for c in detector.classes if c != "benign"]
    probs = v.select([f"p_{c}" for c in attack]).to_numpy()
    top = np.array(attack)[probs.argmax(axis=1)]
    alerts = v["is_alert"].to_numpy()
    assert (v["predicted_class"].to_numpy()[alerts] == top[alerts]).all()
    assert (v["predicted_class"].to_numpy()[~alerts] == "benign").all()


def test_label_not_used_by_detector(detector, flows):
    v1 = compute_verdicts(detector, flows)
    v2 = compute_verdicts(detector, flows.with_columns(pl.lit("worms").alias("label")))
    assert v1.drop("true_label").equals(v2.drop("true_label"))
    v3 = compute_verdicts(detector, flows.drop("label"))
    assert "true_label" not in v3.columns
    assert v1.drop("true_label").equals(v3)


def test_order_independent(detector, flows):
    v1 = compute_verdicts(detector, flows)
    v2 = compute_verdicts(detector, flows.sample(fraction=1.0, shuffle=True, seed=5))
    assert v1.equals(v2)


def test_alert_context(detector, flows):
    v = compute_verdicts(detector, flows)
    a = alerts_from_verdicts(v, flows)
    assert a.height == int(v["is_alert"].sum())
    for col in (
        "flow_uid",
        "capture_id",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "first_seen_ms",
        "last_seen_ms",
        "predicted_class",
        "attack_score",
    ):
        assert col in a.columns
    row = a.row(0, named=True)
    src = flows.filter(pl.col("flow_uid") == row["flow_uid"]).row(0, named=True)
    assert row["src_ip"] == src["src_ip"]
    assert row["first_seen_ms"] == src["bidirectional_first_seen_ms"]
    assert row["last_seen_ms"] == src["bidirectional_last_seen_ms"]


# ---------------------------------------------------------------- фича 004: эксперты


@pytest.fixture(scope="module")
def ensemble(tiny_ensemble):
    from mlsiem.detect.ensemble import load_model

    return load_model(tiny_ensemble)


def test_ensemble_alerts_have_experts(ensemble, flows):
    import json

    v = compute_verdicts(ensemble, flows)
    a = alerts_from_verdicts(v, flows, experts_meta=ensemble.experts_meta)
    assert a.height == int(v["is_alert"].sum()) > 0
    for row in a.iter_rows(named=True):
        experts = json.loads(row["experts"])
        assert set(experts) == {"classifier", "anomaly"}
        for name, e in experts.items():
            assert set(e) == {"score", "threshold", "fired"}
            assert e["threshold"] == ensemble.experts_meta[name]["threshold"]
        fired = sorted(n for n, e in experts.items() if e["fired"])
        assert row["fired_experts"] == ",".join(fired)  # "" — только мета-слой
        assert row["explanation"]
    # на синтетике обе ситуации встречаются: сработал хоть один эксперт и сработали оба
    assert (a["fired_experts"] != "").any()


def test_verdict_columns(ensemble, detector, flows):
    v = compute_verdicts(ensemble, flows)
    base = ["flow_uid", "predicted_class", "attack_score", "is_alert"]
    probs = [f"p_{c}" for c in ensemble.classes]
    experts = ["e_classifier_score", "e_classifier_fired", "e_anomaly_score", "e_anomaly_fired"]
    assert v.columns[: len(base) + len(probs)] == base + probs
    assert set(experts) <= set(v.columns)
    assert {"reversed", "true_label"} <= set(v.columns)
    # у детектора 002 эксперт один — classifier
    d = compute_verdicts(detector, flows)
    assert "e_classifier_score" in d.columns and "e_anomaly_score" not in d.columns
    a = alerts_from_verdicts(d, flows)
    assert set(a["fired_experts"].unique()) == {"classifier"}


def test_synthetic_flows_are_direct(detector, flows):
    # Синтетика после правки фикстуры (R15): инициатор всегда src — ответных потоков нет,
    # поэтому группировка на ней та же, что в 002
    v = compute_verdicts(detector, flows)
    assert not v["reversed"].any()
