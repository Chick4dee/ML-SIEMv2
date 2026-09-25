"""Общий интерфейс модели `load_model`: детектор 002 и ансамбль выглядят для цепочки одинаково.

Проверяем две вещи. Первая — детектор 002 через новый интерфейс даёт ровно те же вердикты,
что и раньше (FR-002, SC-005). Вторая — ансамбль отказывается работать при любой
несостыковке экспертов, и в сообщении названо, какой эксперт виноват (FR-014).
"""

import json
import shutil

import numpy as np
import polars as pl
import pytest

from mlsiem.detect.artifact import DetectorLoadError, load_detector
from mlsiem.detect.ensemble import LoadedModel, load_model
from mlsiem.detect.metrics import attack_score


@pytest.fixture(scope="module")
def flows(synthetic_flows):
    return pl.concat(list(synthetic_flows.values()))


# ---------------------------------------------------------------- детектор 002


def test_detector_through_interface(tiny_detector, flows):
    m = load_model(tiny_detector)
    det = load_detector(tiny_detector)
    assert isinstance(m, LoadedModel)
    assert m.kind == "detector" and m.selected is None
    assert m.version == det.version
    assert m.classes == det.classes and m.threshold == det.threshold
    assert m.features == det.features
    assert m.experts == ["classifier"]
    m.check_input("1.0.0", flows.columns)

    v = m.verdict_frame(flows)
    # Те же вердикты, что считал 002: скор 1 − P(benign), порог детектора, класс — лучшая атака
    srt = flows.sort("flow_uid")
    proba = det.predict_proba(srt)
    score = attack_score(proba, det.classes)
    assert np.allclose(v["attack_score"].to_numpy(), score)
    assert (v["is_alert"].to_numpy() == (score >= det.threshold)).all()
    for i, c in enumerate(det.classes):
        assert np.allclose(v[f"p_{c}"].to_numpy(), proba[:, i])
    attack = [c for c in det.classes if c != "benign"]
    top = np.array(attack)[proba[:, [det.classes.index(c) for c in attack]].argmax(axis=1)]
    alerts = v["is_alert"].to_numpy()
    assert (v["predicted_class"].to_numpy()[alerts] == top[alerts]).all()
    assert (v["predicted_class"].to_numpy()[~alerts] == "benign").all()
    # Эксперт один — классификатор; его колонки совпадают со скором
    assert np.allclose(v["e_classifier_score"].to_numpy(), score)
    assert (v["e_classifier_fired"] == v["is_alert"]).all()
    assert "e_anomaly_score" not in v.columns
    expl = v.filter(pl.col("is_alert"))["explanation"]
    assert expl.null_count() == 0 and expl.str.starts_with("сработал классификатор").all()
    assert v.filter(~pl.col("is_alert"))["explanation"].null_count() == v.height - int(alerts.sum())


def test_empty_dir_refused(tmp_path):
    with pytest.raises(DetectorLoadError, match="ensemble_card.json.*model_card.json"):
        load_model(tmp_path)


# ---------------------------------------------------------------- ансамбль


def test_ensemble_loads(tiny_ensemble, flows):
    m = load_model(tiny_ensemble)
    card = json.loads((tiny_ensemble / "ensemble_card.json").read_text(encoding="utf-8"))
    assert m.kind == "ensemble"
    assert m.version == card["ensemble_version"]
    assert m.selected == "ensemble:stack_logreg"
    assert m.experts == ["classifier", "anomaly"]
    assert m.output_classes[-1] == "anomaly"
    assert set(m.experts_meta) == {"classifier", "anomaly"}
    assert m.threshold == pytest.approx(card["threshold"])
    v = m.verdict_frame(flows)
    for col in ("e_classifier_score", "e_classifier_fired", "e_anomaly_score", "e_anomaly_fired"):
        assert col in v.columns
    assert v["attack_score"].is_between(0, 1).all()
    assert (v["is_alert"] == (v["attack_score"] >= m.threshold)).all()
    # «anomaly» — ровно там, где алерт есть, классификатор молчит, а аномалии сработали
    only_a = v["is_alert"] & ~v["e_classifier_fired"] & v["e_anomaly_fired"]
    assert (v.filter(only_a)["predicted_class"] == "anomaly").all()
    assert (v.filter(~only_a & v["is_alert"])["predicted_class"] != "anomaly").all()
    # Метка в модели не участвует
    v2 = m.verdict_frame(flows.with_columns(pl.lit("worms").alias("label")))
    assert v.drop("true_label").equals(v2.drop("true_label"))


def _copy_ensemble(src, tmp_path):
    """Копия ансамбля и его эксперта аномалий — чтобы ломать их без вреда для фикстуры."""
    card = json.loads((src / "ensemble_card.json").read_text(encoding="utf-8"))
    dst = tmp_path / "ensemble"
    shutil.copytree(src, dst)
    anomaly = next(e for e in card["experts"] if e["name"] == "anomaly")
    new_anomaly = tmp_path / "anomaly"
    shutil.copytree(anomaly["path"], new_anomaly)
    anomaly["path"] = new_anomaly.as_posix()
    (dst / "ensemble_card.json").write_text(json.dumps(card, ensure_ascii=False), encoding="utf-8")
    return dst, new_anomaly, card


def _write_card(dst, card):
    (dst / "ensemble_card.json").write_text(json.dumps(card, ensure_ascii=False), encoding="utf-8")


def test_refuses_missing_expert_model(tiny_ensemble, tmp_path):
    dst, anomaly, _ = _copy_ensemble(tiny_ensemble, tmp_path)
    (anomaly / "model.joblib").unlink()
    with pytest.raises(DetectorLoadError, match="эксперт anomaly"):
        load_model(dst)


def test_refuses_version_mismatch(tiny_ensemble, tmp_path):
    dst, _, card = _copy_ensemble(tiny_ensemble, tmp_path)
    next(e for e in card["experts"] if e["name"] == "anomaly")["version"] = "19990101-deadbeef"
    _write_card(dst, card)
    with pytest.raises(DetectorLoadError, match="anomaly.*другой версии"):
        load_model(dst)


def test_refuses_other_major_schema(tiny_ensemble, tmp_path):
    dst, _, card = _copy_ensemble(tiny_ensemble, tmp_path)
    card["schema_version"] = "2.0.0"
    _write_card(dst, card)
    with pytest.raises(DetectorLoadError, match="мажорные"):
        load_model(dst)


def test_refuses_missing_meta(tiny_ensemble, tmp_path):
    dst, _, _ = _copy_ensemble(tiny_ensemble, tmp_path)
    (dst / "meta.joblib").unlink()
    with pytest.raises(DetectorLoadError, match="meta.joblib"):
        load_model(dst)


def test_single_classifier_needs_no_meta(tiny_ensemble, tmp_path, flows, tiny_detector):
    dst, _, card = _copy_ensemble(tiny_ensemble, tmp_path)
    card["selected"] = "single:classifier"
    card["threshold"] = load_detector(tiny_detector).threshold
    _write_card(dst, card)
    (dst / "meta.joblib").unlink()
    m = load_model(dst)
    assert m.kind == "ensemble" and m.selected == "single:classifier"
    assert m.version == card["ensemble_version"]
    assert m.experts == ["classifier"]
    v = m.verdict_frame(flows)
    d = load_model(tiny_detector).verdict_frame(flows)
    assert v.equals(d)
