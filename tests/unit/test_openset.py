"""Способы оценки неизвестного по логитам (фича 008, US5, R12): ручной расчёт, калибровка, "
"насыщение."""

from __future__ import annotations

import math

import numpy as np
import pytest
from scipy.special import softmax

from mlsiem.detect import openset
from mlsiem.detect.candidates import build_candidate

CLASSES = ["benign", "dos", "recon"]


def test_оценки_совпадают_с_ручным_расчётом():
    z = np.array([[2.0, 1.0, 0.0]])
    e = math.e
    assert openset.attack_vs_normal(z, CLASSES)[0] == pytest.approx(math.log(e + 1) - 2)
    assert openset.msp(z)[0] == pytest.approx(math.log(e + 1) - math.log(e * e + e + 1))
    assert openset.energy(z)[0] == pytest.approx(-math.log(e * e + e + 1))


def test_равные_логиты():
    z = np.zeros((1, 3))
    assert openset.attack_vs_normal(z, CLASSES)[0] == pytest.approx(math.log(2))
    assert openset.msp(z)[0] == pytest.approx(math.log(2 / 3))
    assert openset.energy(z)[0] == pytest.approx(-math.log(3))


def test_msp_не_насыщается_там_где_вероятности_насыщаются():
    sure, surer = np.array([[50.0, 0.0, 0.0]]), np.array([[40.0, 0.0, 0.0]])
    # через вероятности обе уверенные точки неотличимы: 1 − max p = 0 в обоих случаях
    assert (1 - softmax(sure, axis=1).max()) == (1 - softmax(surer, axis=1).max()) == 0.0
    # через логиты разница сохраняется
    assert openset.msp(sure)[0] < openset.msp(surer)[0] < 0
    assert np.isfinite(openset.msp(sure)).all()


def test_объединение_по_p_значениям_калибровано():
    rng = np.random.default_rng(0)

    def norm(n):
        return {
            "attack_vs_normal": rng.normal(0, 1, n),
            "msp": rng.normal(0, 1, n),
            "energy": rng.normal(0, 1, n),
        }

    cal = openset.NormalCalibrator().fit(norm(40_000))
    for alpha in (0.01, 0.05):
        thr = cal.threshold(alpha)
        share = float((cal.combined(norm(40_000)) > thr).mean())
        assert abs(share - alpha) < 0.01, (alpha, share)  # на свежей норме доля тревог ≈ α


def test_объединение_ловит_то_что_необычно_хотя_бы_по_одной_оценке():
    rng = np.random.default_rng(1)
    val = {k: rng.normal(0, 1, 20_000) for k in openset.SCORES}
    cal = openset.NormalCalibrator().fit(val)
    thr, _ = openset.thresholds_for(val, (0.01,))
    odd_only_energy = {
        "attack_vs_normal": np.zeros(500),
        "msp": np.zeros(500),
        "energy": np.full(500, 6.0),
    }
    rec = openset.recall_by_method(odd_only_energy, cal, thr, (0.01,))
    assert rec["energy"][0.01] == 1.0 and rec["combined"][0.01] == 1.0
    assert rec["msp"][0.01] == 0.0 and rec["attack_vs_normal"][0.01] == 0.0


def test_ecdf_монотонна_и_в_границах():
    cal = openset.NormalCalibrator().fit({"a": np.arange(100.0)})
    v = cal.ecdf("a", np.array([-5.0, 0.0, 49.5, 99.0, 1000.0]))
    assert (np.diff(v) >= 0).all() and v[0] == 0.0 and v[-1] == 1.0


def test_логиты_бустинга_согласуются_с_предсказанием_модели():
    rng = np.random.default_rng(2)
    X = rng.normal(0, 1, (900, 4))
    y = np.array(CLASSES)[np.argmax(X[:, :3], axis=1)]
    model = build_candidate(
        "lgbm", {"n_estimators": 30, "num_leaves": 7, "min_child_samples": 5}, 0
    )
    model.fit(X, y)
    z = openset.raw_logits(model, X)
    classes = list(model.classes_)
    assert z.shape == (900, 3)
    assert (np.array(classes)[z.argmax(axis=1)] == model.predict(X)).all()
    assert np.allclose(softmax(z, axis=1), model.predict_proba(X), atol=1e-6)
    scores = openset.all_scores(z, classes)
    assert set(scores) == set(openset.SCORES) and all(len(v) == 900 for v in scores.values())


def test_двухклассовый_бустинг_даёт_пару_логитов_и_конечные_оценки():
    rng = np.random.default_rng(3)
    X = rng.normal(0, 1, (600, 4))
    y = np.where(X[:, 0] > 0, "dos", "benign")
    model = build_candidate(
        "lgbm", {"n_estimators": 30, "num_leaves": 7, "min_child_samples": 5}, 0
    )
    model.fit(X, y)
    z = openset.raw_logits(model, X)
    classes = list(model.classes_)
    assert z.shape == (600, 2)
    assert np.allclose(softmax(z, axis=1), model.predict_proba(X), atol=1e-6)
    scores = openset.all_scores(z, classes)
    assert all(np.isfinite(v).all() for v in scores.values())


def test_плато_из_ничьих_у_нормы_не_ломает_порог():
    # 3% нормы — одинаковые потоки на самом верху (одиночные пакеты); порог 1% попадает в плато
    rng = np.random.default_rng(4)
    base = rng.normal(0, 1, 9_700)
    val = {k: np.concatenate([base, np.full(300, 10.0)]) for k in openset.SCORES}
    thr, cal = openset.thresholds_for(val, (0.01,))
    above_plateau = {k: np.full(100, 20.0) for k in openset.SCORES}  # атака выше всей нормы
    on_plateau = {k: np.full(100, 10.0) for k in openset.SCORES}  # неотличима от плато нормы
    assert openset.recall_by_method(above_plateau, cal, thr, (0.01,))["combined"][0.01] == 1.0
    assert openset.recall_by_method(on_plateau, cal, thr, (0.01,))["combined"][0.01] == 0.0
    # доля ложных на самой норме не превышает заявленную
    norm_rec = openset.recall_by_method(val, cal, thr, (0.01,))
    assert all(r[0.01] <= 0.01 + 1e-9 for r in norm_rec.values())
