"""Мета-слой: блоки времени и out-of-fold без утечек, кандидаты, итоговый класс, объяснение."""

import numpy as np
import pytest

from mlsiem.detect import meta
from mlsiem.detect.meta import (
    StackModel,
    explain,
    final_class,
    meta_input,
    oof_predict,
    rule_scores,
    time_blocks,
)

CLASSES = ["benign", "dos", "exploits"]


# ---------------------------------------------------------------- блоки времени и OOF (T017)


def test_blocks_are_sequential_and_disjoint():
    t = np.arange(0, 1_000_000, 1000)  # потоки раз в секунду
    b = time_blocks(t, 4, gap_ms=5000)
    assert b.k == 4
    assert sorted(set(b.block.tolist())) == [0, 1, 2, 3]
    # последовательные: номер блока не убывает со временем
    assert (np.diff(b.block[np.argsort(t)]) >= 0).all()
    sizes = np.bincount(b.block)
    assert sizes.max() - sizes.min() <= 1


def test_gap_excluded_from_neighbour_training():
    t = np.arange(0, 1_000_000, 1000)
    gap = 5000
    b = time_blocks(t, 4, gap_ms=gap)
    for j, (train, pred) in enumerate(b.folds()):
        assert not set(train) & set(pred)
        assert (b.block[pred] == j).all()
        edges = [b.boundaries[e] for e in (j - 1, j) if 0 <= e < len(b.boundaries)]
        for edge in edges:
            assert (np.abs(t[train] - edge) >= gap).all()
        # потоки у границы — не в обучении, но и не потеряны: они в своём блоке
        near = np.flatnonzero(np.min([np.abs(t - e) for e in edges], axis=0) < gap)
        assert not set(near) & set(train)


def test_each_flow_predicted_once_by_model_not_seeing_it():
    rng = np.random.default_rng(0)
    t = np.sort(rng.integers(0, 10_000_000, size=600))
    X = rng.normal(size=(600, 3))
    y = rng.choice(CLASSES, size=600)
    b = time_blocks(t, 5, gap_ms=10_000)
    seen_by_model: list[set] = []
    calls = []

    def spy_fit(X_tr, y_tr):
        # «шпион» запоминает, на каких строках учился (по значению первого признака)
        trained = set(X_tr[:, 0].tolist())
        seen_by_model.append(trained)

        def predict(X_pr):
            calls.append(set(X_pr[:, 0].tolist()))
            assert not trained & set(X_pr[:, 0].tolist()), "модель предсказывает то, на чём училась"
            return np.full((len(X_pr), 3), len(seen_by_model), dtype=float)

        return predict

    out = oof_predict(spy_fit, X, y, b)
    assert len(seen_by_model) == 5
    # каждая строка получила предсказание ровно от одной модели
    all_pred = [x for c in calls for x in c]
    assert len(all_pred) == len(set(all_pred)) == 600
    assert set(np.unique(out[:, 0])) == {1, 2, 3, 4, 5}


def test_blocks_errors():
    with pytest.raises(ValueError, match="хотя бы 2"):
        time_blocks(np.arange(10), 1, 0)
    with pytest.raises(ValueError, match="меньше"):
        time_blocks(np.arange(3), 5, 0)
    with pytest.raises(ValueError, match="пустой блок"):
        time_blocks(np.zeros(100, dtype=int), 4, 0)


# ---------------------------------------------------------------- кандидаты (T018)


def _P(rows):
    return np.array(rows, dtype=float)


def test_any_fired_is_any_expert_on_its_threshold():
    rng = np.random.default_rng(1)
    P = rng.dirichlet([1, 1, 1], size=500)
    a = rng.random(500)
    thr_c, thr_a = 0.8, 0.95
    s = rule_scores("any_fired", P, CLASSES, a, thr_c, thr_a)
    fired = ((1 - P[:, 0]) >= thr_c) | (a >= thr_a)
    assert ((s >= meta.ANY_FIRED_THRESHOLD) == fired).all()
    # скор монотонен по каждому эксперту: максимум двух скоров на общей шкале
    assert s.min() >= 0 and s.max() <= 1


def test_mean_score():
    P = _P([[0.2, 0.5, 0.3], [0.9, 0.05, 0.05]])
    a = np.array([0.6, 0.1])
    s = rule_scores("mean_score", P, CLASSES, a, 0.5, 0.9)
    assert s == pytest.approx([(0.8 + 0.6) / 2, (0.1 + 0.1) / 2])


def test_rule_proba_consistent_with_score():
    P = _P([[0.2, 0.5, 0.3], [0.9, 0.08, 0.02]])
    a = np.array([0.99, 0.2])
    proba = meta.meta_proba("mean_score", P, CLASSES, a, 0.5, 0.9)
    s = rule_scores("mean_score", P, CLASSES, a, 0.5, 0.9)
    assert np.allclose(1 - proba[:, 0], s)
    assert np.allclose(proba.sum(axis=1), 1)
    # доли атак между собой — как у классификатора
    assert proba[0, 1] / proba[0, 2] == pytest.approx(0.5 / 0.3)


def test_stack_outputs_all_classes_summing_to_one():
    rng = np.random.default_rng(2)
    P = rng.dirichlet([3, 1, 1], size=400)
    a = rng.random(400)
    y = np.where(a > 0.8, "dos", np.where(P[:, 2] > 0.4, "exploits", "benign"))
    classes = [*CLASSES, "worms"]  # класса worms в данных нет — вероятность 0
    P4 = np.hstack([P, np.zeros((400, 1))])
    stack = StackModel(classes, seed=0).fit(meta_input(P4, a), y)
    out = stack.predict_proba(meta_input(P4, a))
    assert out.shape == (400, 4)
    assert np.allclose(out.sum(axis=1), 1)
    assert (out[:, 3] == 0).all()


def test_meta_input_only_expert_outputs():
    P = _P([[0.2, 0.5, 0.3]])
    a = np.array([0.7])
    X = meta_input(P, a)
    assert X.shape == (1, 4)  # 3 вероятности + перцентиль — и ничего из признаков потока
    assert X[0, -1] == 0.7
    assert X[0, 0] == pytest.approx(np.log(0.2 + 1e-6))


def test_final_class_rules():
    proba = _P([[0.1, 0.2, 0.7], [0.1, 0.6, 0.3], [0.9, 0.05, 0.05], [0.2, 0.5, 0.3]])
    is_alert = np.array([True, True, False, True])
    clf_fired = np.array([True, False, False, False])
    an_fired = np.array([True, True, True, False])
    cls = final_class(proba, CLASSES, is_alert, clf_fired, an_fired)
    assert cls.tolist() == ["exploits", "anomaly", "benign", "dos"]
    # без эксперта аномалий класса anomaly не бывает
    assert final_class(proba, CLASSES, is_alert, clf_fired, None).tolist() == [
        "exploits",
        "dos",
        "benign",
        "dos",
    ]


def test_explanations_four_cases():
    common = {"clf_class": "exploits", "clf_score": 0.99, "clf_threshold": 0.986}
    both = explain(
        **common,
        clf_fired=True,
        anomaly_score=0.998,
        anomaly_threshold=0.995,
        anomaly_fired=True,
        meta_score=0.97,
        meta_threshold=0.9,
    )
    assert both == (
        "сработали классификатор (exploits, 0.990 ≥ 0.986) и детектор аномалий "
        "(99.8-й перцентиль нормы ≥ 99.5)"
    )
    only_a = explain(
        **{**common, "clf_score": 0.5},
        clf_fired=False,
        anomaly_score=0.999,
        anomaly_threshold=0.995,
        anomaly_fired=True,
        meta_score=0.9,
        meta_threshold=0.9,
    )
    assert only_a.startswith("сработал только детектор аномалий")
    assert "класс атаки неизвестен" in only_a
    only_c = explain(
        **common,
        clf_fired=True,
        anomaly_score=0.4,
        anomaly_threshold=0.995,
        anomaly_fired=False,
        meta_score=0.95,
        meta_threshold=0.9,
    )
    assert only_c.startswith("сработал только классификатор")
    none = explain(
        **{**common, "clf_score": 0.9},
        clf_fired=False,
        anomaly_score=0.9,
        anomaly_threshold=0.995,
        anomaly_fired=False,
        meta_score=0.93,
        meta_threshold=0.91,
    )
    assert none == (
        "ни один эксперт не превысил свой порог, алерт поднял мета-слой (скор 0.930 ≥ 0.910)"
    )
    # детерминизм
    assert none == explain(
        **{**common, "clf_score": 0.9},
        clf_fired=False,
        anomaly_score=0.9,
        anomaly_threshold=0.995,
        anomaly_fired=False,
        meta_score=0.93,
        meta_threshold=0.91,
    )
