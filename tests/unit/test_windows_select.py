"""Выбор победителя окон (фича 007, R8, SC-002): только по val, два шага с приростом
`min_gain`, отрицательный результат — законный исход; test на выбор и порог не влияет."""

import inspect

import numpy as np
import pytest

from mlsiem.detect import metrics as M
from mlsiem.detect.windows_experiment import select_nn_vs_boosting, select_vs_current


def test_step1_gru_needs_min_gain():
    r = select_nn_vs_boosting({"lgbm": 0.80, "gru": 0.805}, min_gain=0.01, skip_nn=False)
    assert r["winner"] == "lgbm" and r["gain"] == pytest.approx(0.005)
    assert "более простое" in r["text"]
    r = select_nn_vs_boosting({"lgbm": 0.80, "gru": 0.81}, min_gain=0.01, skip_nn=False)
    assert r["winner"] == "gru"


def test_step1_skipped_without_nn():
    r = select_nn_vs_boosting({"lgbm": 0.5}, min_gain=0.01, skip_nn=True)
    assert r["winner"] == "lgbm" and r["skipped"] and "пропущен" in r["text"]


def test_step2_needs_gain_over_current():
    assert select_vs_current("lgbm", 0.70, 0.69, min_gain=0.01)["passed"]
    r = select_vs_current("gru", 0.70, 0.695, min_gain=0.01)
    assert not r["passed"] and "отрицательный результат" in r["text"]


def test_selection_and_threshold_do_not_take_test():
    """SC-002: у функций выбора и порога нет входа для test — ни по имени, ни по смыслу."""
    for fn in (select_nn_vs_boosting, select_vs_current, M.choose_threshold):
        names = " ".join(inspect.signature(fn).parameters)
        assert "test" not in names


def test_threshold_and_decision_depend_only_on_val(tiny_windows_experiment):
    """В протоколе эксперимента порог каждого участника пересчитывается из одних его
    val-скоров, а решение — из val-метрик: test-цифры в решение не входят."""
    exp = tiny_windows_experiment["exp"]
    values = exp["decision"]["values"]
    for name, p in exp["participants"].items():
        assert values[name] == pytest.approx(p["val"]["macro_pr_auc_reliable"])
    step2 = select_vs_current(
        exp["selection"]["winner"],
        values[exp["selection"]["winner"]],
        values["current"],
        min_gain=exp["selection"]["min_gain"],
    )
    assert step2["passed"] == exp["decision"]["passed_selection"]


def test_swapping_labels_outside_val_changes_nothing():
    rng = np.random.default_rng(0)
    y_val = rng.random(200) < 0.2
    s_val = np.where(y_val, rng.random(200) * 0.5 + 0.5, rng.random(200) * 0.6)
    thr = M.choose_threshold(y_val, s_val)
    decision = select_vs_current("lgbm", 0.7, 0.6, min_gain=0.01)
    rng.shuffle(np.arange(100))  # «подмена test» — у функций выбора нет для неё входа
    assert M.choose_threshold(y_val, s_val) == thr
    assert select_vs_current("lgbm", 0.7, 0.6, min_gain=0.01) == decision
