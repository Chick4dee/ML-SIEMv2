"""Кандидаты-детекторы и правило выбора победителя (research R1, R4, R7)."""

import numpy as np
import pytest
from lightgbm import LGBMClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from mlsiem.detect.candidates import LGBM_THREADS, build_candidate, select_winner


def test_logreg_pipeline():
    pipe = build_candidate("logreg", {"C": 0.5, "max_iter": 200}, seed=7)
    assert isinstance(pipe, Pipeline)
    steps = [type(s) for _, s in pipe.steps]
    assert steps == [FunctionTransformer, StandardScaler, LogisticRegression]
    model = pipe.steps[-1][1]
    assert model.solver == "lbfgs"
    assert model.random_state == 7
    assert model.C == 0.5


def test_lgbm_pipeline_deterministic_params():
    pipe = build_candidate("lgbm", {"n_estimators": 10}, seed=3)
    assert len(pipe.steps) == 1
    model = pipe.steps[0][1]
    assert isinstance(model, LGBMClassifier)
    params = model.get_params()
    assert params["deterministic"] is True
    assert params["force_row_wise"] is True
    assert params["num_threads"] == LGBM_THREADS
    assert params["random_state"] == 3


def test_lgbm_same_seed_same_result():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(300, 5)).astype(np.float32)
    y = np.where(X[:, 0] > 0.3, "dos", "benign")
    p1 = build_candidate("lgbm", {"n_estimators": 20}, seed=1).fit(X, y).predict_proba(X)
    p2 = build_candidate("lgbm", {"n_estimators": 20}, seed=1).fit(X, y).predict_proba(X)
    np.testing.assert_array_equal(p1, p2)


def test_unknown_candidate():
    with pytest.raises(ValueError, match="mlp"):
        build_candidate("mlp", {}, seed=0)


def test_winner_when_gain_enough():
    res = {"logreg": {"macro_pr_auc_val": 0.60}, "lgbm": {"macro_pr_auc_val": 0.62}}
    winner, text = select_winner(res, min_gain=0.01)
    assert winner == "lgbm"
    assert "lgbm" in text


def test_baseline_when_gain_small():
    res = {"logreg": {"macro_pr_auc_val": 0.60}, "lgbm": {"macro_pr_auc_val": 0.605}}
    winner, text = select_winner(res, min_gain=0.01)
    assert winner == "logreg"
    assert "прост" in text


def test_baseline_when_best():
    res = {"logreg": {"macro_pr_auc_val": 0.7}, "lgbm": {"macro_pr_auc_val": 0.6}}
    assert select_winner(res, min_gain=0.01)[0] == "logreg"


def test_selection_ignores_test():
    base = {"logreg": {"macro_pr_auc_val": 0.60}, "lgbm": {"macro_pr_auc_val": 0.70}}
    with_test = {
        "logreg": {"macro_pr_auc_val": 0.60, "macro_pr_auc_test": 0.99},
        "lgbm": {"macro_pr_auc_val": 0.70, "macro_pr_auc_test": 0.01},
    }
    assert select_winner(base, min_gain=0.01) == select_winner(with_test, min_gain=0.01)
