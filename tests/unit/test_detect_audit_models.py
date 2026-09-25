"""Аудит артефактов (research R6): зонд ловит «разделяющий в одиночку» признак, перестановочная
важность детерминирована и ставит его первым."""

import numpy as np

from mlsiem.detect.audit_models import (
    audit_expert,
    permutation_importance_score,
    single_feature_probe,
)

FEATURES = ["noise_a", "leak", "noise_b"]


def _data(seed=0, n=2000):
    rng = np.random.default_rng(seed)
    y = rng.random(n) < 0.1
    X = rng.normal(size=(n, 3))
    # «Артефакт генератора»: у всех атак признак leak отрицателен, у нормы — положителен
    X[:, 1] = np.where(y, -1.0, 1.0) * (1 + rng.random(n))
    return X, y


def test_probe_flags_leaking_feature():
    X, y = _data()
    probe = single_feature_probe(X, y, FEATURES, flag_at=0.9)
    assert probe[0]["feature"] == "leak"
    assert probe[0]["pr_auc"] >= 0.9 and probe[0]["flagged"]
    assert probe[0]["sign"] == "−"  # атака — это «меньше»
    assert not any(r["flagged"] for r in probe if r["feature"] != "leak")


def test_probe_needs_both_classes():
    X, _ = _data()
    assert single_feature_probe(X, np.zeros(len(X), bool), FEATURES) == []


def test_permutation_importance_deterministic_and_ranks_leak_first():
    X, y = _data()

    def score_fn(M):
        return -M[:, 1] + 0.01 * M[:, 0]

    a = permutation_importance_score(score_fn, X, y, FEATURES, seed=5, top=3, max_rows=1500)
    b = permutation_importance_score(score_fn, X, y, FEATURES, seed=5, top=3, max_rows=1500)
    assert a == b
    assert a["top"][0]["feature"] == "leak"
    assert a["n_rows"] == 1500


def test_audit_text_mentions_decision():
    X, y = _data()
    rep = audit_expert(
        lambda M: -M[:, 1], X, y, FEATURES, seed=0, flag_at=0.9, top=3, max_rows=1000
    )
    assert rep["flagged_features"] == ["leak"]
    assert "exclude_features" in rep["text"]
    rep2 = audit_expert(
        lambda M: -M[:, 1],
        X,
        y,
        FEATURES,
        seed=0,
        flag_at=0.9,
        top=3,
        max_rows=1000,
        excluded=["other"],
    )
    assert "Исключены" in rep2["text"]
