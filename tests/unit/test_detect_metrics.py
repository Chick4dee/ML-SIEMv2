"""Метрики детектора: PR-AUC по классам, macro, скор атаки, порог по F1, prior."""

import numpy as np
import pytest
from sklearn.metrics import average_precision_score

from mlsiem.detect import metrics as M

CLASSES = ["benign", "dos", "exploits"]


def _data(seed=0, n=300):
    rng = np.random.default_rng(seed)
    y = rng.choice(CLASSES, size=n, p=[0.7, 0.2, 0.1])
    proba = rng.dirichlet([1, 1, 1], size=n)
    return y, proba


def test_per_class_matches_sklearn():
    y, proba = _data()
    pc = M.per_class_pr_auc(y, proba, CLASSES)
    for i, c in enumerate(CLASSES):
        assert pc[c] == pytest.approx(average_precision_score(y == c, proba[:, i]))
    assert M.macro_pr_auc(pc) == pytest.approx(np.mean(list(pc.values())))


def test_class_without_examples():
    y, proba = _data()
    y[y == "exploits"] = "dos"
    pc = M.per_class_pr_auc(y, proba, CLASSES)
    assert pc["exploits"] is None
    assert M.classes_without_examples(pc) == ["exploits"]
    assert M.macro_pr_auc(pc) == pytest.approx((pc["benign"] + pc["dos"]) / 2)


def test_attack_score():
    proba = np.array([[0.9, 0.05, 0.05], [0.2, 0.5, 0.3]])
    np.testing.assert_allclose(M.attack_score(proba, CLASSES), [0.1, 0.8])
    with pytest.raises(ValueError, match="benign"):
        M.attack_score(proba, ["a", "b", "c"])


def _brute_threshold(y, s):
    best, best_f1 = None, -1.0
    for t in sorted(set(s)):
        pred = s >= t
        tp = (pred & y).sum()
        f1 = 2 * tp / (pred.sum() + y.sum())
        if f1 >= best_f1:  # «≥»: при равенстве F1 берём больший порог
            best, best_f1 = t, f1
    return best


def test_threshold_is_max_f1():
    rng = np.random.default_rng(1)
    y = rng.random(500) < 0.2
    s = np.clip(rng.normal(0.3, 0.2, 500) + 0.3 * y, 0, 1)
    assert M.choose_threshold(y, s) == pytest.approx(_brute_threshold(y, s))


def test_threshold_ties_pick_larger():
    # Две атаки (скоры 0.9 и 0.6) и два benign между ними. F1 по порогам:
    # 0.9 → 2/3; 0.8 → 1/2; 0.7 → 2/5; 0.6 → 2/3. Ничья 0.9 и 0.6 — берётся больший
    y = np.array([True, False, False, True])
    s = np.array([0.9, 0.8, 0.7, 0.6])
    assert M.choose_threshold(y, s) == pytest.approx(0.9)


def test_threshold_many_equal_scores_deterministic():
    rng = np.random.default_rng(2)
    s = rng.choice([0.1, 0.5, 0.9], size=1000)
    y = rng.random(1000) < s
    t1 = M.choose_threshold(y, s)
    perm = rng.permutation(1000)
    assert M.choose_threshold(y[perm], s[perm]) == t1
    assert t1 in (0.1, 0.5, 0.9)
    assert t1 == pytest.approx(_brute_threshold(y, s))


def test_threshold_no_attacks():
    s = np.array([0.1, 0.4])
    t = M.choose_threshold(np.array([False, False]), s)
    assert (s >= t).sum() == 0


def test_binary_report():
    y = np.array([True, True, False, False])
    r = M.binary_report(y, np.array([0.9, 0.2, 0.8, 0.1]), 0.5)
    assert r["precision"] == pytest.approx(0.5)
    assert r["recall"] == pytest.approx(0.5)
    assert r["n_alerts"] == 2
    assert r["roc_auc"] == pytest.approx(0.75)


def test_prior_equals_class_shares():
    y_train = np.array(["benign"] * 70 + ["dos"] * 20 + ["exploits"] * 10)
    y_eval = np.array(["benign"] * 50 + ["dos"] * 30 + ["exploits"] * 20)
    p = M.prior_baseline(y_train, y_eval, CLASSES)
    assert p["per_class"]["dos"] == pytest.approx(0.3)
    assert p["per_class"]["exploits"] == pytest.approx(0.2)
    assert p["macro_pr_auc"] == pytest.approx((0.5 + 0.3 + 0.2) / 3)


# ---------------------------------------------------------------- фича 004


def test_binary_pr_auc_matches_sklearn():
    rng = np.random.default_rng(1)
    y = rng.random(200) < 0.2
    s = rng.random(200)
    assert M.binary_pr_auc(y, s) == pytest.approx(average_precision_score(y, s))


def test_binary_pr_auc_undefined():
    s = np.linspace(0, 1, 10)
    assert M.binary_pr_auc(np.zeros(10, bool), s) is None
    assert M.binary_pr_auc(np.ones(10, bool), s) is None


def test_catch_rate():
    y = np.array(["dos", "dos", "dos", "benign", "exploits"])
    alerts = np.array([True, False, True, True, False])
    assert M.catch_rate(y, alerts, "dos") == pytest.approx(2 / 3)
    assert M.catch_rate(y, alerts, "exploits") == 0.0
    assert M.catch_rate(y, alerts, "worms") is None


def test_fpr_on_benign():
    y = np.array(["benign"] * 4 + ["dos"])
    alerts = np.array([True, False, False, False, True])
    assert M.fpr_on_benign(y, alerts) == pytest.approx(0.25)
    assert M.fpr_on_benign(np.array(["dos"]), np.array([True])) is None


def test_unreliable_classes():
    y = np.array(["benign"] * 100 + ["worms"] * 3 + ["dos"] * 60)
    assert M.unreliable_classes(y, ["benign", "worms", "dos", "backdoor"], below=50) == ["worms"]


# ---------------------------------------------------------------- фича 007: надёжные классы


def test_reliable_classes_by_count():
    y = np.array(["benign"] * 30 + ["exploits"] * 20 + ["dos"] * 3)
    classes = ["benign", "dos", "exploits", "worms"]
    assert M.reliable_classes(y, classes, 20) == ["benign", "exploits"]
    assert M.reliable_classes(y, classes, 31) == []


def test_macro_reliable_matches_macro_when_all_reliable():
    per_class = {"benign": 0.9, "exploits": 0.5, "dos": 0.1, "worms": None}
    assert M.macro_pr_auc_reliable(per_class, ["benign", "exploits"]) == pytest.approx(0.7)
    everyone = ["benign", "exploits", "dos"]
    assert M.macro_pr_auc_reliable(per_class, everyone) == pytest.approx(M.macro_pr_auc(per_class))
