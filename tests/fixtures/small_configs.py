"""Маленькие конфиги фичи 004 для тестов: всё как в репозитории, но модели крошечные.

Синтетика 002 — несколько тысяч потоков, поэтому деревьев мало, подвыборка нормы маленькая,
а блоков OOF — три: тест идёт секунды, а логика та же, что в бою.
"""

from __future__ import annotations

from pathlib import Path


def small_ensemble_raw(classifier: Path, root: Path, **overrides) -> dict:
    raw = {
        "split": "unsw_time",
        "seed": 42,
        "classifier": str(classifier),
        "anomaly": {
            "candidates": {
                "iforest": {"n_estimators": 50, "max_samples": 512},
                "autoencoder": {"hidden": [16, 6, 16], "max_iter": 50},
            },
            "train_sample": 3000,
            "calibration_share": 0.10,
            "anomaly_fpr": 0.02,
            "exclude_features": [],
        },
        "meta": {
            "candidates": ["any_fired", "mean_score", "stack_logreg"],
            "folds": 3,
            "gap_ms": 60000,
        },
        "hidden_classes": ["exploits", "dos"],
        "selection": {"min_gain": 0.01, "min_unknown_gain": 0.10},
        "audit": {"probe_flag": 0.9, "permutation_rows": 2000, "top": 5},
        "unreliable_below": 50,
        "output": {
            "anomaly": str(Path(root) / "experts" / "anomaly"),
            "ensemble": str(Path(root) / "ensemble"),
        },
    }
    raw.update(overrides)
    return raw
