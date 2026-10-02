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


def small_windows_raw(root: Path, **overrides) -> dict:
    """Конфиг окон 007 для синтетики: те же ключи, что configs/windows.yaml, но модели
    крошечные (секунды обучения на CPU), а порог надёжного класса — 3 окна: на синтетике
    окон атак на val единицы-десятки."""
    raw = {
        "split": "unsw_time",
        "transfer_split": "unsw_cross_day",
        "seed": 42,
        "window": {
            "length_ms": 60000,
            "seq_max": 32,
            "train_shifts_ms": [0, 30000],
            "holdout_share": 0.10,
        },
        "current_model": "auto",
        "current_aggregate": "max",
        "selection": {
            "metric": "macro_pr_auc_reliable_val",
            "min_class_windows": 3,
            "min_gain": 0.01,
        },
        "audit": {"max_drop": 0.10, "single_feature_share": 0.90},
        "candidates": {
            "lgbm": {
                "n_estimators": 30,
                "learning_rate": 0.1,
                "num_leaves": 15,
                "class_weight": "balanced",
                "early_stopping_rounds": 10,
            },
            "gru": {
                "proj": 16,
                "hidden": 16,
                "dropout": 0.1,
                "lr": 0.003,
                "weight_decay": 0.0001,
                "batch": 128,
                "max_epochs": 2,
                "patience": 2,
                "class_weight_cap": 50,
                "amp": True,
            },
        },
        "output": str(Path(root) / "windows"),
    }
    raw.update(overrides)
    return raw


# Фича 006: минимальный набор сценариев для тестов без ВМ. Адреса — из сети стенда 10.88.0.0/24;
# окно скана совпадает с атакой в tests/fixtures/lab_sample.pcap (make_lab_pcap.py)
LAB_PCAP = Path(__file__).parent / "lab_sample.pcap"


def lab_scenarios() -> list[dict]:
    return [
        {
            "name": "port_scan",
            "version": "1",
            "tool": "nmap",
            "args": "-sS -p 1-1024 -T4 {target}",
            "target": "web",
            "expected_class": "reconnaissance",
            "rate_limit": "T4",
            "duration_limit_s": 60,
            "catch_threshold": 0.3,
        },
        {
            "name": "control_replay",
            "version": "1",
            "tool": "tcpreplay",
            "args": "--intf1=lab0 {pcap}",
            "target": "web",
            "expected_class": "generic",
            "rate_limit": "topspeed",
            "duration_limit_s": 60,
            "catch_threshold": 0.5,
            "pcap": "/opt/mlsiem/control_replay.pcap",
            "src_map": "175.45.176.1:10.88.0.30",
            "dst_map": "149.171.126.10:10.88.0.20",
        },
    ]
