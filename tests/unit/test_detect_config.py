"""Конфиг эксперимента детектора: корректный читается, ошибки называют ключ."""

import copy
from pathlib import Path

import pytest
import yaml

from mlsiem.data.config import ConfigError
from mlsiem.detect.config import load_detect_config, parse_detect_config

REPO = Path(__file__).parents[2]


@pytest.fixture
def raw() -> dict:
    return yaml.safe_load((REPO / "configs" / "detect.yaml").read_text(encoding="utf-8"))


def test_repo_config_loads():
    cfg = load_detect_config(REPO / "configs" / "detect.yaml")
    assert cfg.split == "unsw_time"
    assert cfg.transfer_split == "unsw_cross_day"
    assert cfg.seed == 42
    assert cfg.selection.metric == "macro_pr_auc_val"
    assert cfg.selection.min_gain == pytest.approx(0.01)
    assert list(cfg.candidates) == ["logreg", "lgbm"]
    assert cfg.candidates["lgbm"]["num_leaves"] == 63
    assert cfg.output == Path("models/detector")


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="не найден"):
        load_detect_config(tmp_path / "nope.yaml")


@pytest.mark.parametrize("key", ["split", "seed", "selection", "candidates", "output"])
def test_missing_key_named(raw, key):
    broken = copy.deepcopy(raw)
    del broken[key]
    with pytest.raises(ConfigError, match=key):
        parse_detect_config(broken)


def test_wrong_type_named(raw):
    raw["seed"] = "сорок два"
    with pytest.raises(ConfigError, match="seed"):
        parse_detect_config(raw)


def test_bool_is_not_int(raw):
    raw["seed"] = True
    with pytest.raises(ConfigError, match="seed"):
        parse_detect_config(raw)


def test_negative_min_gain(raw):
    raw["selection"]["min_gain"] = -0.1
    with pytest.raises(ConfigError, match="min_gain"):
        parse_detect_config(raw)


def test_unknown_candidate(raw):
    raw["candidates"]["mlp"] = {}
    with pytest.raises(ConfigError, match="mlp"):
        parse_detect_config(raw)


def test_baseline_required(raw):
    del raw["candidates"]["logreg"]
    with pytest.raises(ConfigError, match="logreg"):
        parse_detect_config(raw)


def test_split_must_be_unsw(raw):
    raw["split"] = "ctu13_scenario"
    with pytest.raises(ConfigError, match="split"):
        parse_detect_config(raw)


# ---------------------------------------------------------------- фича 004: EnsembleConfig


class TestEnsembleConfig:
    @pytest.fixture
    def eraw(self) -> dict:
        return yaml.safe_load((REPO / "configs" / "ensemble.yaml").read_text(encoding="utf-8"))

    def test_repo_config_loads(self):
        from mlsiem.detect.config import load_ensemble_config

        cfg = load_ensemble_config(REPO / "configs" / "ensemble.yaml")
        assert cfg.split == "unsw_time" and cfg.seed == 42
        assert cfg.classifier == Path("models/detector")
        assert list(cfg.anomaly.candidates) == ["iforest", "autoencoder"]
        assert cfg.anomaly.anomaly_fpr == pytest.approx(0.005)
        assert cfg.anomaly.calibration_share == pytest.approx(0.10)
        assert cfg.anomaly.train_sample == 300_000
        assert cfg.meta.candidates == ("any_fired", "mean_score", "stack_logreg")
        assert cfg.meta.folds == 5 and cfg.meta.gap_ms == 60000
        assert cfg.hidden_classes == ("exploits", "dos")
        assert cfg.selection.min_gain == pytest.approx(0.01)
        assert cfg.selection.min_unknown_gain == pytest.approx(0.10)
        assert cfg.output_anomaly == Path("models/experts/anomaly")
        assert cfg.output_ensemble == Path("models/ensemble")

    @pytest.mark.parametrize(
        "path, value, match",
        [
            ("anomaly.candidates", {"iforest": {}, "ocsvm": {}}, "ocsvm"),
            ("anomaly.candidates", {"autoencoder": {}}, "бейзлайн"),
            ("meta.candidates", ["any_fired", "xgb_meta"], "xgb_meta"),
            ("anomaly.anomaly_fpr", 0.0, "anomaly_fpr"),
            ("anomaly.anomaly_fpr", 0.7, "anomaly_fpr"),
            ("anomaly.calibration_share", 0.5, "calibration_share"),
            ("anomaly.calibration_share", 0, "calibration_share"),
            ("meta.folds", 1, "folds"),
            ("meta.gap_ms", -1, "gap_ms"),
            ("selection.min_gain", -0.01, "min_gain"),
            ("selection.min_unknown_gain", -0.1, "min_unknown_gain"),
            ("hidden_classes", [], "hidden_classes"),
            ("split", "ctu13_scenario", "UNSW"),
            ("anomaly.exclude_features", ["src_ip"], "exclude_features"),
        ],
    )
    def test_errors_named(self, eraw, path, value, match):
        from mlsiem.detect.config import parse_ensemble_config

        node = eraw
        *parents, last = path.split(".")
        for p in parents:
            node = node[p]
        node[last] = value
        with pytest.raises(ConfigError, match=match):
            parse_ensemble_config(eraw)
