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
