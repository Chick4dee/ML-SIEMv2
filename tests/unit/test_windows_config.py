"""Конфиг окон (фича 007, FR-019): все числа эксперимента — в configs/windows.yaml, проверка
целиком до запуска, понятное сообщение с именем ключа."""

import copy
from pathlib import Path

import pytest
import yaml

from mlsiem.data.config import ConfigError
from mlsiem.detect.windows import load_windows_config, parse_windows_config
from mlsiem.soc.config import load_soc_config, parse_soc_config

REPO = Path(__file__).parents[2]


def _raw() -> dict:
    return yaml.safe_load((REPO / "configs" / "windows.yaml").read_text(encoding="utf-8"))


def test_repo_config_reads():
    cfg = load_windows_config(REPO / "configs" / "windows.yaml")
    assert cfg.split == "unsw_time" and cfg.transfer_split == "unsw_cross_day"
    assert cfg.length_ms == 60000 and cfg.seq_max == 128
    assert cfg.train_shifts_ms == (0, 15000, 30000, 45000)
    assert cfg.min_class_windows == 20 and cfg.min_gain == 0.01
    assert cfg.max_drop == 0.10 and cfg.single_feature_share == 0.90
    assert set(cfg.candidates) == {"lgbm", "gru"}


@pytest.mark.parametrize(
    ("path", "value", "key"),
    [
        (("window", "length_ms"), 0, "window.length_ms"),
        (("window", "length_ms"), -5, "window.length_ms"),
        (("window", "seq_max"), 0, "window.seq_max"),
        (("window", "train_shifts_ms"), [0, 60000], "window.train_shifts_ms"),
        (("window", "train_shifts_ms"), [0, -1], "window.train_shifts_ms"),
        (("window", "train_shifts_ms"), [15000], "window.train_shifts_ms"),
        (("selection", "min_gain"), -0.01, "selection.min_gain"),
        (("selection", "min_class_windows"), 0, "selection.min_class_windows"),
        (("audit", "max_drop"), 0, "audit.max_drop"),
        (("current_aggregate",), "mean", "current_aggregate"),
    ],
)
def test_bad_values_refused(path, value, key):
    raw = copy.deepcopy(_raw())
    node = raw
    for p in path[:-1]:
        node = node[p]
    node[path[-1]] = value
    with pytest.raises(ConfigError, match=key.replace(".", r"\.")):
        parse_windows_config(raw)


def test_unknown_candidate_refused():
    raw = copy.deepcopy(_raw())
    raw["candidates"]["transformer"] = {}
    with pytest.raises(ConfigError, match="transformer"):
        parse_windows_config(raw)


def test_lgbm_is_required():
    raw = copy.deepcopy(_raw())
    del raw["candidates"]["lgbm"]
    with pytest.raises(ConfigError, match="lgbm"):
        parse_windows_config(raw)


def test_soc_windows_section():
    cfg = load_soc_config(REPO / "configs" / "soc.yaml")
    assert cfg.windows.model == Path("models/windows")
    assert cfg.windows.mode == "auto"
    assert cfg.windows.length_ms == 60000


def test_soc_windows_optional_and_mode_checked():
    raw = copy.deepcopy(load_soc_config(REPO / "configs" / "soc.yaml").raw)
    del raw["windows"]
    assert parse_soc_config(raw).windows.mode == "auto"
    raw["windows"] = {"model": "x", "mode": "off"}
    assert parse_soc_config(raw).windows.mode == "off"
    raw["windows"] = {"model": "x", "mode": "force"}
    with pytest.raises(ConfigError, match="windows.mode"):
        parse_soc_config(raw)
