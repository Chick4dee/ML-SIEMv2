"""Тесты чтения configs/data.yaml."""

from pathlib import Path

import pytest
import yaml

from mlsiem.data.config import ConfigError, load_config

REPO_CONFIG = Path(__file__).parents[2] / "configs" / "data.yaml"


def _write(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "data.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return path


def _raw() -> dict:
    return yaml.safe_load(REPO_CONFIG.read_text(encoding="utf-8"))


def test_repo_config_loads():
    cfg = load_config(REPO_CONFIG)
    assert cfg.seed == 42
    assert cfg.split.quantiles == (0.70, 0.85)
    assert cfg.split.gap_ms == 600_000
    assert cfg.ctu13.timezone == "Europe/Prague"
    # относительный путь к GT разрешается от root датасета
    assert cfg.unsw.gt_csv == cfg.unsw.root / "CSV Files" / "NUSW-NB15_GT.csv"
    assert cfg.audit.tree_depth == 4


def test_missing_key_names_the_key(tmp_path):
    raw = _raw()
    del raw["datasets"]["ctu13"]["timezone"]
    with pytest.raises(ConfigError, match="datasets.ctu13.timezone"):
        load_config(_write(tmp_path, raw))


def test_wrong_type_names_the_key(tmp_path):
    raw = _raw()
    raw["split"]["gap_ms"] = "десять минут"
    with pytest.raises(ConfigError, match="split.gap_ms"):
        load_config(_write(tmp_path, raw))


def test_ctu13_parts_must_cover_all_scenarios_once(tmp_path):
    raw = _raw()
    raw["split"]["ctu13_parts"]["test"] = [8, 12, 7]  # 7 уже в val
    with pytest.raises(ConfigError, match="ctu13_parts"):
        load_config(_write(tmp_path, raw))

    raw = _raw()
    raw["split"]["ctu13_parts"]["test"] = [8]  # 12 потерялся
    with pytest.raises(ConfigError, match="ctu13_parts"):
        load_config(_write(tmp_path, raw))
