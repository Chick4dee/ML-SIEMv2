"""Конфиг SOC: корректный читается; ошибки в уровнях, действиях и условиях ловятся сразу."""

from pathlib import Path

import pytest
import yaml

from mlsiem.data.config import ConfigError
from mlsiem.soc.config import SEVERITY_LEVELS, load_soc_config, parse_soc_config

REPO = Path(__file__).parents[2]


@pytest.fixture
def raw() -> dict:
    return yaml.safe_load((REPO / "configs" / "soc.yaml").read_text(encoding="utf-8"))


def test_repo_config_loads():
    cfg = load_soc_config(REPO / "configs" / "soc.yaml")
    assert cfg.db == Path("var/soc.db")
    assert cfg.runs_dir == Path("var/runs")
    assert cfg.api.host == "127.0.0.1"
    assert cfg.api.port == 8000
    assert cfg.window_ms == 900_000
    assert cfg.bump_at == 100
    assert cfg.severity_base["exploits"] == "high"
    assert cfg.severity_base["reconnaissance"] == "low"
    assert cfg.protected_ips == ()
    assert [r.id for r in cfg.rules] == [
        "protected",
        "intrusion_single_target",
        "intrusion_many_targets",
        "noisy_attack",
        "recon",
        "default",
    ]
    assert cfg.rules[-1].when == {}
    assert SEVERITY_LEVELS == ("low", "medium", "high", "critical")


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="не найден"):
        load_soc_config(tmp_path / "nope.yaml")


@pytest.mark.parametrize(
    "path",
    ["db", "runs_dir", "api.port", "grouping.window_ms", "severity.bump_at", "playbook.rules"],
)
def test_missing_key_named(raw, path):
    node = raw
    *parents, last = path.split(".")
    for p in parents:
        node = node[p]
    del node[last]
    with pytest.raises(ConfigError, match=path.replace(".", r"\.")):
        parse_soc_config(raw)


def test_wrong_type(raw):
    raw["grouping"]["window_ms"] = "15 минут"
    with pytest.raises(ConfigError, match="window_ms"):
        parse_soc_config(raw)


def test_bad_severity_level(raw):
    raw["severity"]["base"]["dos"] = "severe"
    with pytest.raises(ConfigError, match="severity.base.dos"):
        parse_soc_config(raw)


def test_bad_min_severity(raw):
    raw["playbook"]["rules"][4]["when"]["min_severity"] = "extreme"
    with pytest.raises(ConfigError, match="min_severity"):
        parse_soc_config(raw)


def test_bad_action(raw):
    raw["playbook"]["rules"][0]["action"] = "shutdown_network"
    with pytest.raises(ConfigError, match="action"):
        parse_soc_config(raw)


def test_unknown_condition(raw):
    raw["playbook"]["rules"][1]["when"]["min_confidence"] = 0.9
    with pytest.raises(ConfigError, match="min_confidence"):
        parse_soc_config(raw)


def test_condition_wrong_type(raw):
    raw["playbook"]["rules"][1]["when"]["max_targets"] = True
    with pytest.raises(ConfigError, match="max_targets"):
        parse_soc_config(raw)


def test_duplicate_rule_ids(raw):
    raw["playbook"]["rules"][1]["id"] = "protected"
    with pytest.raises(ConfigError, match="повторяются"):
        parse_soc_config(raw)
