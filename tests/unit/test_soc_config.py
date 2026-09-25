"""Конфиг SOC: корректный читается; ошибки в уровнях, действиях и условиях ловятся сразу."""

from pathlib import Path

import pytest
import yaml

from mlsiem.data.config import ConfigError
from mlsiem.soc.config import SEVERITY_LEVELS, UiConfig, load_soc_config, parse_soc_config

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
        # фича 004: класс «аномалия» — всегда ручной разбор, сразу после защищённых
        "unknown_class",
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


# ---------------------------------------------------------------- фича 003: сети и консоль


def test_networks_and_ui_read():
    cfg = load_soc_config(REPO / "configs" / "soc.yaml")
    names = [(n.name, n.role, [str(c) for c in n.cidrs]) for n in cfg.networks]
    assert names == [
        ("жертвы UNSW-NB15", "victims", ["149.171.126.0/24"]),
        ("фон UNSW-NB15", "background", ["59.166.0.0/24"]),
    ]
    assert cfg.ui == UiConfig(
        refresh_seconds=10, page_size=50, recent_alerts=20, alerts_page_size=50
    )


def test_bad_cidr_names_network(raw):
    raw["networks"] = [{"name": "кривая", "role": "victims", "cidrs": ["300.1.1.0/24"]}]
    with pytest.raises(ConfigError, match="кривая"):
        parse_soc_config(raw)


def test_ipv6_and_host_bits_allowed(raw):
    raw["networks"] = [{"name": "v6", "role": "other", "cidrs": ["2001:db8::1/64", "10.0.0.5/24"]}]
    cfg = parse_soc_config(raw)
    assert [str(c) for c in cfg.networks[0].cidrs] == ["2001:db8::/64", "10.0.0.0/24"]


def test_bad_role(raw):
    raw["networks"] = [{"name": "x", "role": "attackers", "cidrs": ["10.0.0.0/8"]}]
    with pytest.raises(ConfigError, match="role"):
        parse_soc_config(raw)


@pytest.mark.parametrize("value", [2, 301, "10", True])
def test_refresh_out_of_range(raw, value):
    raw["ui"]["refresh_seconds"] = value
    with pytest.raises(ConfigError, match="refresh_seconds"):
        parse_soc_config(raw)


def test_sections_optional_for_002_configs(raw):
    # Конфиг 002 без новых разделов читается: сети по умолчанию — жертвы и фон UNSW-NB15
    # (FR-018), настройки консоли — из data-model
    repo_networks = load_soc_config(REPO / "configs" / "soc.yaml").networks
    del raw["networks"], raw["ui"]
    cfg = parse_soc_config(raw)
    assert cfg.networks == repo_networks
    assert cfg.ui == UiConfig()


def test_empty_networks_allowed(raw):
    raw["networks"] = []
    assert parse_soc_config(raw).networks == ()


# ---------------------------------------------------------------- фича 004


def test_direction_modes(raw):
    assert parse_soc_config(raw).direction == "auto"
    raw["grouping"]["direction"] = "as_is"
    assert parse_soc_config(raw).direction == "as_is"
    raw["grouping"]["direction"] = "reverse"
    with pytest.raises(ConfigError, match="grouping.direction"):
        parse_soc_config(raw)


def test_direction_optional_for_old_configs(raw):
    del raw["grouping"]["direction"]
    assert parse_soc_config(raw).direction == "auto"


def test_anomaly_needs_severity(raw):
    from mlsiem.soc.config import check_model_classes

    cfg = parse_soc_config(raw)
    check_model_classes(cfg, ["benign", "dos", "anomaly"])
    del raw["severity"]["base"]["anomaly"]
    cfg = parse_soc_config(raw)
    check_model_classes(cfg, ["benign", "dos"])  # у детектора 002 класса anomaly нет — ок
    with pytest.raises(ValueError, match="anomaly"):
        check_model_classes(cfg, ["benign", "dos", "anomaly"])


def test_soc_run_refuses_without_anomaly_level(raw, tmp_path, synthetic_split, tiny_ensemble):
    from mlsiem.soc.run import run_chain

    del raw["severity"]["base"]["anomaly"]
    cfg = parse_soc_config({**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "r")})
    with pytest.raises(ValueError, match="severity.base"):
        run_chain("split:unsw_time/test", cfg, model_dir=tiny_ensemble, data_dir=synthetic_split)
    assert not (tmp_path / "r").exists() or not any((tmp_path / "r").iterdir())
