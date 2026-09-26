"""Конфиг потока (фича 005): репозиторный читается, ошибки называют ключ и объясняют причину."""

import copy
from pathlib import Path

import pytest
import yaml

from mlsiem.data.config import ConfigError
from mlsiem.stream.config import load_stream_config, parse_speed, parse_stream_config

REPO = Path(__file__).parents[2]


@pytest.fixture
def raw() -> dict:
    return yaml.safe_load((REPO / "configs" / "stream.yaml").read_text(encoding="utf-8"))


def test_repo_config_loads():
    cfg = load_stream_config(REPO / "configs" / "stream.yaml")
    assert cfg.broker.bootstrap == "10.77.0.10:9092"
    assert cfg.broker.connect_timeout_s == 10
    assert (cfg.topics.flows, cfg.topics.rejected) == ("mlsiem.flows", "mlsiem.flows.rejected")
    assert cfg.topics.retention_ms == 168 * 3600 * 1000
    assert cfg.consumer.batch_max_messages == 5000
    assert cfg.consumer.allowed_lateness_ms == 120_000
    assert cfg.replay.default_speed == 60
    assert cfg.stand.vm_name == "mlsiem-broker"
    assert str(cfg.stand.network) == "10.77.0.0/24"
    assert len(cfg.stand.kafka_sha512) == 128
    assert cfg.stand.kafka_heap_mb < cfg.stand.memory_mb


def _set(raw: dict, dotted: str, value) -> dict:
    out = copy.deepcopy(raw)
    node = out
    *path, last = dotted.split(".")
    for part in path:
        node = node[part]
    node[last] = value
    return out


@pytest.mark.parametrize(
    ("key", "value", "match"),
    [
        ("broker.bootstrap", "10.77.0.10", "broker.bootstrap.*хост:порт"),
        ("broker.bootstrap", "10.77.0.10:0", "broker.bootstrap"),
        ("topics.partitions", 0, "topics.partitions"),
        ("consumer.batch_max_messages", 0, "consumer.batch_max_messages"),
        ("consumer.allowed_lateness_ms", -1, "consumer.allowed_lateness_ms"),
        ("consumer.lease_ttl_s", 5, "consumer.lease_ttl_s"),
        ("stand.broker_ip", "10.78.0.10", "не в одной сети /24"),
        ("stand.memory_mb", 512, "stand.memory_mb"),
        ("stand.kafka_heap_mb", 2048, "stand.kafka_heap_mb"),
        ("stand.kafka_sha512", "abc", "stand.kafka_sha512"),
        ("replay.default_speed", 0, "replay.default_speed"),
        ("replay.default_speed", "быстро", "replay.default_speed"),
        ("topics.rejected", "mlsiem.flows", "различаться"),
    ],
)
def test_bad_values(raw, key, value, match):
    with pytest.raises(ConfigError, match=match):
        parse_stream_config(_set(raw, key, value))


def test_missing_key(raw):
    bad = copy.deepcopy(raw)
    del bad["consumer"]["group"]
    with pytest.raises(ConfigError, match="consumer.group"):
        parse_stream_config(bad)


def test_speed_max():
    assert parse_speed("max") is None
    assert parse_speed("MAX") is None
    assert parse_speed(60) == 60.0
    assert parse_speed("2.5") == 2.5


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="не найден"):
        load_stream_config(tmp_path / "nope.yaml")
