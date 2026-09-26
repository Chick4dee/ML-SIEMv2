"""Проверка стенда с хоста (`mlsiem stand check`, FR-004, FR-003a): только чтение и понятные
ответы."""

import json
import time
from pathlib import Path

import pytest

from mlsiem.stand.check import (
    CheckReport,
    check_broker,
    check_host_address,
    check_isolation,
    parse_adapters,
    stand_check,
)
from mlsiem.stream.broker import MemoryBroker, MemoryCluster, topic_specs
from mlsiem.stream.config import load_stream_config

REPO = Path(__file__).parents[2]

# Так выглядит вывод `Get-VMNetworkAdapter -VMName mlsiem-broker | Select-Object Name,
# SwitchName, MacAddress, Connected | ConvertTo-Json` после установки
ADAPTERS_OK = json.dumps(
    [
        {
            "Name": "mgmt",
            "SwitchName": "mlsiem-mgmt",
            "MacAddress": "00155D4D0010",
            "Connected": True,
        },
        {"Name": "install", "SwitchName": None, "MacAddress": "00155D4D0011", "Connected": False},
    ]
)
ADAPTER_IN_LAB = json.dumps(
    {"Name": "Network Adapter", "SwitchName": "mlsiem-lab", "MacAddress": "x", "Connected": True}
)


@pytest.fixture(scope="module")
def cfg():
    return load_stream_config(REPO / "configs" / "stream.yaml")


@pytest.fixture
def cluster(cfg) -> MemoryCluster:
    c = MemoryCluster()
    for s in topic_specs(cfg):
        c.add_topic(s.name, s.partitions, s.retention_ms)
    return c


def _factory(cluster, cfg):
    return lambda: MemoryBroker(cluster, vm_name=cfg.stand.vm_name)


def test_broker_ok_lists_topics(cfg, cluster):
    report = CheckReport()
    check_broker(cfg, _factory(cluster, cfg), report)
    assert report.ok, report.problems
    text = "\n".join(report.lines)
    assert "доступен" in text
    assert cfg.topics.flows in text and "168 ч" in text


def test_missing_topic_is_problem(cfg):
    c = MemoryCluster()
    c.add_topic(cfg.topics.flows, 1, cfg.topics.retention_ms)
    report = CheckReport()
    check_broker(cfg, _factory(c, cfg), report)
    assert not report.ok
    assert cfg.topics.rejected in report.problems[0]
    assert "mlsiem-install-kafka.sh" in report.problems[0]


def test_unavailable_broker_is_quick_and_explained(cfg, cluster):
    cluster.down = True
    report = CheckReport()
    t0 = time.monotonic()
    check_broker(cfg, _factory(cluster, cfg), report)
    assert time.monotonic() - t0 <= cfg.broker.connect_timeout_s
    assert not report.ok
    assert f"Start-VM {cfg.stand.vm_name}" in report.problems[0]


def test_isolation_ok(cfg):
    assert check_isolation(parse_adapters(json.loads(ADAPTERS_OK)), cfg) == []


def test_isolation_broken(cfg):
    problems = check_isolation(parse_adapters(json.loads(ADAPTER_IN_LAB)), cfg)
    assert any("брокер виден из сети стенда" in p for p in problems)
    # и заодно: без служебного адаптера хост машину не увидит
    assert any(cfg.stand.mgmt_switch in p for p in problems)


def test_host_address(cfg):
    assert check_host_address([{"IPAddress": cfg.stand.host_ip, "PrefixLength": 24}], cfg) == []
    assert "10-network.ps1" in check_host_address([], cfg)[0]


def test_full_check_with_fake_powershell(cfg, cluster):
    def ps(command, timeout):
        if "Get-NetIPAddress" in command:
            return [{"IPAddress": cfg.stand.host_ip, "PrefixLength": cfg.stand.prefix}]
        if "Get-VMNetworkAdapter" in command:
            return json.loads(ADAPTERS_OK)
        raise AssertionError(command)

    report = stand_check(cfg, _factory(cluster, cfg), powershell=ps)
    assert report.ok, report.problems
    assert any("брокера нет" in line for line in report.lines)


def test_no_hyperv_rights_is_warning(cfg, cluster):
    def ps(command, timeout):
        if "Get-NetIPAddress" in command:
            return [{"IPAddress": cfg.stand.host_ip}]
        raise RuntimeError("нет прав")

    report = stand_check(cfg, _factory(cluster, cfg), powershell=ps)
    assert report.ok
    assert any("изоляция не проверена" in w for w in report.warnings)
