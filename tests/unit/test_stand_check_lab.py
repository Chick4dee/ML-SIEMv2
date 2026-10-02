"""Проверка машин стенда в `stand check` (фича 006, US1): разбор состояния на подставных данных,
без ВМ. PowerShell подменяется функцией по тексту команды, канал — раннером в этом же процессе.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mlsiem.lab.channel import ChannelError, LocalChannel
from mlsiem.lab.runner import RunnerState
from mlsiem.stand.check import CheckReport, check_isolation, parse_adapters
from mlsiem.stand.lab_check import (
    check_clock,
    check_lab_adapters,
    check_vms,
    lab_check,
)
from mlsiem.stream.config import load_stream_config

REPO = Path(__file__).parents[2]
NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def cfg():
    return load_stream_config(REPO / "configs" / "stream.yaml")


def _vm(name, state="Running"):
    return {"Name": name, "State": state}


def _adapter(switch, name="Network Adapter", mirroring=None):
    return {
        "Name": name,
        "SwitchName": switch,
        "MacAddress": "x",
        "Connected": True,
        "PortMirroringMode": mirroring,
    }


class FakePS:
    """PowerShell по ключевым словам команды → ответ (список) или исключение."""

    def __init__(self, vms, adapters=None, free_kb=8 * 1024 * 1024):
        self.vms, self.adapters, self.free_kb = vms, adapters or {}, free_kb

    def __call__(self, command, timeout):
        if "Get-VM " in command:
            if isinstance(self.vms, Exception):
                raise self.vms
            return self.vms
        if "Get-VMNetworkAdapter" in command:
            for vm, ads in self.adapters.items():
                if f"'{vm}'" in command:
                    return ads
            raise RuntimeError("нет такой машины")
        if "FreePhysicalMemory" in command:
            return [{"FreePhysicalMemory": self.free_kb}]
        raise AssertionError(command)


def _channel(cfg, *, reachable, skew_s=0.0):
    """Раннер, у которого сеть подменена: reachable(host, port) → bool."""
    clock = lambda: (NOW + timedelta(seconds=skew_s)).isoformat().replace("+00:00", "Z")  # noqa: E731
    state = RunnerState(
        cfg.raw,
        "/nonexistent/journal.jsonl",
        clock=clock,
        probe=lambda host, port, timeout: reachable(host, port),
    )
    return LocalChannel(state)


def _services_up(cfg):
    ports = {80, 22, 21, 53}
    return lambda host, port: host == cfg.lab.victim.ip and port in ports


def _run(cfg, ps, channel):
    report = CheckReport()
    lab_check(cfg, report, channel=channel, powershell=ps, now=lambda: NOW)
    return report


def test_vms_not_created_is_not_a_problem(cfg):
    assert check_vms([], cfg) == ([], [])
    report = _run(cfg, FakePS([]), None)
    assert report.ok and any("ещё не созданы" in x for x in report.lines)


def test_one_vm_missing_and_stopped(cfg):
    lines, problems = check_vms([_vm("mlsiem-victim", "Off")], cfg)
    assert any("mlsiem-victim не запущена" in p and "Start-VM" in p for p in problems)
    assert any("нет машины mlsiem-attacker" in p for p in problems)
    assert lines == []


def test_adapters_only_in_lab_switch(cfg):
    assert check_lab_adapters("mlsiem-victim", parse_adapters([_adapter("mlsiem-lab")]), cfg) == []
    # Отключённый установочный адаптер (нет коммутатора) — пути наружу нет
    assert (
        check_lab_adapters(
            "mlsiem-victim", parse_adapters([_adapter("mlsiem-lab"), _adapter(None)]), cfg
        )
        == []
    )
    mgmt = check_lab_adapters(
        "mlsiem-victim", parse_adapters([_adapter("mlsiem-lab"), _adapter("mlsiem-mgmt")]), cfg
    )
    assert mgmt and "путь из стенда наружу" in mgmt[0]
    default = check_lab_adapters(
        "mlsiem-attacker", parse_adapters([_adapter("mlsiem-lab"), _adapter("Default Switch")]), cfg
    )
    assert default and "Disconnect-VMNetworkAdapter" in default[0]
    assert check_lab_adapters(
        "mlsiem-victim", parse_adapters([_adapter(None)]), cfg
    )  # не видна сенсору


def test_sensor_adapter_allowed_on_broker_only_as_mirror_destination(cfg):
    sensor = _adapter("mlsiem-lab", name="sensor", mirroring="Destination")
    mgmt = _adapter("mlsiem-mgmt", name="mgmt")
    assert check_isolation(parse_adapters([mgmt, sensor]), cfg) == []
    # Любой другой адаптер брокера в сети стенда — по-прежнему нарушение изоляции (005)
    other = _adapter("mlsiem-lab", name="Network Adapter")
    assert check_isolation(parse_adapters([mgmt, other]), cfg)
    # «sensor» без режима приёмника зеркала — тоже нет
    bare = _adapter("mlsiem-lab", name="sensor", mirroring=None)
    assert check_isolation(parse_adapters([mgmt, bare]), cfg)


def test_clock_skew():
    assert check_clock(NOW, "2026-10-01T12:00:00.500Z", 1) == (0.5, True)
    skew, ok = check_clock(NOW, "2026-10-01T12:00:03Z", 1)
    assert skew == 3 and not ok


def test_all_good(cfg):
    ps = FakePS(
        [_vm("mlsiem-victim"), _vm("mlsiem-attacker")],
        {"mlsiem-victim": [_adapter("mlsiem-lab")], "mlsiem-attacker": [_adapter("mlsiem-lab")]},
    )
    report = _run(cfg, ps, _channel(cfg, reachable=_services_up(cfg), skew_s=0.2))
    assert report.problems == [], report.problems
    text = "\n".join(report.lines)
    assert "канал управления атакующим" in text and "изоляция изнутри" in text
    assert "служба жертвы web" in text and "расхождение 0.20 с" in text
    assert "свободная память хоста: 8.0 ГБ" in text
    assert report.warnings == []


def test_isolation_breach_service_down_and_clock(cfg):
    ps = FakePS(
        [_vm("mlsiem-victim"), _vm("mlsiem-attacker")],
        {"mlsiem-victim": [_adapter("mlsiem-lab")], "mlsiem-attacker": [_adapter("mlsiem-lab")]},
    )

    def reachable(host, port):
        if host == "8.8.8.8":  # из стенда виден интернет
            return True
        return host == cfg.lab.victim.ip and port in {80, 22, 21}  # dns молчит

    report = _run(cfg, ps, _channel(cfg, reachable=reachable, skew_s=5))
    joined = "\n".join(report.problems)
    assert "изоляция нарушена" in joined and "8.8.8.8:53" in joined
    assert "служба dns" in joined
    assert "расходятся на 5.0 с" in joined and "Enable-VMIntegrationService" in joined


def test_low_memory_is_a_warning(cfg):
    ps = FakePS(
        [_vm("mlsiem-victim"), _vm("mlsiem-attacker")],
        {"mlsiem-victim": [_adapter("mlsiem-lab")], "mlsiem-attacker": [_adapter("mlsiem-lab")]},
        free_kb=2 * 1024 * 1024,
    )
    report = _run(cfg, ps, None)
    assert report.ok and any("SC-009" in w and "2.0 ГБ" in w for w in report.warnings)


def test_channel_down_is_one_clear_problem(cfg):
    class Dead:
        def request(self, req, timeout_s=20.0):
            raise ChannelError("машина mlsiem-attacker не ответила за 10 с")

    ps = FakePS(
        [_vm("mlsiem-victim"), _vm("mlsiem-attacker")],
        {"mlsiem-victim": [_adapter("mlsiem-lab")], "mlsiem-attacker": [_adapter("mlsiem-lab")]},
    )
    report = _run(cfg, ps, Dead())
    assert len([p for p in report.problems if "канал управления" in p]) == 1


def test_get_vm_unavailable_warns(cfg):
    report = _run(cfg, FakePS(RuntimeError("Access denied")), None)
    assert report.ok and any("Get-VM недоступен" in w for w in report.warnings)


def test_runner_ping_lists_scenarios(cfg):
    reply = _channel(cfg, reachable=lambda h, p: False).request({"cmd": "ping"})
    assert reply["ok"] and {s["name"] for s in reply["scenarios"]} >= {"control_replay"}
    json.dumps(reply)  # ответ сериализуем
