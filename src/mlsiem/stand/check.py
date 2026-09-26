"""Проверка брокерной машины с хоста — `mlsiem stand check` (FR-004, FR-003a, contracts/cli.md).

Только чтение: адрес хоста в служебной сети, доступность брокера, его топики и срок хранения,
и то, что у машины брокера нет адаптера в сети стенда. Каждая проблема — строка с подсказкой,
что делать («машина выключена? Start-VM mlsiem-broker»), а не трассировка.

Сведения Hyper-V берутся из PowerShell (`Get-VMNetworkAdapter`, `Get-NetIPAddress`) с
выводом через `ConvertTo-Json` — разбор JSON надёжнее, чем разбор таблиц PowerShell. Если
PowerShell или модуль Hyper-V недоступны (нет прав, другая ОС), проверка изоляции не
проваливается молча: это предупреждение с объяснением, почему её не удалось сделать.

Каждый шаг ограничен `broker.connect_timeout_s` — выключенная машина даёт ответ за секунды,
а не зависание (SC-001: проверка ≤ 10 с).
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from mlsiem.stream.broker import Broker, BrokerUnavailable, topic_specs


@dataclass
class CheckReport:
    lines: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def run_powershell(command: str, timeout_s: float) -> Any:
    """Выполнить команду PowerShell (только чтение) и вернуть разобранный JSON-вывод.

    Бросает RuntimeError с понятным текстом, если PowerShell нет, команда упала или не
    уложилась в тайм-аут.
    """
    try:
        done = subprocess.run(
            # Вывод — в UTF-8: иначе PowerShell отдаёт кириллицу в кодировке OEM (cp866)
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " + command,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "PowerShell не найден (проверка возможна только на хосте Windows)"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"PowerShell не ответил за {timeout_s:g} с") from exc
    if done.returncode != 0:
        err = (done.stderr or done.stdout).strip().splitlines()
        raise RuntimeError(err[0] if err else f"код возврата {done.returncode}")
    out = done.stdout.strip()
    if not out:
        return []
    data = json.loads(out)
    # ConvertTo-Json отдаёт один объект без списка, если строка одна
    return data if isinstance(data, list) else [data]


def parse_adapters(data: Any) -> list[dict]:
    """Вывод `Get-VMNetworkAdapter … | ConvertTo-Json` → [{name, switch, mac, connected}]."""
    items = data if isinstance(data, list) else [data]
    out = []
    for a in items:
        if not isinstance(a, dict):
            continue
        out.append(
            {
                "name": a.get("Name"),
                "switch": a.get("SwitchName"),
                "mac": a.get("MacAddress"),
                "connected": a.get("Connected"),
            }
        )
    return out


def check_isolation(adapters: list[dict], cfg) -> list[str]:
    """Проблемы изоляции: адаптер машины брокера в сети стенда — брокер виден атакующему."""
    s = cfg.stand
    problems = []
    for a in adapters:
        if a.get("switch") == s.lab_switch:
            problems.append(
                f"брокер виден из сети стенда: у машины {s.vm_name} адаптер «{a.get('name')}» "
                f"подключён к {s.lab_switch} — отключите его: "
                f"Remove-VMNetworkAdapter -VMName {s.vm_name} -Name '{a.get('name')}' (FR-003a)"
            )
    if adapters and not any(a.get("switch") == s.mgmt_switch for a in adapters):
        problems.append(
            f"у машины {s.vm_name} нет адаптера в служебной сети {s.mgmt_switch} — хост её не "
            "увидит; пересоздайте машину скриптом stand/hyperv/20-vm-broker.ps1"
        )
    return problems


def check_host_address(addresses: list[dict], cfg) -> list[str]:
    """Адрес хоста на vEthernet служебной сети: `Get-NetIPAddress … | ConvertTo-Json`."""
    s = cfg.stand
    ips = {str(a.get("IPAddress")) for a in addresses if isinstance(a, dict)}
    if s.host_ip in ips:
        return []
    return [
        f"у хоста нет адреса {s.host_ip}/{s.prefix} на vEthernet ({s.mgmt_switch}) — "
        "выполните stand/hyperv/10-network.ps1 от администратора"
    ]


def check_broker(cfg, broker_factory: Callable[[], Broker], report: CheckReport) -> None:
    """Доступность брокера, кластер, топики и их срок хранения."""
    s = cfg.stand
    try:
        broker = broker_factory()
    except BrokerUnavailable as exc:
        report.problems.append(str(exc))
        return
    try:
        broker.ping()
        info = broker.cluster_info() if hasattr(broker, "cluster_info") else {}
        report.lines.append(
            f"брокер {cfg.broker.bootstrap} доступен"
            + (
                f": кластер {info.get('cluster_id')}, узлы {', '.join(info.get('brokers', []))}"
                if info
                else ""
            )
            + f" (ожидается Kafka {s.kafka_version} в режиме KRaft)"
        )
        topics = broker.list_topics()
        for spec in topic_specs(cfg):
            got = topics.get(spec.name)
            if got is None:
                report.problems.append(
                    f"нет топика {spec.name} — установка Kafka не дошла до конца; на машине: "
                    "sudo bash /usr/local/sbin/mlsiem-install-kafka.sh"
                )
                continue
            ret = got.get("retention_ms")
            ret_text = f"{ret / 3_600_000:g} ч" if ret else "не известен"
            report.lines.append(
                f"  топик {spec.name}: партиций {got['partitions']}, срок хранения {ret_text}"
            )
            if ret is not None and ret != spec.retention_ms:
                report.warnings.append(
                    f"у топика {spec.name} срок хранения {ret} мс, а в конфиге "
                    f"{spec.retention_ms} мс (topics.retention_hours)"
                )
    except BrokerUnavailable as exc:
        report.problems.append(str(exc))
    finally:
        broker.close()


def stand_check(cfg, broker_factory: Callable[[], Broker], *, powershell=run_powershell):
    """Полная проверка: адрес хоста, машина и её адаптеры, брокер и топики."""
    s = cfg.stand
    report = CheckReport()
    timeout = cfg.broker.connect_timeout_s

    try:
        addrs = powershell(
            f"Get-NetIPAddress -InterfaceAlias 'vEthernet ({s.mgmt_switch})' -AddressFamily IPv4 "
            "-ErrorAction Stop | Select-Object IPAddress, PrefixLength | ConvertTo-Json",
            timeout,
        )
        problems = check_host_address(addrs, cfg)
        report.problems += problems
        if not problems:
            report.lines.append(f"хост: {s.host_ip}/{s.prefix} на vEthernet ({s.mgmt_switch})")
    except (RuntimeError, ValueError) as exc:
        report.problems.append(
            f"не найден адаптер vEthernet ({s.mgmt_switch}) с адресом хоста ({exc}) — выполните "
            "stand/hyperv/10-network.ps1 от администратора"
        )

    try:
        adapters = parse_adapters(
            powershell(
                f"Get-VMNetworkAdapter -VMName '{s.vm_name}' -ErrorAction Stop | "
                "Select-Object Name, SwitchName, MacAddress, Connected | ConvertTo-Json",
                timeout,
            )
        )
        iso = check_isolation(adapters, cfg)
        report.problems += iso
        if not iso:
            switches = ", ".join(sorted({str(a["switch"]) for a in adapters}))
            report.lines.append(
                f"машина {s.vm_name}: адаптеры в {switches}; "
                f"в сети стенда {s.lab_switch} брокера нет"
            )
    except (RuntimeError, ValueError) as exc:
        report.warnings.append(
            f"изоляция не проверена: Get-VMNetworkAdapter недоступен ({exc}) — запустите от "
            "администратора или участника группы «Администраторы Hyper-V»"
        )

    check_broker(cfg, broker_factory, report)
    return report
