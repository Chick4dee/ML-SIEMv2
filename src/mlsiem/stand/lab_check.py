"""Проверка машин стенда 006 с хоста — часть `mlsiem stand check` (US1, contracts/cli.md).

Только чтение. Что проверяется, если машины стенда подняты:
- наличие машин жертвы и атакующего и состояние (Get-VM);
- изоляция по адаптерам: у машин стенда адаптер ТОЛЬКО в `mlsiem-lab` (ни служебной сети,
  ни подключённого Default Switch — иначе у атаки был бы путь наружу, FR-005);
- изоляция «изнутри»: с атакующей машины недоступны хост, брокер и интернет (раннер пробует
  подключиться — сеть стенда от них отрезана);
- службы жертвы отвечают с атакующего (раннер пробует порты);
- расхождение часов атакующего и хоста ≤ `lab.clock_skew_max_s` (R13, иначе разметка набора
  по журналу ненадёжна);
- канал управления работает (R6);
- запас памяти хоста при поднятых машинах ≥ `lab.host_free_gb_min` (SC-009, предупреждение).

Машина выключена или раннер молчит — понятная строка с подсказкой, не зависание: каждый шаг
ограничен таймаутом, а при недоступном канале остальные проверки «изнутри» пропускаются.
Все внешние вызовы (PowerShell, канал, часы) передаются параметрами — тесты их подменяют.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from mlsiem.lab import journal
from mlsiem.lab.channel import Channel, ChannelError
from mlsiem.lab.scenarios import SERVICE_PORTS
from mlsiem.stand.check import CheckReport, run_powershell

# Куда с атакующей машины ходить НЕЛЬЗЯ: адрес хоста и брокера в служебной сети, интернет
OUTSIDE_PROBES = (("broker", None, 9092), ("host", None, 445), ("internet", "8.8.8.8", 53))


def check_vms(vms: list[dict], cfg) -> tuple[list[str], list[str]]:
    """(строки, проблемы) по `Get-VM … | Select Name, State`. Нет ни одной машины — стенд ещё
    не поднимали: это не проблема, проверка пропускается (возвращается ([], []))."""
    lab = cfg.lab
    present = {str(v.get("Name")): str(v.get("State")) for v in vms if isinstance(v, dict)}
    wanted = (lab.victim.vm, lab.attacker.vm)
    if not any(w in present for w in wanted):
        return [], []
    lines, problems = [], []
    for name in wanted:
        state = present.get(name)
        if state is None:
            problems.append(
                f"нет машины {name} — создайте её по stand/hyperv/README.md (раздел про 006)"
            )
        elif state.lower() not in ("running", "2"):
            problems.append(f"машина {name} не запущена (состояние {state}) — Start-VM {name}")
        else:
            lines.append(f"машина {name}: запущена")
    return lines, problems


def check_lab_adapters(vm: str, adapters: list[dict], cfg) -> list[str]:
    """Изоляция машины стенда по адаптерам: только сеть стенда, наружу пути нет."""
    problems = []
    s = cfg.stand
    for a in adapters:
        sw = a.get("switch")
        if sw == s.lab_switch:
            continue
        if sw in (None, ""):
            continue  # отключён от коммутатора — пути нет
        problems.append(
            f"у машины {vm} адаптер «{a.get('name')}» подключён к {sw} — это путь из стенда "
            f"наружу; отключите: Disconnect-VMNetworkAdapter -VMName {vm} -Name '{a.get('name')}' "
            "(stand/hyperv/45-post-install.ps1 делает это после установки)"
        )
    if adapters and not any(a.get("switch") == s.lab_switch for a in adapters):
        problems.append(
            f"у машины {vm} нет адаптера в сети стенда {s.lab_switch} — машина не видна "
            "сенсору; пересоздайте её скриптом stand/hyperv/"
            + ("40-vm-victim.ps1" if vm == cfg.lab.victim.vm else "50-vm-attacker.ps1")
        )
    return problems


def check_clock(host_now: datetime, remote_now_iso: str, max_skew_s: float) -> tuple[float, bool]:
    """(расхождение, секунд; в пределах ли допуска). Часы машины — строка раннера."""
    remote = journal.parse_iso(remote_now_iso)
    skew = abs((host_now - remote).total_seconds())
    return skew, skew <= max_skew_s


def free_memory_gb(powershell: Callable, timeout: float) -> float | None:
    """Свободная физическая память хоста, ГБ (None — не удалось узнать)."""
    try:
        data = powershell(
            "Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory "
            "| ConvertTo-Json",
            timeout,
        )
        kb = float(data[0]["FreePhysicalMemory"])
    except (RuntimeError, ValueError, KeyError, IndexError, TypeError):
        return None
    return kb / (1024 * 1024)


def lab_check(
    cfg,
    report: CheckReport,
    *,
    channel: Channel | None,
    powershell: Callable = run_powershell,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> None:
    """Дополняет отчёт проверками машин стенда; без раздела `lab` ничего не делает."""
    from mlsiem.stand.check import parse_adapters

    lab = cfg.lab
    if lab is None:
        return
    timeout = cfg.broker.connect_timeout_s
    names = f"'{lab.victim.vm}','{lab.attacker.vm}'"
    try:
        vms = powershell(
            f"Get-VM -Name {names} -ErrorAction SilentlyContinue | Select-Object Name, State "
            "| ConvertTo-Json",
            timeout,
        )
    except (RuntimeError, ValueError) as exc:
        report.warnings.append(
            f"машины стенда не проверены: Get-VM недоступен ({exc}) — запустите от "
            "администратора или участника группы «Администраторы Hyper-V»"
        )
        return
    lines, problems = check_vms(vms, cfg)
    report.lines += lines
    report.problems += problems
    if not lines and not problems:
        report.lines.append("машины стенда ещё не созданы — проверка стенда 006 пропущена")
        return

    # Изоляция по адаптерам каждой поднятой машины
    for vm in (lab.victim.vm, lab.attacker.vm):
        try:
            adapters = parse_adapters(
                powershell(
                    f"Get-VMNetworkAdapter -VMName '{vm}' -ErrorAction Stop | "
                    "Select-Object Name, SwitchName, MacAddress, Connected | ConvertTo-Json",
                    timeout,
                )
            )
        except (RuntimeError, ValueError):
            continue  # машины нет — об этом уже сказано выше
        bad = check_lab_adapters(vm, adapters, cfg)
        report.problems += bad
        if not bad and adapters:
            report.lines.append(
                f"  {vm}: адаптеры только в {cfg.stand.lab_switch}, наружу пути нет"
            )

    free = free_memory_gb(powershell, timeout)
    if free is not None:
        text = f"свободная память хоста: {free:.1f} ГБ"
        if free < lab.host_free_gb_min:
            report.warnings.append(
                f"{text} — меньше {lab.host_free_gb_min:g} ГБ при поднятых машинах стенда "
                "(SC-009); закройте лишнее или поднимайте стенд частями (без фоновой нормы)"
            )
        else:
            report.lines.append(text)

    if channel is None:
        return
    _check_inside(cfg, report, channel, now)


def _check_inside(cfg, report: CheckReport, channel: Channel, now) -> None:
    """Проверки через раннер атакующей: канал, службы жертвы, изоляция изнутри, часы."""
    lab, s = cfg.lab, cfg.stand
    try:
        ping = channel.request({"cmd": "ping"}, timeout_s=cfg.broker.connect_timeout_s)
    except ChannelError as exc:
        report.problems.append(
            f"канал управления атакующим ({lab.attacker.mgmt}) не работает: {exc}"
        )
        return
    if not ping.get("ok"):
        report.problems.append(f"раннер атакующего ответил ошибкой: {ping.get('error')}")
        return
    report.lines.append(f"канал управления атакующим ({lab.attacker.mgmt}): работает")

    victim_targets = [
        {"host": lab.victim.ip, "port": SERVICE_PORTS[svc]} for svc in lab.victim.services
    ]
    outside = [
        {
            "host": host or (s.broker_ip if kind == "broker" else s.host_ip),
            "port": port,
            "timeout": 2,
        }
        for kind, host, port in OUTSIDE_PROBES
    ]
    try:
        res = channel.request(
            {"cmd": "probe", "targets": victim_targets + outside},
            timeout_s=cfg.broker.connect_timeout_s + 2 * len(victim_targets + outside),
        )
    except ChannelError as exc:
        report.problems.append(f"проверка связности с атакующей не удалась: {exc}")
        res = {"ok": False}
    if res.get("ok"):
        reach = {(r["host"], r["port"]): r["reachable"] for r in res["results"]}
        for svc in lab.victim.services:
            ok = reach.get((lab.victim.ip, SERVICE_PORTS[svc]), False)
            if ok:
                report.lines.append(f"  служба жертвы {svc} (порт {SERVICE_PORTS[svc]}): отвечает")
            else:
                report.problems.append(
                    f"служба {svc} жертвы {lab.victim.ip}:{SERVICE_PORTS[svc]} не отвечает с "
                    "атакующего — жертва не поднялась или служба не запущена"
                )
        for t in outside:
            if reach.get((t["host"], t["port"]), False):
                report.problems.append(
                    f"изоляция нарушена: с атакующей доступен {t['host']}:{t['port']} — из сети "
                    "стенда есть путь наружу (FR-005); проверьте адаптеры машин стенда"
                )
        if not any(reach.get((t["host"], t["port"]), False) for t in outside):
            report.lines.append(
                "  изоляция изнутри: хост, брокер и интернет с атакующей недоступны"
            )

    try:
        clock = channel.request({"cmd": "clock"}, timeout_s=cfg.broker.connect_timeout_s)
        skew, ok = check_clock(now(), clock["now"], lab.clock_skew_max_s)
        if ok:
            report.lines.append(f"  часы атакующего и хоста: расхождение {skew:.2f} с")
        else:
            report.problems.append(
                f"часы атакующего и хоста расходятся на {skew:.1f} с (допуск "
                f"{lab.clock_skew_max_s:g} с) — разметка набора по журналу будет ненадёжной; "
                "включите службу времени Hyper-V: Enable-VMIntegrationService -VMName "
                f"{lab.attacker.vm} -Name 'Служба синхронизации времени'"
            )
    except (ChannelError, KeyError, ValueError) as exc:
        report.problems.append(f"часы атакующего не прочитаны: {exc}")
