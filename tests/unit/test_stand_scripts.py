"""Скрипты стенда `stand/hyperv/*.ps1` (FR-002, research R3): подтверждение, идемпотентность,
никаких адресов и имён в коде — всё из configs/stream.yaml.

Сами скрипты меняют систему владельца, поэтому здесь они не запускаются: проверяется их текст
и синтаксис (парсером PowerShell, если он есть).
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

HYPERV = Path(__file__).parents[2] / "stand" / "hyperv"
# Скрипты, которые не меняют состояние хоста: проверка-план, чтение конфига и диспетчеры
# команд в гостя/сенсор (фича 006) — им ShouldProcess не нужен, они ничего на хосте не создают
READ_ONLY = {
    "00-check.ps1",
    "Read-StreamConfig.ps1",
    "70-sensor.ps1",
    "80-scenario.ps1",
    "lib-com.ps1",
}
# Диспетчеры, которые адресуют машину параметром (-Vm) и не читают Read-StreamConfig.ps1
NO_CONFIG = {"80-scenario.ps1", "lib-com.ps1"}
CHANGING = re.compile(
    r"^\s*(New-VMSwitch|New-VM|New-NetIPAddress|Remove-VM|Remove-VMSwitch|Remove-NetIPAddress|"
    r"Set-VMNetworkAdapter|Add-VMNetworkAdapter|Rename-VMNetworkAdapter|"
    r"Disconnect-VMNetworkAdapter|Add-VMDvdDrive|Set-VMFirmware|Set-VMMemory|Set-VMProcessor|"
    r"Set-VM|Start-VM|Stop-VM|Invoke-WebRequest\s.*-OutFile|Remove-Item)\b",
    re.MULTILINE,
)
# Имена и адреса стенда — только в конфиге
LITERALS = ("10.77.", "mlsiem-broker", "mlsiem-mgmt", "mlsiem-lab", "00:15:5D", "00155D")
SCRIPTS = sorted(HYPERV.glob("*.ps1"))


def _text(p: Path) -> str:
    return p.read_text(encoding="utf-8-sig")


def test_expected_scripts_exist():
    names = {p.name for p in SCRIPTS}
    assert {
        "00-check.ps1",
        "10-network.ps1",
        "20-vm-broker.ps1",
        "30-post-install.ps1",
        "90-remove.ps1",
        "Read-StreamConfig.ps1",
        # фича 006: машины стенда, сенсор, сценарии, удаление
        "40-vm-victim.ps1",
        "50-vm-attacker.ps1",
        "45-post-install.ps1",
        "60-sensor-adapter.ps1",
        "70-sensor.ps1",
        "80-scenario.ps1",
        "91-remove-lab.ps1",
    } <= names


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_utf8_bom(script):
    # Windows PowerShell 5.1 читает файл без BOM в кодировке ANSI — кириллица сломалась бы
    assert script.read_bytes().startswith(b"\xef\xbb\xbf")


@pytest.mark.parametrize("script", [p for p in SCRIPTS if p.name not in READ_ONLY], ids=str)
def test_changes_only_with_should_process(script):
    text = _text(script)
    assert "[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]" in text
    lines = text.splitlines()
    for m in CHANGING.finditer(text):
        n = text[: m.start()].count("\n")
        window = "\n".join(lines[max(0, n - 12) : n])
        assert "$PSCmdlet.ShouldProcess(" in window, f"{script.name}:{n + 1}: {lines[n].strip()}"


@pytest.mark.parametrize("script", [p for p in SCRIPTS if p.name not in READ_ONLY], ids=str)
def test_idempotent_checks(script):
    text = _text(script)
    # Перед созданием — проверка, что этого ещё нет; повторный запуск пишет «уже есть»
    for create, probe in (
        ("New-VMSwitch", "Get-VMSwitch"),
        ("New-VM ", "Get-VM "),
        ("New-NetIPAddress", "Get-NetIPAddress"),
    ):
        if create in text:
            assert probe in text and "-ErrorAction SilentlyContinue" in text


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_no_hardcoded_stand_values(script):
    text = _text(script)
    for literal in LITERALS:
        assert literal not in text, f"{script.name}: {literal} — должно браться из конфига"
    if script.name != "Read-StreamConfig.ps1" and script.name not in NO_CONFIG:
        assert "Read-StreamConfig.ps1" in text


@pytest.mark.skipif(shutil.which("powershell") is None, reason="нет Windows PowerShell")
def test_syntax():
    cmd = (
        "$bad = 0; foreach ($f in Get-ChildItem '" + str(HYPERV) + "\\*.ps1') { $e = $null; "
        "[System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, "
        "[ref]$e) | Out-Null; foreach ($x in $e) { Write-Output ($f.Name + ': ' + $x.Message); "
        "$bad++ } }; exit $bad"
    )
    done = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 0, done.stdout + done.stderr
