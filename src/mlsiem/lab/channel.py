"""Канал управления атакующей машиной с хоста (фича 006, research R6, FR-010/FR-015).

Хост общается с раннером на атакующей машине строкой JSON → строкой JSON (протокол — в
`mlsiem.lab.runner`). Сети между хостом и машиной стенда нет (изоляция FR-005), поэтому
транспорт — канал гипервизора; его реализует скрипт `stand/hyperv/80-scenario.ps1`
(COM-порт ВМ → именованный канал на хосте; запасной — PowerShell Direct для Windows-гостей).

Здесь два транспорта с одним интерфейсом `request(dict, timeout_s) -> dict`:
- `ScriptChannel` — вызывает 80-scenario.ps1 через PowerShell (на хосте со стендом);
- `LocalChannel` — зовёт `runner.handle_line` в том же процессе (тесты без ВМ).
Любой сбой канала — `ChannelError` с подсказкой, а не трассировка и не зависание.
"""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path
from typing import Protocol

from mlsiem.lab import runner

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "stand" / "hyperv" / "80-scenario.ps1"
# Запас ожидания ответа сверх предела сценария: накладные расходы канала и раннера
REPLY_MARGIN_S = 30.0


class ChannelError(RuntimeError):
    """Канал к машине недоступен или ответил неразборчиво; текст — по-русски."""


class Channel(Protocol):
    def request(self, req: dict, timeout_s: float = 20.0) -> dict: ...


class LocalChannel:
    """Раннер в этом же процессе — для тестов и для `lab` без стенда."""

    def __init__(self, state: runner.RunnerState):
        self.state = state

    def request(self, req: dict, timeout_s: float = 20.0) -> dict:
        return json.loads(runner.handle_line(self.state, json.dumps(req)))


class ScriptChannel:
    """Через `stand/hyperv/80-scenario.ps1 -Vm <имя> -Channel com|direct -RequestB64 …`."""

    def __init__(self, vm: str, channel: str = "com", script: Path = SCRIPT):
        self.vm, self.channel, self.script = vm, channel, Path(script)

    def request(self, req: dict, timeout_s: float = 20.0) -> dict:
        payload = base64.b64encode(json.dumps(req, ensure_ascii=False).encode("utf-8")).decode()
        cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self.script),
            "-Vm",
            self.vm,
            "-Channel",
            self.channel,
            "-RequestB64",
            payload,
            "-TimeoutS",
            str(int(timeout_s)),
        ]
        try:
            done = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_s + 10,
            )
        except FileNotFoundError as exc:
            raise ChannelError(
                "PowerShell не найден — управление стендом возможно только с хоста Windows"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ChannelError(
                f"машина {self.vm} не ответила за {timeout_s:g} с — она выключена или раннер не "
                f"запущен? (Start-VM {self.vm}; на машине: systemctl status mlsiem-lab-runner)"
            ) from exc
        out = (done.stdout or "").strip().splitlines()
        if done.returncode != 0 or not out:
            err = (done.stderr or done.stdout or "").strip().splitlines()
            raise ChannelError(
                f"канал к {self.vm} не открылся: {err[0] if err else f'код {done.returncode}'}"
            )
        try:
            reply = json.loads(out[-1])
        except json.JSONDecodeError as exc:
            raise ChannelError(f"ответ машины {self.vm} не разобран: {out[-1][:200]!r}") from exc
        if not isinstance(reply, dict):
            raise ChannelError(f"ответ машины {self.vm} не объект JSON")
        return reply


def make_channel(cfg) -> Channel:
    """Канал к атакующей машине по `lab.attacker.mgmt`."""
    if cfg.lab is None:
        raise ChannelError("в конфиге нет раздела lab — машины стенда не описаны")
    return ScriptChannel(cfg.lab.attacker.vm, "com" if cfg.lab.attacker.mgmt == "com" else "direct")
