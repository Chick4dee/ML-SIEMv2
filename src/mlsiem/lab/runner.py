"""Раннер на атакующей машине: принимает команды хоста по последовательному порту (R6).

Зачем порт. Сеть стенда изолирована от хоста (FR-005), а у машин стенда нет адаптера в
служебной сети, поэтому хост управляет атакующим «снаружи сети» — через COM-порт ВМ Hyper-V
(`Set-VMComPort`, именованный канал на хосте). PowerShell Direct к Linux-гостям не работает
(он только для Windows-гостей), поэтому порт — основной путь, а не запасной (research R6).

Протокол: строка JSON-запрос → строка JSON-ответ `{"ok": true|false, ...}`. Команды:
`ping`, `clock`, `probe`, `scenario`, `normal`, `journal`. Одна команда за раз; сценарий
блокирует канал на время запуска — хост ждёт ответ с запасом сверх `duration_limit_s`.

`handle()` — чистая функция «запрос → ответ» без порта: на ней строятся тесты (канал без ВМ).
Как и остальной `mlsiem.lab`, файл — только стандартная библиотека.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from collections.abc import Callable
from pathlib import Path

from mlsiem.lab import journal
from mlsiem.lab.normal import NormalRunner
from mlsiem.lab.scenarios import (
    ScenarioError,
    ScenarioRunner,
    default_executor,
    list_scenarios,
)

DEFAULT_PORT = "/dev/ttyS0"
DEFAULT_CONFIG = "/etc/mlsiem/lab.json"
DEFAULT_JOURNAL = "/var/lib/mlsiem/journal.jsonl"
PROBE_TIMEOUT_S = 2.0


def tcp_probe(host: str, port: int, timeout_s: float = PROBE_TIMEOUT_S) -> bool:
    """Достучался ли до host:port по TCP за timeout_s (для проверки служб и изоляции)."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout_s):
            return True
    except OSError:
        return False


class RunnerState:
    """Всё, что раннер держит между командами: конфиг, журнал, исполнитель и норма."""

    def __init__(
        self,
        raw: dict,
        journal_path: str | Path = DEFAULT_JOURNAL,
        *,
        executor=default_executor,
        clock: Callable[[], str] = journal.now_iso,
        probe: Callable[[str, int, float], bool] = tcp_probe,
    ):
        self.raw = raw
        self.journal_path = Path(journal_path)
        self.clock = clock
        self.probe = probe
        self.scenarios = ScenarioRunner(raw, self.journal_path, executor=executor, clock=clock)
        self.normal = NormalRunner(raw, self.journal_path, executor=executor, clock=clock)


def handle(state: RunnerState, request: dict) -> dict:
    """Один запрос → один ответ. Любая ошибка — `ok: false` с текстом, а не падение раннера:
    он живёт на машине часами и обязан пережить кривой запрос."""
    cmd = request.get("cmd")
    try:
        if cmd == "ping":
            return {"ok": True, "scenarios": list_scenarios(state.raw)}
        if cmd == "clock":
            return {"ok": True, "now": state.clock()}
        if cmd == "probe":
            results = [
                {
                    "host": t["host"],
                    "port": int(t["port"]),
                    "reachable": state.probe(t["host"], int(t["port"]), float(t.get("timeout", 2))),
                }
                for t in request.get("targets", [])
            ]
            return {"ok": True, "results": results}
        if cmd == "scenario":
            rec = state.scenarios.run(request["name"], request.get("version"))
            return {"ok": rec["outcome"] != "rejected", "record": rec}
        if cmd == "normal":
            action = request.get("action")
            if action == "start":
                state.normal.start()
                return {"ok": True, "running": True}
            if action == "stop":
                rec = state.normal.stop()
                return {"ok": True, "running": False, "record": rec}
            return {"ok": False, "error": f"normal: действие {action!r} неизвестно (start|stop)"}
        if cmd == "journal":
            return {"ok": True, "records": journal.read(state.journal_path)}
        return {"ok": False, "error": f"неизвестная команда {cmd!r}"}
    except (ScenarioError, journal.JournalError, RuntimeError, KeyError, ValueError) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def handle_line(state: RunnerState, line: str) -> str:
    """Строка запроса → строка ответа (JSON); битый JSON — ответ-ошибка."""
    try:
        request = json.loads(line)
        if not isinstance(request, dict):
            raise ValueError("запрос должен быть JSON-объектом")
    except ValueError as exc:
        return json.dumps({"ok": False, "error": f"запрос не разобран: {exc}"}, ensure_ascii=False)
    return json.dumps(handle(state, request), ensure_ascii=False, separators=(",", ":"))


def serve(state: RunnerState, port_path: str = DEFAULT_PORT) -> None:  # pragma: no cover
    """Читает команды с порта и отвечает; на машине запускается службой systemd."""
    import termios
    import tty

    fd = os.open(port_path, os.O_RDWR | os.O_NOCTTY)
    tty.setraw(fd)
    attrs = termios.tcgetattr(fd)
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    buf = b""
    while True:
        chunk = os.read(fd, 4096)
        if not chunk:
            continue
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if line.strip():
                reply = handle_line(state, line.decode("utf-8", "replace")) + "\n"
                os.write(fd, reply.encode("utf-8"))


def main(argv: list[str] | None = None) -> int:  # pragma: no cover
    argv = sys.argv[1:] if argv is None else argv
    port = argv[0] if argv else DEFAULT_PORT
    config = Path(os.environ.get("MLSIEM_LAB_CONFIG", DEFAULT_CONFIG))
    raw = json.loads(config.read_text(encoding="utf-8"))
    serve(RunnerState(raw, os.environ.get("MLSIEM_LAB_JOURNAL", DEFAULT_JOURNAL)), port)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
