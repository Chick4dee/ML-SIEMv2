"""Раннер на атакующей машине: принимает команды хоста по последовательному порту (R6).

Зачем порт. Сеть стенда изолирована от хоста (FR-005), а у машин стенда нет адаптера в
служебной сети, поэтому хост управляет атакующим «снаружи сети» — через COM-порт ВМ Hyper-V
(`Set-VMComPort`, именованный канал на хосте). PowerShell Direct к Linux-гостям не работает
(он только для Windows-гостей), поэтому порт — основной путь, а не запасной (research R6).

Протокол: строка JSON-запрос → строка JSON-ответ `{"ok": true|false, ...}`. Команды:
`ping`, `clock`, `probe`, `scenario`, `variant` (008), `tools` (008), `put_file` (008), `diag`
(008), `restart` (008), `normal`, `journal`. Одна команда за раз; сценарий
блокирует канал на время запуска — хост ждёт ответ с запасом сверх `duration_limit_s`.

`handle()` — чистая функция «запрос → ответ» без порта: на ней строятся тесты (канал без ВМ).
Как и остальной `mlsiem.lab`, файл — только стандартная библиотека.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
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
from mlsiem.lab.variants import VariantRunner, expand_variants, list_variants

DEFAULT_PORT = "/dev/ttyS0"
DEFAULT_CONFIG = "/etc/mlsiem/lab.json"
DEFAULT_JOURNAL = "/var/lib/mlsiem/journal.jsonl"
PROBE_TIMEOUT_S = 2.0
# Куда хост может класть файлы командой put_file (обновление кода раннера и конфига без SSH, 008)
PUT_ROOTS = ("/opt/mlsiem", "/etc/mlsiem", "/usr/share/wordlists", "/var/lib/mlsiem")
MAX_PUT_BYTES = 8 * 1024 * 1024
TOOL_EXTRA = ("curl", "dig", "ssh", "sshpass", "ip")
DIAG_EXTRA = (
    "ls",
    "cat",
    "which",
    "uname",
    "id",
    "df",
    "free",
    "ip",
    "ss",
    "systemctl",
    "tail",
    "head",
)


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
        self.variants = VariantRunner(raw, self.journal_path, executor=executor, clock=clock)


def tool_info(tool: str, version_arg: str = "--version", timeout_s: float = 5.0) -> dict | None:
    """Путь и первая строка вывода версии инструмента; None — инструмента нет на машине."""
    path = shutil.which(tool)
    if not path:
        return None
    try:
        done = subprocess.run(
            [path, version_arg], capture_output=True, text=True, timeout=timeout_s, errors="replace"
        )
        text = (done.stdout or done.stderr or "").strip().splitlines()
        version = text[0][:120] if text else ""
    except (OSError, subprocess.SubprocessError):
        version = ""
    return {"path": path, "version": version}


def tools_report(raw: dict) -> dict:
    """Инструменты всех вариантов и нормы: версии или None (недоступен) — для `lab tools check`."""
    report: dict = {}
    for v in expand_variants(raw):
        report.setdefault(v["tool"], tool_info(v["tool"], v.get("version_arg", "--version")))
    for t in TOOL_EXTRA:
        report.setdefault(t, tool_info(t, "-V" if t in ("ssh",) else "--version"))
    return report


def put_file(path: str, content_b64: str, mode: str | None = None) -> dict:
    """Записывает файл по команде хоста (только под PUT_ROOTS) и возвращает его размер и SHA-256."""
    target = os.path.realpath(path)
    if not any(target == r or target.startswith(r + os.sep) for r in PUT_ROOTS):
        raise ValueError(f"путь {path!r} вне разрешённых каталогов {list(PUT_ROOTS)}")
    data = base64.b64decode(content_b64)
    if len(data) > MAX_PUT_BYTES:
        raise ValueError(f"файл {len(data)} байт больше предела {MAX_PUT_BYTES}")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    tmp = target + ".part"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, target)
    if mode:
        os.chmod(target, int(mode, 8))
    return {"path": target, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def diag(raw: dict, argv: list[str], timeout_s: float = 10.0) -> dict:
    """Диагностический запуск разрешённой утилиты (инструменты вариантов и безвредные системные), "
    "вывод — хвост."""
    allowed = {v["tool"] for v in expand_variants(raw)} | set(TOOL_EXTRA) | set(DIAG_EXTRA)
    if not argv or argv[0] not in allowed:
        raise ValueError(
            f"diag: утилита {argv[:1]} не разрешена; допустимы {sorted(allowed)[:12]}…"
        )
    done = subprocess.run(
        argv, capture_output=True, text=True, timeout=min(float(timeout_s), 30.0), errors="replace"
    )
    return {
        "rc": done.returncode,
        "stdout": (done.stdout or "")[-800:],
        "stderr": (done.stderr or "")[-800:],
    }


def handle(state: RunnerState, request: dict) -> dict:
    """Один запрос → один ответ. Любая ошибка — `ok: false` с текстом, а не падение раннера:
    он живёт на машине часами и обязан пережить кривой запрос."""
    cmd = request.get("cmd")
    try:
        if cmd == "ping":
            return {
                "ok": True,
                "scenarios": list_scenarios(state.raw),
                "variants": list_variants(state.raw),
            }
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
        if cmd == "variant":
            rec = state.variants.run(
                request["scenario"],
                request.get("variant"),
                request.get("params") or {},
                source_ip=request.get("source_ip"),
                meta=request.get("meta") or {},
            )
            return {"ok": rec["outcome"] != "rejected", "record": rec}
        if cmd == "tools":
            return {"ok": True, "tools": tools_report(state.raw)}
        if cmd == "diag":
            return {
                "ok": True,
                **diag(
                    state.raw, [str(a) for a in request.get("argv", [])], request.get("timeout", 10)
                ),
            }
        if cmd == "restart":
            # Служба systemd (Restart=always) поднимет раннер с новым кодом; ответ уходит до выхода
            import threading

            threading.Timer(0.7, lambda: os._exit(0)).start()
            return {"ok": True, "restarting": True}
        if cmd == "put_file":
            return {
                "ok": True,
                **put_file(request["path"], request["content_b64"], request.get("mode")),
            }
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
    except (
        ScenarioError,
        journal.JournalError,
        RuntimeError,
        KeyError,
        ValueError,
        OSError,
    ) as exc:
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
