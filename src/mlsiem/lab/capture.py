"""Запись сеанса на сенсорной машине: tcpdump на приёмнике зеркала портов (фича 008, R15, FR-025).

Сенсор стенда слушает сеть стенда через зеркало портов Hyper-V (006); для набора запись сеанса
сохраняется в pcap на сенсорной машине и по окончании сеанса забирается на хост. Признаки потоков
считаются потом тем же экстрактором 001 из этой записи (train = serve), поэтому на время сбора
потребитель и консоль можно не держать (память хоста, R13).

Управление — по SSH через служебную сеть (адрес сенсорной машины в `collection.capture.ssh`):
это не сеть стенда, изоляция не нарушается. Все вызовы идут через подменяемый `runner`, поэтому
логику проверяют тесты без машины.
"""

from __future__ import annotations

import hashlib
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

DEFAULT_SSH_OPTIONS = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=8",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "StrictHostKeyChecking=no",
]


class CaptureError(RuntimeError):
    """Запись сеанса не запустилась, не остановилась или не забралась; текст — по-русски."""


def _default_runner(argv: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
    )


class SensorCapture:
    def __init__(
        self,
        ssh_target: str,
        iface: str,
        remote_dir: str,
        *,
        rotate_mb: int = 4000,
        ssh_options: list[str] | None = None,
        runner: Callable[[list[str], float], subprocess.CompletedProcess] = _default_runner,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.target = ssh_target
        self.iface = iface
        self.remote_dir = remote_dir.rstrip("/")
        self.rotate_mb = int(rotate_mb)
        self.ssh_options = list(ssh_options if ssh_options is not None else DEFAULT_SSH_OPTIONS)
        self._run = runner
        self._sleep = sleep

    @classmethod
    def from_config(cls, raw: dict, **kw) -> SensorCapture:
        c = raw["collection"]["capture"]
        return cls(
            c["ssh"],
            c["iface"],
            c["remote_dir"],
            rotate_mb=c.get("rotate_mb", 4000),
            ssh_options=c.get("ssh_options"),
            **kw,
        )

    # ------------------------------------------------------------ низкий уровень

    def _ssh(self, command: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
        try:
            return self._run(["ssh", *self.ssh_options, self.target, command], timeout)
        except FileNotFoundError as exc:
            raise CaptureError("ssh не найден на хосте") from exc
        except subprocess.TimeoutExpired as exc:
            raise CaptureError(
                f"сенсорная машина {self.target} не ответила за {timeout:g} с"
            ) from exc

    def session_dir(self, session_id: str) -> str:
        return f"{self.remote_dir}/{session_id}"

    # ------------------------------------------------------------ проверки

    def check(self) -> dict:
        """Связь, наличие tcpdump и интерфейса, свободное место (МБ). Исключение — запись "
        "невозможна."""
        done = self._ssh(
            f"sudo -n mkdir -p {self.remote_dir} && echo dir=ok; "
            f"command -v tcpdump >/dev/null && echo tcpdump=ok; ip link show {self.iface} "
            ">/dev/null 2>&1 && echo iface=ok; "
            f"df -Pm {self.remote_dir} 2>/dev/null | tail -1 | awk '{{print \"free_mb=\" $4}}'",
            30,
        )
        info = dict(line.split("=", 1) for line in done.stdout.split() if "=" in line)
        problems = []
        if done.returncode != 0 and "dir" not in info:
            problems.append(
                f"нет доступа к {self.target}: {(done.stderr or done.stdout).strip()[:120]}"
            )
        if info.get("tcpdump") != "ok":
            problems.append("на сенсорной машине нет tcpdump")
        if info.get("iface") != "ok":
            problems.append(f"на сенсорной машине нет интерфейса {self.iface}")
        if problems:
            raise CaptureError("; ".join(problems))
        info["free_mb"] = int(info.get("free_mb", 0) or 0)
        return info

    def clock_skew_s(self, host_now: Callable[[], float] = time.time) -> float:
        """Расхождение часов хоста и сенсорной машины, секунды (положительное — машина впереди)."""
        t0 = host_now()
        done = self._ssh("date -u +%s.%N", 15)
        t1 = host_now()
        try:
            remote = float(done.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError) as exc:
            raise CaptureError(f"не разобрано время сенсорной машины: {done.stdout!r}") from exc
        return remote - (t0 + t1) / 2

    # ------------------------------------------------------------ сеанс

    def start(self, session_id: str) -> dict:
        d = self.session_dir(session_id)
        # -Z root: tcpdump иначе сбрасывает права до пользователя tcpdump и не может писать в
        # каталог root;
        # pid пишется по абсолютному пути (cd внутри фонового задания не меняет каталог остальной
        # команды)
        cmd = (
            f"sudo -n mkdir -p {d} && sudo -n sh -c 'nohup tcpdump -i {self.iface} -s 0 -U -Z root "
            f"-C {self.rotate_mb} -w {d}/session.pcap > {d}/tcpdump.log 2>&1 & echo $! > "
            f"{d}/tcpdump.pid' && sleep 2 && "
            f"sudo -n kill -0 $(cat {d}/tcpdump.pid) && echo started"
        )
        done = self._ssh(cmd, 45)
        if "started" not in done.stdout:
            raise CaptureError(
                f"tcpdump не запустился: {(done.stderr or done.stdout).strip()[:200]}"
            )
        return {"session_id": session_id, "remote_dir": d}

    def is_running(self, session_id: str) -> bool:
        d = self.session_dir(session_id)
        done = self._ssh(
            f"sudo -n kill -0 $(cat {d}/tcpdump.pid 2>/dev/null) 2>/dev/null && echo yes || echo "
            "no",
            20,
        )
        return done.stdout.strip().endswith("yes")

    def stop(self, session_id: str, wait_s: float = 40.0) -> dict:
        """Останавливает tcpdump (SIGINT: он дописывает буфер) и возвращает счётчики из его "
        "журнала."""
        d = self.session_dir(session_id)
        self._ssh(f"sudo -n kill -INT $(cat {d}/tcpdump.pid) 2>/dev/null; true", 20)
        waited = 0.0
        while waited < wait_s and self.is_running(session_id):
            self._sleep(1.0)
            waited += 1.0
        if self.is_running(session_id):
            raise CaptureError(f"tcpdump не остановился за {wait_s:g} с")
        log = self._ssh(f"tail -5 {d}/tcpdump.log", 20).stdout
        return parse_tcpdump_log(log)

    def fetch(self, session_id: str, local_dir: str | Path) -> list[dict]:
        """Забирает файлы сеанса на хост; возвращает [{name, bytes, sha256}] и проверяет размер."""
        local = Path(local_dir)
        local.mkdir(parents=True, exist_ok=True)
        d = self.session_dir(session_id)
        listing = self._ssh(f"ls -1 {d}", 20).stdout.split()
        out = []
        for name in listing:
            if not (name.startswith("session.pcap") or name == "tcpdump.log"):
                continue
            argv = ["scp", *self.ssh_options, f"{self.target}:{d}/{name}", str(local / name)]
            done = self._run(argv, 3600)
            if done.returncode != 0:
                raise CaptureError(f"scp {name}: {(done.stderr or '').strip()[:160]}")
            data = (
                (local / name).read_bytes()
                if (local / name).stat().st_size < 64 * 1024 * 1024
                else None
            )
            h = hashlib.sha256()
            if data is not None:
                h.update(data)
            else:
                with open(local / name, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
            out.append(
                {"name": name, "bytes": (local / name).stat().st_size, "sha256": h.hexdigest()}
            )
        if not any(o["name"].startswith("session.pcap") for o in out):
            raise CaptureError(f"в {d} нет файлов записи session.pcap*")
        return out


def parse_tcpdump_log(text: str) -> dict:
    """Счётчики из хвоста журнала tcpdump: 'N packets captured', 'M packets dropped by kernel'."""
    stats = {"captured": None, "dropped": None}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "packets" and parts[2] == "captured":
            stats["captured"] = int(parts[0])
        if len(parts) >= 5 and parts[1] == "packets" and parts[2] == "dropped":
            stats["dropped"] = int(parts[0])
    return stats
