"""Фоновая норма стенда (фича 006, research R14, FR-019).

Раннер на атакующей машине гоняет ОБЫЧНЫЙ трафик к службам жертвы: веб-запросы, вход по SSH с
правильным паролем тестовой учётки, скачивание файла по FTP, DNS-запросы. Это «чужая» benign
для замера ложных срабатываний (US4/US5). Интервал работы пишется в журнал сценариев как
запуск `background_normal` с `expected_class = benign`.

Как и `journal.py`/`scenarios.py`, модуль — только стандартная библиотека: он копируется на
атакующую машину. Состав и интенсивность — из раздела `normal` конфига (веса шагов в `mix`).

Детерминизм: выбор шага — по `random.Random(seed)`, сид задаётся при создании, так что тест
проверяет состав без случайностей; на машине сид берётся от времени.
"""

from __future__ import annotations

import random
import threading
from collections.abc import Callable
from pathlib import Path

from mlsiem.lab import journal
from mlsiem.lab.scenarios import Executor, attacker_ip, default_executor, victim_ip
from mlsiem.lab.variants import ACTIVE_SOURCES, source_ips

NAME = "background_normal"
VERSION = "1"


def step_command(raw: dict, service: str, source_ip: str | None = None) -> list[str]:
    """Команда одного шага нормы для службы жертвы (правильные учётные данные из конфига).

    `source_ip` (008) — адрес источника шага: норма идёт с нескольких адресов,
    чтобы адрес не определял класс."""
    victim = raw["lab"]["victim"]
    ip = victim["ip"]
    timeout = str(int(raw["normal"]["step_timeout_s"]))
    if service == "web":
        return [
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "--max-time",
            timeout,
            *_bind("curl", source_ip),
            f"http://{ip}/",
        ]
    if service == "ssh":
        # sshpass подаёт ПРАВИЛЬНЫЙ пароль тестовой учётки: это норма, а не перебор
        return [
            "sshpass",
            "-p",
            victim["ssh_password"],
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            f"ConnectTimeout={timeout}",
            *_bind("ssh", source_ip),
            f"{victim['ssh_user']}@{ip}",
            "uname -a",
        ]
    if service == "ftp":
        return [
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "--max-time",
            timeout,
            *_bind("curl", source_ip),
            f"ftp://{ip}/",
        ]
    if service == "dns":
        return [
            "dig",
            f"@{ip}",
            "+time=" + timeout,
            "+tries=1",
            *_bind("dig", source_ip),
            "lab.test",
            "A",
        ]
    raise ValueError(f"неизвестная служба нормы {service!r}")


def _bind(tool: str, source_ip: str | None) -> list[str]:
    """Флаги привязки адреса источника для утилит нормы (пусто — основной адрес)."""
    if not source_ip:
        return []
    return {"curl": ["--interface", source_ip], "ssh": ["-b", source_ip], "dig": ["-b", source_ip]}[
        tool
    ]


def normal_sources(raw: dict) -> list[str]:
    """Адреса источников нормы из `normal.sources` (имена из `lab.sources`); пусто — основной "
    "адрес."""
    names = raw["normal"].get("sources") or []
    ips = source_ips(raw)
    return [ips[n] for n in names if n in ips]


def weighted_services(raw: dict) -> tuple[list[str], list[int]]:
    mix = {k: int(v) for k, v in raw["normal"]["mix"].items() if int(v) > 0}
    return list(mix), list(mix.values())


class NormalRunner:
    """Фоновая норма: `start()` — поток-раннер, `stop()` — остановка и запись в журнал.

    `sleep` и `executor` подменяются в тестах; `run_steps(n)` делает n шагов синхронно (для
    теста состава без потоков и ожидания).
    """

    def __init__(
        self,
        raw: dict,
        journal_path: str | Path,
        *,
        executor: Executor = default_executor,
        clock: Callable[[], str] = journal.now_iso,
        seed: int | None = None,
    ):
        self.raw = raw
        self.journal_path = Path(journal_path)
        self.executor = executor
        self.clock = clock
        self.rng = random.Random(seed)
        self.steps_done: dict[str, int] = {}
        self._started: str | None = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    @property
    def running(self) -> bool:
        return self._started is not None

    def step(self) -> str:
        """Один шаг нормы: выбрать службу по весам и выполнить команду. Возвращает службу."""
        services, weights = weighted_services(self.raw)
        service = self.rng.choices(services, weights=weights, k=1)[0]
        # Источник шага: из настроенных, но не тот, с которого сейчас идёт атака (008, R7):
        # иначе потоки нормы попали бы в окно разметки атаки того же адреса
        pool = [ip for ip in normal_sources(self.raw) if ip not in ACTIVE_SOURCES]
        source = self.rng.choice(pool) if pool else None
        if normal_sources(self.raw) and not pool:
            return service  # все источники заняты атаками — шаг пропускается
        try:
            self.executor(
                step_command(self.raw, service, source), float(self.raw["normal"]["step_timeout_s"])
            )
        except OSError:
            # Нет curl/dig на машине — шаг не удался, норма продолжается: разовый сбой
            # утилиты не должен валить фоновую работу на часы
            return service
        self.steps_done[service] = self.steps_done.get(service, 0) + 1
        return service

    def run_steps(self, n: int) -> list[str]:
        return [self.step() for _ in range(n)]

    def start(self) -> None:
        if self.running:
            raise RuntimeError("фоновая норма уже запущена")
        self._started = self.clock()
        self._stop.clear()
        self.steps_done = {}
        period = float(self.raw["normal"]["period_s"])
        workers = max(1, int(self.raw["normal"].get("workers", 1)))

        def loop() -> None:
            while not self._stop.is_set():
                self.step()
                self._stop.wait(period)

        # Несколько рабочих потоков (008): набору нужна норма в тысячи потоков, а один шаг
        # — это процесс curl/dig/ssh; период и число рабочих задают интенсивность в конфиге
        self._threads = [
            threading.Thread(target=loop, name=f"mlsiem-normal-{i}", daemon=True)
            for i in range(workers)
        ]
        for t in self._threads:
            t.start()

    def stop(self) -> dict | None:
        """Останавливает норму и пишет интервал в журнал; None, если она не была запущена."""
        if not self.running:
            return None
        self._stop.set()
        for t in getattr(self, "_threads", []):
            t.join(timeout=float(self.raw["normal"]["step_timeout_s"]) + 5)
        return self.finish()

    def finish(self) -> dict:
        """Записывает интервал нормы (с начала до сейчас) как запуск с классом benign."""
        started, self._started = self._started, None
        rec = journal.make_record(
            name=NAME,
            version=VERSION,
            attacker_ip=attacker_ip(self.raw),
            targets=[victim_ip(self.raw)],
            expected_class=journal.BENIGN,
            started_at=started or self.clock(),
            ended_at=self.clock(),
            outcome="completed",
        )
        journal.append(self.journal_path, rec)
        return rec
