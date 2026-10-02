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

NAME = "background_normal"
VERSION = "1"


def step_command(raw: dict, service: str) -> list[str]:
    """Команда одного шага нормы для службы жертвы (правильные учётные данные из конфига)."""
    victim = raw["lab"]["victim"]
    ip = victim["ip"]
    timeout = str(int(raw["normal"]["step_timeout_s"]))
    if service == "web":
        return ["curl", "-s", "-o", "/dev/null", "--max-time", timeout, f"http://{ip}/"]
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
            f"{victim['ssh_user']}@{ip}",
            "uname -a",
        ]
    if service == "ftp":
        return ["curl", "-s", "-o", "/dev/null", "--max-time", timeout, f"ftp://{ip}/"]
    if service == "dns":
        return ["dig", f"@{ip}", "+time=" + timeout, "+tries=1", "lab.test", "A"]
    raise ValueError(f"неизвестная служба нормы {service!r}")


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
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._started is not None

    def step(self) -> str:
        """Один шаг нормы: выбрать службу по весам и выполнить команду. Возвращает службу."""
        services, weights = weighted_services(self.raw)
        service = self.rng.choices(services, weights=weights, k=1)[0]
        try:
            self.executor(
                step_command(self.raw, service), float(self.raw["normal"]["step_timeout_s"])
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

        def loop() -> None:
            while not self._stop.is_set():
                self.step()
                self._stop.wait(period)

        self._thread = threading.Thread(target=loop, name="mlsiem-normal", daemon=True)
        self._thread.start()

    def stop(self) -> dict | None:
        """Останавливает норму и пишет интервал в журнал; None, если она не была запущена."""
        if not self.running:
            return None
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=float(self.raw["normal"]["step_timeout_s"]) + 5)
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
