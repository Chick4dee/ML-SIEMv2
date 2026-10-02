"""Реестр и запуск сценариев атак на стенде (фича 006, research R9/R11, FR-012…FR-014).

Работает на атакующей машине (её раннер вызывает хост по каналу управления, R6) и на хосте
(`mlsiem lab scenario list`, тесты). Поэтому, как `journal.py`, — только стандартная
библиотека, а настройки — обычные словари из `configs/stream.yaml` (разделы `lab` и
`scenarios`), которые seed-ISO кладёт на машину файлом `/etc/mlsiem/lab.json`.

Главные правила (конституция V, spec FR-013):
- цель сценария обязана лежать в сети стенда `lab.subnet`; иначе запуск отклоняется ДО старта
  инструмента и попадает в журнал как `rejected` — атака физически не может уйти за стенд;
- одновременно идёт один сценарий: следы двух атак в одном окне разметки неразделимы;
- у каждого запуска есть предел длительности (`duration_limit_s`) — инструмент убивается по
  нему: «шторм пакетов» (Edge) не должен утопить сенсор и жертву.
"""

from __future__ import annotations

import ipaddress
import os
import shlex
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from mlsiem.lab import journal

SERVICE_PORTS = {"web": 80, "ssh": 22, "ftp": 21, "dns": 53}
# Что подставляется в `args` сценария; остальные {…} — ошибка (опечатка в конфиге)
PLACEHOLDERS = ("target", "port", "ssh_user", "pcap")


class ScenarioError(ValueError):
    """Сценарий не найден или описан неверно (ошибка конфига, а не отказ по безопасности)."""


class ScenarioRejected(Exception):
    """Запуск отклонён политикой стенда (цель вне сети, параллельный запуск); `reason` —
    причина для журнала и вывода."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


Executor = Callable[[list[str], float], int]


def default_executor(argv: list[str], timeout_s: float) -> int:
    """Запускает инструмент и ждёт не дольше `timeout_s`; по истечении — убивает.

    Возвращает код возврата (при убийстве по пределу — 0: упор в предел для длинной атаки —
    штатное завершение, см. `ScenarioRunner.run`). Нет программы → FileNotFoundError."""
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return 0


# ---------------------------------------------------------------- реестр


def find_scenario(raw: dict, name: str, version: str | None = None) -> dict:
    items = raw.get("scenarios") or []
    for sc in items:
        if sc.get("name") == name and (version is None or str(sc.get("version")) == str(version)):
            return sc
    known = ", ".join(f"{s.get('name')}@{s.get('version')}" for s in items) or "нет"
    raise ScenarioError(
        f"сценарий {name}{'@' + str(version) if version else ''} не найден: {known}"
    )


def list_scenarios(raw: dict) -> list[dict]:
    """Сценарии для `lab scenario list`: имя, версия, инструмент, класс, цель."""
    return [
        {
            "name": sc["name"],
            "version": str(sc["version"]),
            "tool": sc["tool"],
            "target": sc["target"],
            "expected_class": sc["expected_class"],
            "duration_limit_s": sc["duration_limit_s"],
        }
        for sc in raw.get("scenarios") or []
    ]


def victim_ip(raw: dict) -> str:
    return raw["lab"]["victim"]["ip"]


def attacker_ip(raw: dict) -> str:
    return raw["lab"]["attacker"]["ip"]


def targets_of(raw: dict, sc: dict) -> list[str]:
    """Адреса целей сценария: пока одна жертва стенда. Контрольный сценарий дополнительно
    «целится» в адреса подмены — они тоже проверяются на принадлежность стенду."""
    out = [victim_ip(raw)]
    if sc.get("dst_map"):
        out.append(_map_new(sc["dst_map"]))
    if sc.get("src_map"):
        out.append(_map_new(sc["src_map"]))
    return list(dict.fromkeys(out))


def _map_new(entry: str) -> str:
    """`старый:новый` → новый адрес (без префикса /32)."""
    try:
        _, new = entry.split(":", 1)
        return new.split("/", 1)[0].strip()
    except ValueError:
        raise ScenarioError(f"подмена адресов {entry!r}: нужен вид старый:новый") from None


def check_targets(raw: dict, targets: list[str]) -> None:
    """Все цели в сети стенда, иначе `ScenarioRejected` (FR-013)."""
    subnet = ipaddress.ip_network(raw["lab"]["subnet"])
    bad = []
    for t in targets:
        try:
            if ipaddress.ip_address(t) not in subnet:
                bad.append(t)
        except ValueError:
            bad.append(t)
    if bad:
        raise ScenarioRejected(
            f"цель вне сети стенда {subnet}: {', '.join(bad)} — сценарии бьют только по стенду"
        )


# ---------------------------------------------------------------- команды


def render_args(raw: dict, sc: dict, **extra: str) -> list[str]:
    """Аргументы сценария после подстановки {target}, {port}, {ssh_user}, {pcap}."""
    values = {
        "target": victim_ip(raw),
        "port": str(SERVICE_PORTS.get(sc["target"], "")),
        "ssh_user": raw["lab"]["victim"]["ssh_user"],
        "pcap": sc.get("pcap") or "",
        **extra,
    }
    try:
        text = sc["args"].format(**values)
    except KeyError as exc:
        raise ScenarioError(
            f"сценарий {sc['name']}: в args неизвестная подстановка {exc}; допустимы "
            f"{', '.join('{' + p + '}' for p in PLACEHOLDERS)}"
        ) from None
    return shlex.split(text)


def check_control_maps(raw: dict, sc: dict) -> None:
    """Контрольный сценарий: переписанные адреса обязаны лежать в сети стенда (R9, FR-013).

    Иначе tcpreplay отправил бы трафик с чужими адресами — и либо он ушёл бы «не туда», либо
    инцидент указал бы не на машину стенда. Проверяется ДО сборки артефакта и до запуска.
    """
    new_addrs = [_map_new(sc["src_map"]), _map_new(sc["dst_map"])]
    check_targets(raw, new_addrs)


def control_rewrite_command(sc: dict, out_pcap: str | Path) -> list[str]:
    """Команда `tcprewrite` сборки артефакта контрольного сценария: фрагмент → адреса стенда,
    пересчёт контрольных сумм. Сам фрагмент отбирает владелец из test `unsw_time` (узнаваемый
    класс с высокой поимкой модели), поэтому он приходит параметром `sc['pcap']`."""
    return [
        "tcprewrite",
        pnat_arg(sc),
        "--fixcsum",
        f"--infile={sc['pcap']}",
        f"--outfile={out_pcap}",
    ]


def pnat_arg(sc: dict) -> str:
    """`--pnat` для tcprewrite: оба адреса подменяются в обе стороны потока (R9).
    `src_map`/`dst_map` — «исходный_адрес:адрес_стенда»."""
    parts = []
    for entry in (sc["src_map"], sc["dst_map"]):
        old, new = entry.split(":", 1)
        old, new = old.strip(), new.strip()
        parts.append(f"{old}/32:{new}/32" if "/" not in old else f"{old}:{new}")
    return "--pnat=" + ",".join(parts)


def commands(raw: dict, sc: dict, workdir: str | Path) -> list[list[str]]:
    """Последовательность команд сценария. Обычный — одна команда инструмента; контрольный —
    сначала `tcprewrite` (подмена адресов на стенд с пересчётом контрольных сумм), потом
    `tcpreplay` переписанного файла (R9)."""
    if sc["tool"] == "tcpreplay":
        check_control_maps(raw, sc)
        rewritten = str(Path(workdir) / f"{sc['name']}.rewritten.pcap")
        rewrite = control_rewrite_command(sc, rewritten)
        return [rewrite, ["tcpreplay", *render_args(raw, sc, pcap=rewritten)]]
    return [[sc["tool"], *render_args(raw, sc)]]


# ---------------------------------------------------------------- блокировка «один сценарий»


class _Lock:
    """Файловая блокировка (O_EXCL): второй запуск видит файл и отклоняется. В файле — run_uid."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._held = False

    def acquire(self, run_uid: str) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return False
        with os.fdopen(fd, "w") as f:
            f.write(run_uid)
        self._held = True
        return True

    def holder(self) -> str:
        try:
            return self.path.read_text(encoding="utf-8").strip()
        except OSError:
            return "?"

    def release(self) -> None:
        if self._held:
            self.path.unlink(missing_ok=True)
            self._held = False


class ScenarioRunner:
    """Запускает сценарии по реестру, пишет журнал (FR-014).

    `executor` и `clock` подменяются в тестах: без инструментов и без реального ожидания.
    """

    def __init__(
        self,
        raw: dict,
        journal_path: str | Path,
        *,
        executor: Executor = default_executor,
        clock: Callable[[], str] = journal.now_iso,
        lock_path: str | Path | None = None,
        workdir: str | Path | None = None,
    ):
        self.raw = raw
        self.journal_path = Path(journal_path)
        self.executor = executor
        self.clock = clock
        self.lock = _Lock(lock_path or self.journal_path.with_suffix(".lock"))
        self.workdir = Path(workdir) if workdir else Path(tempfile.gettempdir())

    def _record(self, sc: dict, started: str, ended: str, outcome: str, **kw) -> dict:
        rec = journal.make_record(
            name=sc["name"],
            version=str(sc["version"]),
            attacker_ip=attacker_ip(self.raw),
            targets=targets_of(self.raw, sc),
            expected_class=sc["expected_class"],
            started_at=started,
            ended_at=ended,
            outcome=outcome,
            **kw,
        )
        journal.append(self.journal_path, rec)
        return rec

    def run(self, name: str, version: str | None = None) -> dict:
        """Выполняет сценарий и возвращает запись журнала.

        Отказы политики (цель вне стенда, параллельный запуск) — запись `rejected` и тот же
        record в результате: вызывающий (CLI) по `outcome` печатает причину и возвращает 1.
        Неизвестный сценарий — `ScenarioError` (журнал не пишется: запуска не было).
        """
        sc = find_scenario(self.raw, name, version)
        started = self.clock()
        try:
            check_targets(self.raw, targets_of(self.raw, sc))
        except ScenarioRejected as exc:
            return self._record(sc, started, self.clock(), "rejected", reject_reason=exc.reason)
        run_uid = journal.new_run_uid()
        if not self.lock.acquire(run_uid):
            return self._record(
                sc,
                started,
                self.clock(),
                "rejected",
                reject_reason=f"уже идёт другой сценарий ({self.lock.holder()}): параллельный "
                "запуск отклонён — следы двух атак в одном окне разметки неразделимы",
            )
        try:
            cmds = commands(self.raw, sc, self.workdir)
            started = self.clock()
            outcome = "completed"
            deadline_s = float(sc["duration_limit_s"])
            try:
                for i, argv in enumerate(cmds):
                    rc = self.executor(argv, deadline_s)
                    if rc != 0 and i < len(cmds) - 1:
                        # Подготовительный шаг (tcprewrite) не удался: переигрывать нечего
                        outcome = "aborted"
                        break
            except (OSError, subprocess.SubprocessError):
                # Нет инструмента или он не смог стартовать: атаки не было — «прервано»
                outcome = "aborted"
            return self._record(sc, started, self.clock(), outcome, run_uid=run_uid)
        finally:
            self.lock.release()
