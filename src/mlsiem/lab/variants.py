"""Варианты сценариев и запуск с журналом версии 2 (фича 008, research R2–R5, R15).

Сценарий версии 2 группирует варианты: один класс атаки — несколько инструментов и наборов
параметров. Вариант = родительские поля сценария + свои (tool, args, source_bind, params,
duration_limit_s). Сценарий без `variants` (версия 1, 006) раскрывается в один вариант `default`:
старые конфиги и команда `lab scenario run <имя>` работают как раньше.

Как и `scenarios.py`/`journal.py`, модуль только на стандартной библиотеке — он копируется на
атакующую машину.

Привязка адреса источника (`source_bind`, R3):
- `flag <аргументы>` — флаги инструмента ({src}, {iface}) вставляются сразу после его имени;
- `route` — на время запуска маршрут в сеть стенда фиксируется с нужным src (запуски по одному);
- пусто — инструмент идёт с основного адреса.
Адрес-алиас добавляется на интерфейс до запуска (повторное добавление безвредно).
"""

from __future__ import annotations

import contextlib
import ipaddress
import shlex
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from mlsiem.lab import journal
from mlsiem.lab.scenarios import (
    SERVICE_PORTS,
    Executor,
    ScenarioError,
    ScenarioRejected,
    _Lock,
    attacker_ip,
    check_targets,
    default_executor,
    targets_of,
    victim_ip,
)

MIN_RUN_S = 3.0  # инструмент, упавший быстрее с ненулевым кодом, атаки не создал: запуск aborted
ACTIVE_SOURCES: set[str] = set()  # источники, с которых идёт атака: фоновая норма их обходит


def attacker_iface(raw: dict) -> str:
    return str(raw["lab"]["attacker"].get("iface", "lab0"))


def lab_prefix(raw: dict) -> int:
    return ipaddress.ip_network(raw["lab"]["subnet"]).prefixlen


def source_ips(raw: dict, role: str | None = None) -> dict[str, str]:
    """Имя источника → адрес из `lab.sources` (если раздела нет — один источник `attacker`)."""
    items = raw["lab"].get("sources")
    if not items:
        return {"attacker": attacker_ip(raw)}
    return {s["name"]: s["ip"] for s in items if role is None or s.get("role") == role}


def source_name_of(raw: dict, ip: str) -> str:
    for name, addr in source_ips(raw).items():
        if addr == ip:
            return name
    return ip


def expand_variants(raw: dict) -> list[dict]:
    """Плоский список вариантов всех сценариев (см. описание модуля)."""
    out = []
    for sc in raw.get("scenarios") or []:
        base = {k: v for k, v in sc.items() if k != "variants"}
        for v in sc.get("variants") or [{"name": "default"}]:
            item = {**base, **{k: val for k, val in v.items() if k != "name"}}
            item["scenario"] = sc["name"]
            item["variant"] = v["name"]
            item.setdefault("params", {})
            item.setdefault("source_bind", None)
            item["reserve_unknown"] = bool(
                v.get("reserve_unknown", sc.get("reserve_unknown", False))
            )
            item["hard"] = bool(v.get("hard", sc.get("hard", False)))
            out.append(item)
    return out


def find_variant(
    raw: dict, scenario: str, variant: str | None = None, version: str | None = None
) -> dict:
    items = [
        v
        for v in expand_variants(raw)
        if v["scenario"] == scenario
        and (version is None or str(v["version"]) == str(version))
        and (variant is None or v["variant"] == variant)
    ]
    if not items:
        known = ", ".join(f"{v['scenario']}/{v['variant']}" for v in expand_variants(raw)) or "нет"
        raise ScenarioError(f"вариант {scenario}/{variant or '*'} не найден: {known}")
    return items[0]


def list_variants(raw: dict) -> list[dict]:
    """Для `lab scenario list` и `lab tools check`: класс, инструмент, параметры, резерв."""
    return [
        {
            "scenario": v["scenario"],
            "version": str(v["version"]),
            "variant": v["variant"],
            "tool": v.get("tool_label") or v["tool"],
            "binary": v["tool"],
            "expected_class": v["expected_class"],
            "target": v["target"],
            "duration_limit_s": v["duration_limit_s"],
            "params": {k: list(d.get("values", [])) for k, d in v["params"].items()},
            "holdout": {
                k: list(d.get("holdout", [])) for k, d in v["params"].items() if d.get("holdout")
            },
            "reserve_unknown": v["reserve_unknown"],
            "hard": v["hard"],
        }
        for v in expand_variants(raw)
    ]


def resolve_params(var: dict, given: dict) -> dict:
    """Значения параметров варианта: заданные (должны входить в домен) + первые значения по "
    "умолчанию."""
    out = {}
    label = f"{var['scenario']}/{var['variant']}"
    for name, dom in var["params"].items():
        values = list(dom.get("values", []))
        if not values:
            raise ScenarioError(f"вариант {label}: у параметра {name} нет значений")
        if name in given:
            if given[name] not in values:
                raise ScenarioError(
                    f"вариант {label}: значение {given[name]!r} параметра {name} вне домена "
                    f"{values}"
                )
            out[name] = given[name]
        else:
            out[name] = values[0]
    extra = sorted(set(given) - set(var["params"]))
    if extra:
        raise ScenarioError(f"вариант {label}: неизвестные параметры {extra}")
    return out


def render_variant_args(raw: dict, var: dict, params: dict, src: str) -> list[str]:
    """Аргументы инструмента: {target}, {port}, {ssh_user}, {pcap}, {src}, {iface}, {subnet} и "
    "параметры."""
    values = {
        "target": victim_ip(raw),
        "port": str(SERVICE_PORTS.get(var["target"], "")),
        "ssh_user": raw["lab"]["victim"]["ssh_user"],
        "pcap": var.get("pcap") or "",
        "src": src,
        "iface": attacker_iface(raw),
        "subnet": raw["lab"]["subnet"],
        **{k: str(v) for k, v in params.items()},
    }
    try:
        text = var["args"].format(**values)
    except KeyError as exc:
        raise ScenarioError(
            f"вариант {var['scenario']}/{var['variant']}: в args неизвестная подстановка {exc}"
        ) from None
    return shlex.split(text)


def variant_plan(raw: dict, var: dict, params: dict, src: str) -> dict:
    """Команды запуска варианта: подготовка, основная команда, возврат маршрута (см. описание "
    "модуля)."""
    iface, prefix, subnet = attacker_iface(raw), lab_prefix(raw), raw["lab"]["subnet"]
    primary = attacker_ip(raw)
    pre: list[list[str]] = []
    post: list[list[str]] = []
    if src != primary:
        pre.append(["ip", "addr", "add", f"{src}/{prefix}", "dev", iface])
    bind = var.get("source_bind")
    tool_args = render_variant_args(raw, var, params, src)
    argv = [var["tool"], *tool_args]
    if bind == "route" and src != primary:
        pre.append(["ip", "route", "replace", subnet, "dev", iface, "src", src])
        post.append(["ip", "route", "replace", subnet, "dev", iface, "src", primary])
    elif isinstance(bind, str) and bind.startswith("flag "):
        flags = shlex.split(bind[5:].format(src=src, iface=iface))
        argv = [var["tool"], *flags, *tool_args]
    return {"pre": pre, "main": argv, "post": post}


class VariantRunner:
    """Запуск вариантов с журналом версии 2: источник, параметры, маркер начала, замок по источнику.

    Отдельный от `ScenarioRunner` класс, чтобы код 006 (`run`) не менялся; делит с ним журнал,
    исполнитель и часы. С разных источников запуски могут идти параллельно (замок на источник),
    с одного — только один: следы двух атак с одного адреса в окне разметки неразделимы.
    """

    def __init__(
        self,
        raw: dict,
        journal_path: str | Path,
        *,
        executor: Executor = default_executor,
        clock: Callable[[], str] = journal.now_iso,
        lock_dir: str | Path | None = None,
    ):
        self.raw = raw
        self.journal_path = Path(journal_path)
        self.executor = executor
        self.clock = clock
        self.lock_dir = Path(lock_dir) if lock_dir else self.journal_path.parent

    def _lock_for(self, src: str) -> _Lock:
        return _Lock(self.lock_dir / f"{self.journal_path.stem}.{src}.lock")

    def run(
        self,
        scenario: str,
        variant: str | None,
        params: dict | None = None,
        *,
        source_ip: str | None = None,
        meta: dict | None = None,
    ) -> dict:
        var = find_variant(self.raw, scenario, variant)
        params = resolve_params(var, params or {})
        src = source_ip or attacker_ip(self.raw)
        meta = {k: v for k, v in (meta or {}).items() if v is not None}
        run_uid = meta.pop("run_uid", None) or journal.new_run_uid()
        extra = {
            "variant": var["variant"],
            "tool": var.get("tool_label") or var["tool"],
            "params": params,
            "source_ip": src,
            "source": source_name_of(self.raw, src),
            "reserve_unknown": var["reserve_unknown"],
            "hard_normal": var["hard"],
            **meta,
        }
        targets = targets_of(self.raw, var)
        started = self.clock()

        def record(outcome: str, ended: str, **kw) -> dict:
            rec = journal.make_record(
                name=var["scenario"],
                version=str(var["version"]),
                attacker_ip=src,
                targets=targets,
                expected_class=var["expected_class"],
                started_at=started,
                ended_at=ended,
                outcome=outcome,
                run_uid=run_uid,
                **extra,
                **kw,
            )
            journal.append(self.journal_path, rec)
            return rec

        try:
            check_targets(self.raw, [*targets, src])
        except ScenarioRejected as exc:
            return record("rejected", self.clock(), reject_reason=exc.reason)
        lock = self._lock_for(src)
        if not lock.acquire(run_uid):
            return record(
                "rejected",
                self.clock(),
                reject_reason=f"с источника {src} уже идёт запуск ({lock.holder()}): "
                "параллельный запуск с одного адреса отклонён — "
                "следы двух атак в одном окне разметки неразделимы",
            )
        ACTIVE_SOURCES.add(src)
        try:
            plan = variant_plan(self.raw, var, params, src)
            started = self.clock()
            marker_extra = {
                k: v for k, v in extra.items() if k in journal.EXTRA_FIELDS and k != "source_ip"
            }
            journal.append_marker(
                self.journal_path,
                journal.make_start_marker(
                    run_uid=run_uid,
                    started_at=started,
                    name=var["scenario"],
                    source_ip=src,
                    version=str(var["version"]),
                    targets=targets,
                    expected_class=var["expected_class"],
                    **marker_extra,
                ),
            )
            outcome, why = "completed", None
            try:
                for argv in plan["pre"]:
                    self.executor(argv, 15.0)  # алиас или маршрут: «уже есть» — не ошибка запуска
                t0 = time.monotonic()
                rc = self.executor(plan["main"], float(var["duration_limit_s"]))
                if rc not in (0, None) and time.monotonic() - t0 < MIN_RUN_S:
                    tail = getattr(self.executor, "last_stderr", "") or ""
                    outcome, why = (
                        "aborted",
                        f"инструмент завершился с кодом {rc} за {time.monotonic() - t0:.1f} с: "
                        f"{tail[-200:]}",
                    )
            except (OSError, subprocess.SubprocessError) as exc:
                outcome, why = (
                    "aborted",
                    f"инструмент не запустился: {exc}",
                )  # нет инструмента: атаки не было
            finally:
                for argv in plan["post"]:
                    with contextlib.suppress(OSError, subprocess.SubprocessError):
                        self.executor(argv, 15.0)
            return record(outcome, self.clock(), **({"reject_reason": why} if why else {}))
        finally:
            ACTIVE_SOURCES.discard(src)
            lock.release()
