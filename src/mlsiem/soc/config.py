"""Чтение и проверка configs/soc.yaml.

Здесь живут все «ручки» SOC-части: окно группировки, таблица серьёзности, защищённые адреса,
правила плейбуков, путь к базе и адрес API. В коде этих чисел нет — только здесь.

Правила плейбуков проверяются строго: неизвестное условие в `when` или опечатка в имени
действия должны ронять запуск сразу, а не тихо превращать правило в «подходит всегда».
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from mlsiem.data.config import ConfigError, _get

DEFAULT_SOC_CONFIG = Path("configs/soc.yaml")
SEVERITY_LEVELS = ("low", "medium", "high", "critical")
ACTION_TYPES = ("block_source_ip", "isolate_host", "observe", "manual_review")
# Какие условия можно писать в `when` и какого они типа
RULE_CONDITIONS: dict[str, type] = {
    "protected": bool,
    "class_in": list,
    "max_targets": int,
    "min_severity": str,
}


@dataclass(frozen=True)
class ApiConfig:
    host: str
    port: int


@dataclass(frozen=True)
class Rule:
    id: str
    when: dict[str, Any]
    action: str


@dataclass(frozen=True)
class SocConfig:
    db: Path
    runs_dir: Path
    api: ApiConfig
    window_ms: int
    severity_base: dict[str, str]
    bump_at: int
    protected_ips: tuple[str, ...]
    rules: tuple[Rule, ...]
    raw: dict[str, Any]


def _level(value: Any, key: str) -> str:
    if value not in SEVERITY_LEVELS:
        raise ConfigError(
            f"ключ {key}: уровень серьёзности должен быть одним из {list(SEVERITY_LEVELS)}, "
            f"а записано {value!r}"
        )
    return value


def _parse_rule(raw_rule: Any, i: int) -> Rule:
    key = f"playbook.rules[{i}]"
    if not isinstance(raw_rule, dict):
        raise ConfigError(f"ключ {key}: правило должно быть словарём с полями id, when, action")
    for field in ("id", "when", "action"):
        if field not in raw_rule:
            raise ConfigError(f"в конфиге нет ключа {key}.{field}")
    rule_id = raw_rule["id"]
    if not isinstance(rule_id, str) or not rule_id:
        raise ConfigError(f"ключ {key}.id: нужна непустая строка")
    action = raw_rule["action"]
    if action not in ACTION_TYPES:
        raise ConfigError(
            f"ключ {key}.action: действие должно быть одним из {list(ACTION_TYPES)}, "
            f"а записано {action!r}"
        )
    when = raw_rule["when"] or {}
    if not isinstance(when, dict):
        raise ConfigError(f"ключ {key}.when: нужен словарь условий (пустой — «всегда»)")
    for cond, value in when.items():
        if cond not in RULE_CONDITIONS:
            raise ConfigError(
                f"ключ {key}.when.{cond}: неизвестное условие; допустимы {list(RULE_CONDITIONS)}"
            )
        kind = RULE_CONDITIONS[cond]
        # bool — подкласс int, поэтому `max_targets: true` отсекаем явно
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            raise ConfigError(
                f"ключ {key}.when.{cond}: ожидался тип {kind.__name__}, а записано {value!r}"
            )
    if "min_severity" in when:
        _level(when["min_severity"], f"{key}.when.min_severity")
    if "class_in" in when and not all(isinstance(c, str) for c in when["class_in"]):
        raise ConfigError(f"ключ {key}.when.class_in: нужен список имён классов")
    return Rule(id=rule_id, when=dict(when), action=action)


def parse_soc_config(raw: Any) -> SocConfig:
    if not isinstance(raw, dict):
        raise ConfigError("конфиг SOC: ожидался словарь верхнего уровня")

    base_raw = _get(raw, "severity.base", dict)
    base = {cls: _level(level, f"severity.base.{cls}") for cls, level in base_raw.items()}
    bump_at = _get(raw, "severity.bump_at", int)
    if bump_at < 1:
        raise ConfigError(f"ключ severity.bump_at: нужно целое ≥ 1, а записано {bump_at}")

    window_ms = _get(raw, "grouping.window_ms", int)
    if window_ms < 0:
        raise ConfigError(
            f"ключ grouping.window_ms: окно не может быть отрицательным ({window_ms})"
        )

    protected = _get(raw, "protected_ips", list)
    if not all(isinstance(ip, str) for ip in protected):
        raise ConfigError("ключ protected_ips: нужен список IP-адресов строками")

    rules_raw = _get(raw, "playbook.rules", list)
    if not rules_raw:
        raise ConfigError("ключ playbook.rules: нужно хотя бы одно правило")
    rules = tuple(_parse_rule(r, i) for i, r in enumerate(rules_raw))
    ids = [r.id for r in rules]
    if len(set(ids)) != len(ids):
        raise ConfigError(f"ключ playbook.rules: id правил повторяются: {ids}")

    port = _get(raw, "api.port", int)
    if not 0 < port < 65536:
        raise ConfigError(f"ключ api.port: порт вне диапазона 1–65535 ({port})")

    return SocConfig(
        db=Path(_get(raw, "db", str)),
        runs_dir=Path(_get(raw, "runs_dir", str)),
        api=ApiConfig(host=_get(raw, "api.host", str), port=port),
        window_ms=window_ms,
        severity_base=base,
        bump_at=bump_at,
        protected_ips=tuple(protected),
        rules=rules,
        raw=raw,
    )


def load_soc_config(path: str | Path = DEFAULT_SOC_CONFIG) -> SocConfig:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"не найден файл конфига {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: не читается как YAML: {exc}") from exc
    return parse_soc_config(raw)
