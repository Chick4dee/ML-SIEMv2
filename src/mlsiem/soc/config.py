"""Чтение и проверка configs/soc.yaml.

Здесь живут все «ручки» SOC-части: окно группировки, таблица серьёзности, защищённые адреса,
правила плейбуков, путь к базе и адрес API. В коде этих чисел нет — только здесь.

Правила плейбуков проверяются строго: неизвестное условие в `when` или опечатка в имени
действия должны ронять запуск сразу, а не тихо превращать правило в «подходит всегда».
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from dataclasses import field as dc_field
from pathlib import Path
from typing import Any

import yaml

from mlsiem.data.config import ConfigError, _get

DEFAULT_SOC_CONFIG = Path("configs/soc.yaml")
SEVERITY_LEVELS = ("low", "medium", "high", "critical")
ACTION_TYPES = ("block_source_ip", "isolate_host", "observe", "manual_review")
# Роли именованных сетей (фича 003). Метку «подозрительный источник» дают только victims и
# background, остальные — чтобы подписать адрес в карточке
NETWORK_ROLES = ("victims", "background", "infrastructure", "other")
REFRESH_RANGE = (3, 300)
# Сети по умолчанию — если в конфиге (например, от фичи 002) нет раздела networks. Это
# наблюдения прогона 002: оттуда пришли 17 из 66 «атак», на деле — ответные направления
DEFAULT_NETWORKS: tuple[dict[str, Any], ...] = (
    {"name": "жертвы UNSW-NB15", "role": "victims", "cidrs": ["149.171.126.0/24"]},
    {"name": "фон UNSW-NB15", "role": "background", "cidrs": ["59.166.0.0/24"]},
)
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
class NetworkConfig:
    """Именованная сеть: «жертвы», «фон» и т. п. (FR-018)."""

    name: str
    role: str
    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]


@dataclass(frozen=True)
class UiConfig:
    """Настройки консоли: интервал опроса и размеры страниц (data-model 003)."""

    refresh_seconds: int = 10
    page_size: int = 50
    recent_alerts: int = 20
    alerts_page_size: int = 50


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
    networks: tuple[NetworkConfig, ...] = ()
    ui: UiConfig = dc_field(default_factory=UiConfig)


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


def _parse_network(raw_net: Any, i: int) -> NetworkConfig:
    key = f"networks[{i}]"
    if not isinstance(raw_net, dict):
        raise ConfigError(f"ключ {key}: сеть должна быть словарём с полями name, role, cidrs")
    name = raw_net.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ConfigError(f"ключ {key}.name: нужна непустая строка — название сети")
    role = raw_net.get("role")
    if role not in NETWORK_ROLES:
        raise ConfigError(
            f"ключ {key}.role (сеть «{name}»): роль должна быть одной из {list(NETWORK_ROLES)}, "
            f"а записано {role!r}"
        )
    cidrs_raw = raw_net.get("cidrs")
    if not isinstance(cidrs_raw, list) or not cidrs_raw:
        raise ConfigError(f"ключ {key}.cidrs (сеть «{name}»): нужен непустой список диапазонов")
    cidrs = []
    for c in cidrs_raw:
        # strict=False: «10.0.0.5/24» — это опечатка человека, а не повод падать; берём сеть
        try:
            cidrs.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError as exc:
            raise ConfigError(
                f"ключ {key}.cidrs (сеть «{name}»): {c!r} — не диапазон адресов ({exc})"
            ) from exc
    return NetworkConfig(name=name.strip(), role=role, cidrs=tuple(cidrs))


def _parse_ui(raw_ui: Any) -> UiConfig:
    if raw_ui is None:
        return UiConfig()
    if not isinstance(raw_ui, dict):
        raise ConfigError("ключ ui: нужен словарь настроек консоли")
    wrapped = {"ui": {**UiConfig().__dict__, **raw_ui}}
    values = {k: _get(wrapped, f"ui.{k}", int) for k in UiConfig.__dataclass_fields__}
    lo, hi = REFRESH_RANGE
    if not lo <= values["refresh_seconds"] <= hi:
        raise ConfigError(
            f"ключ ui.refresh_seconds: интервал обновления должен быть от {lo} до {hi} секунд, "
            f"а записано {values['refresh_seconds']}"
        )
    for k in ("page_size", "recent_alerts", "alerts_page_size"):
        if values[k] < 1:
            raise ConfigError(f"ключ ui.{k}: нужно целое ≥ 1, а записано {values[k]}")
    return UiConfig(**values)


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

    # Раздел networks необязателен (конфиги 002 его не знают); пустой список — «без сетей»
    networks_raw = raw.get("networks", list(DEFAULT_NETWORKS))
    if not isinstance(networks_raw, list):
        raise ConfigError("ключ networks: нужен список сетей (name, role, cidrs)")

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
        networks=tuple(_parse_network(n, i) for i, n in enumerate(networks_raw)),
        ui=_parse_ui(raw.get("ui")),
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
