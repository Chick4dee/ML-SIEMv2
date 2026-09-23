"""Чтение и проверка configs/data.yaml.

Конфиг проверяется целиком сразу при запуске: лучше упасть за секунду с понятным
«нет ключа datasets.ctu13.timezone», чем через час обработки на середине датасета.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG = Path("configs/data.yaml")
CTU13_SCENARIOS = tuple(range(1, 14))
SPLIT_PARTS = ("train", "val", "test")


class ConfigError(ValueError):
    """Ошибка в конфиге. В сообщении всегда есть полное имя ключа."""


@dataclass(frozen=True)
class UnswConfig:
    root: Path
    gt_csv: Path
    pcap_glob: str  # шаблон относительно root


@dataclass(frozen=True)
class Ctu13Config:
    root: Path
    timezone: str


@dataclass(frozen=True)
class SplitConfig:
    quantiles: tuple[float, float]
    gap_ms: int
    ctu13_parts: dict[str, tuple[int, ...]]


@dataclass(frozen=True)
class AuditConfig:
    sample_per_part: int
    tree_depth: int
    dangerous_lift: float
    suspicious_pr_auc: float


@dataclass(frozen=True)
class DataConfig:
    unsw: UnswConfig
    ctu13: Ctu13Config
    v1_processed_dir: Path
    split: SplitConfig
    audit: AuditConfig
    seed: int
    # Сырой словарь нужен, чтобы хешировать параметры (например, для манифестов)
    raw: dict[str, Any]


def _get(raw: dict, dotted: str, kind: type | tuple[type, ...]) -> Any:
    """Достаёт значение по пути вида `a.b.c` и проверяет его тип.

    bool в Python — подкласс int, поэтому `gap_ms: true` прошёл бы проверку на int;
    такие случаи отсекаем явно.
    """
    node: Any = raw
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            raise ConfigError(f"в конфиге нет ключа {dotted}")
        node = node[part]
    kinds = kind if isinstance(kind, tuple) else (kind,)
    if isinstance(node, bool) and bool not in kinds or not isinstance(node, kinds):
        names = " или ".join(k.__name__ for k in kinds)
        raise ConfigError(f"ключ {dotted}: ожидался тип {names}, а записано {node!r}")
    return node


def _number(raw: dict, dotted: str) -> float:
    return float(_get(raw, dotted, (int, float)))


def _parse_split(raw: dict) -> SplitConfig:
    quantiles = _get(raw, "split.quantiles", list)
    if len(quantiles) != 2 or not all(
        isinstance(q, int | float) and not isinstance(q, bool) for q in quantiles
    ):
        raise ConfigError("ключ split.quantiles: нужны два числа, например [0.70, 0.85]")
    q1, q2 = float(quantiles[0]), float(quantiles[1])
    if not 0 < q1 < q2 < 1:
        raise ConfigError(f"ключ split.quantiles: нужно 0 < q1 < q2 < 1, а записано {quantiles}")

    parts_raw = _get(raw, "split.ctu13_parts", dict)
    parts: dict[str, tuple[int, ...]] = {}
    for name in SPLIT_PARTS:
        values = _get(raw, f"split.ctu13_parts.{name}", list)
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in values):
            raise ConfigError(f"ключ split.ctu13_parts.{name}: нужны номера сценариев")
        parts[name] = tuple(values)
    extra = set(parts_raw) - set(SPLIT_PARTS)
    if extra:
        raise ConfigError(f"ключ split.ctu13_parts: лишние части {sorted(extra)}")

    # Каждый сценарий ровно в одной части: иначе утечка (сценарий и в train, и в test)
    # или молча потерянные данные
    all_scenarios = [s for name in SPLIT_PARTS for s in parts[name]]
    if sorted(all_scenarios) != list(CTU13_SCENARIOS):
        raise ConfigError(
            "ключ split.ctu13_parts: сценарии 1–13 должны встречаться ровно по одному разу, "
            f"а записано {parts}"
        )
    return SplitConfig(quantiles=(q1, q2), gap_ms=_get(raw, "split.gap_ms", int), ctu13_parts=parts)


def load_config(path: str | Path = DEFAULT_CONFIG) -> DataConfig:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"не найден файл конфига {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: не читается как YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: ожидался словарь верхнего уровня")

    unsw_root = Path(_get(raw, "datasets.unsw.root", str))
    unsw = UnswConfig(
        root=unsw_root,
        gt_csv=unsw_root / _get(raw, "datasets.unsw.gt_csv", str),
        pcap_glob=_get(raw, "datasets.unsw.pcap_glob", str),
    )
    ctu13 = Ctu13Config(
        root=Path(_get(raw, "datasets.ctu13.root", str)),
        timezone=_get(raw, "datasets.ctu13.timezone", str),
    )
    audit = AuditConfig(
        sample_per_part=_get(raw, "audit.sample_per_part", int),
        tree_depth=_get(raw, "audit.tree_depth", int),
        dangerous_lift=_number(raw, "audit.dangerous_lift"),
        suspicious_pr_auc=_number(raw, "audit.suspicious_pr_auc"),
    )
    return DataConfig(
        unsw=unsw,
        ctu13=ctu13,
        v1_processed_dir=Path(_get(raw, "v1_processed_dir", str)),
        split=_parse_split(raw),
        audit=audit,
        seed=_get(raw, "seed", int),
        raw=raw,
    )
