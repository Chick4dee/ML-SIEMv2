"""Чтение и проверка configs/detect.yaml.

Как и конфиг данных 001, проверяется целиком при запуске: эксперимент идёт минуты, и падать
на середине из-за опечатки в имени ключа обидно. Проверки ключей и типов — общие с 001
(`_get` из `mlsiem.data.config`), чтобы сообщения об ошибках выглядели одинаково.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from mlsiem.data.config import ConfigError, _get, _number
from mlsiem.data.split import SPLIT_DATASET

DEFAULT_DETECT_CONFIG = Path("configs/detect.yaml")
# Какие кандидаты умеет строить `detect.candidates`. Первый — бейзлайн (research R4)
KNOWN_CANDIDATES = ("logreg", "lgbm")
BASELINE = "logreg"
SELECTION_METRICS = ("macro_pr_auc_val",)


@dataclass(frozen=True)
class SelectionConfig:
    metric: str
    min_gain: float


@dataclass(frozen=True)
class DetectConfig:
    split: str
    transfer_split: str
    seed: int
    selection: SelectionConfig
    # Имя кандидата → его гиперпараметры (как записаны в конфиге)
    candidates: dict[str, dict[str, Any]]
    output: Path
    # Сырой словарь — для хеша версии детектора и для журнала экспериментов
    raw: dict[str, Any]


def _split_name(raw: dict, key: str) -> str:
    name = _get(raw, key, str)
    if SPLIT_DATASET.get(name) != "unsw":
        raise ConfigError(
            f"ключ {key}: ожидалось разбиение UNSW (unsw_time или unsw_cross_day), "
            f"а записано {name!r}"
        )
    return name


def parse_detect_config(raw: Any) -> DetectConfig:
    """Проверяет уже прочитанный словарь конфига (удобно для тестов без файла)."""
    if not isinstance(raw, dict):
        raise ConfigError("конфиг детектора: ожидался словарь верхнего уровня")

    metric = _get(raw, "selection.metric", str)
    if metric not in SELECTION_METRICS:
        raise ConfigError(
            f"ключ selection.metric: поддерживается только {SELECTION_METRICS}, "
            f"а записано {metric!r}"
        )
    min_gain = _number(raw, "selection.min_gain")
    if min_gain < 0:
        raise ConfigError(
            f"ключ selection.min_gain: прирост не может быть отрицательным ({min_gain})"
        )

    cands_raw = _get(raw, "candidates", dict)
    unknown = sorted(set(cands_raw) - set(KNOWN_CANDIDATES))
    if unknown:
        raise ConfigError(
            f"ключ candidates: неизвестные кандидаты {unknown}; "
            f"поддерживаются {list(KNOWN_CANDIDATES)}"
        )
    if BASELINE not in cands_raw:
        raise ConfigError(
            f"ключ candidates: нужен бейзлайн {BASELINE!r} — с ним сравниваются остальные"
        )
    candidates: dict[str, dict[str, Any]] = {}
    for name in cands_raw:
        params = _get(raw, f"candidates.{name}", dict)
        candidates[name] = dict(params)

    return DetectConfig(
        split=_split_name(raw, "split"),
        transfer_split=_split_name(raw, "transfer_split"),
        seed=_get(raw, "seed", int),
        selection=SelectionConfig(metric=metric, min_gain=min_gain),
        candidates=candidates,
        output=Path(_get(raw, "output", str)),
        raw=raw,
    )


def load_detect_config(path: str | Path = DEFAULT_DETECT_CONFIG) -> DetectConfig:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"не найден файл конфига {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: не читается как YAML: {exc}") from exc
    return parse_detect_config(raw)
