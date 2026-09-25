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


# ---------------------------------------------------------------- фича 004: ансамбль

DEFAULT_ENSEMBLE_CONFIG = Path("configs/ensemble.yaml")
# Кандидаты детектора аномалий (research R1). Первый — бейзлайн: сложный кандидат
# выигрывает, только если лучше него на selection.min_gain
KNOWN_ANOMALY_CANDIDATES = ("iforest", "autoencoder")
ANOMALY_BASELINE = "iforest"
# Кандидаты мета-слоя (research R4): два правила без обучения и стекинг. Порядок — от
# простого к сложному: при равенстве метрик выбирается тот, что раньше в этом списке
KNOWN_META_CANDIDATES = ("any_fired", "mean_score", "stack_logreg")


@dataclass(frozen=True)
class AnomalyConfig:
    candidates: dict[str, dict[str, Any]]
    train_sample: int
    calibration_share: float
    anomaly_fpr: float
    exclude_features: tuple[str, ...]


@dataclass(frozen=True)
class MetaConfig:
    candidates: tuple[str, ...]
    folds: int
    gap_ms: int


@dataclass(frozen=True)
class EnsembleSelection:
    min_gain: float
    min_unknown_gain: float


@dataclass(frozen=True)
class AuditModelsConfig:
    """Аудит артефактов (R6). Раздел в конфиге необязателен — тогда эти значения."""

    probe_flag: float = 0.9
    permutation_rows: int = 50_000
    top: int = 10


@dataclass(frozen=True)
class EnsembleConfig:
    split: str
    seed: int
    classifier: Path
    anomaly: AnomalyConfig
    meta: MetaConfig
    hidden_classes: tuple[str, ...]
    selection: EnsembleSelection
    unreliable_below: int
    output_anomaly: Path
    output_ensemble: Path
    # Сырой словарь — для хеша версий эксперта и ансамбля и для experiment.json
    raw: dict[str, Any]
    audit: AuditModelsConfig = AuditModelsConfig()


def _parse_audit(raw: dict) -> AuditModelsConfig:
    if "audit" not in raw:
        return AuditModelsConfig()
    flag = _number(raw, "audit.probe_flag")
    if not 0.5 < flag <= 1:
        raise ConfigError(f"ключ audit.probe_flag: нужен PR-AUC в (0.5, 1], а записано {flag}")
    rows = _get(raw, "audit.permutation_rows", int)
    top = _get(raw, "audit.top", int)
    if rows < 100 or top < 1:
        raise ConfigError(
            f"ключи audit.permutation_rows (≥ 100) и audit.top (≥ 1): записано {rows} и {top}"
        )
    return AuditModelsConfig(probe_flag=flag, permutation_rows=rows, top=top)


def _share(raw: dict, key: str) -> float:
    """Доля строго внутри (0, 0.5): 0 — «ничего», а больше половины — явно опечатка."""
    value = _number(raw, key)
    if not 0 < value < 0.5:
        raise ConfigError(f"ключ {key}: нужна доля строго между 0 и 0.5, а записано {value}")
    return value


def _str_list(raw: dict, key: str) -> list[str]:
    values = _get(raw, key, list)
    if not all(isinstance(v, str) and v for v in values):
        raise ConfigError(f"ключ {key}: нужен список непустых строк")
    return list(values)


def parse_ensemble_config(raw: Any) -> EnsembleConfig:
    """Проверяет словарь конфига ансамбля целиком — до того, как начнётся долгое обучение."""
    from mlsiem.detect.dataset import feature_columns

    if not isinstance(raw, dict):
        raise ConfigError("конфиг ансамбля: ожидался словарь верхнего уровня")

    cands_raw = _get(raw, "anomaly.candidates", dict)
    unknown = sorted(set(cands_raw) - set(KNOWN_ANOMALY_CANDIDATES))
    if unknown:
        raise ConfigError(
            f"ключ anomaly.candidates: неизвестные кандидаты детектора аномалий {unknown}; "
            f"поддерживаются {list(KNOWN_ANOMALY_CANDIDATES)}"
        )
    if ANOMALY_BASELINE not in cands_raw:
        raise ConfigError(
            f"ключ anomaly.candidates: нужен бейзлайн {ANOMALY_BASELINE!r} — "
            "с ним сравниваются остальные"
        )
    candidates = {n: dict(_get(raw, f"anomaly.candidates.{n}", dict)) for n in cands_raw}

    train_sample = _get(raw, "anomaly.train_sample", int)
    if train_sample < 100:
        raise ConfigError(
            f"ключ anomaly.train_sample: нужно хотя бы 100 нормальных потоков, а записано "
            f"{train_sample}"
        )
    exclude = _str_list(raw, "anomaly.exclude_features")
    not_features = sorted(set(exclude) - set(feature_columns()))
    if not_features:
        raise ConfigError(
            f"ключ anomaly.exclude_features: {not_features} — не признаки группы feature схемы"
        )

    meta_cands = _str_list(raw, "meta.candidates")
    unknown = sorted(set(meta_cands) - set(KNOWN_META_CANDIDATES))
    if unknown or not meta_cands:
        raise ConfigError(
            f"ключ meta.candidates: неизвестные кандидаты мета-слоя {unknown or '(пусто)'}; "
            f"поддерживаются {list(KNOWN_META_CANDIDATES)}"
        )
    if len(set(meta_cands)) != len(meta_cands):
        raise ConfigError(f"ключ meta.candidates: кандидаты повторяются: {meta_cands}")
    folds = _get(raw, "meta.folds", int)
    if folds < 2:
        raise ConfigError(
            f"ключ meta.folds: для out-of-fold нужно хотя бы 2 блока, а записано {folds}"
        )
    gap_ms = _get(raw, "meta.gap_ms", int)
    if gap_ms < 0:
        raise ConfigError(f"ключ meta.gap_ms: зазор не может быть отрицательным ({gap_ms})")

    hidden = _str_list(raw, "hidden_classes")
    if not hidden:
        raise ConfigError(
            "ключ hidden_classes: нужен хотя бы один класс — без него эксперимент "
            "«неизвестная атака» (FR-011) не провести"
        )
    if "benign" in hidden:
        raise ConfigError("ключ hidden_classes: норму (benign) скрывать бессмысленно")

    min_gain = _number(raw, "selection.min_gain")
    min_unknown_gain = _number(raw, "selection.min_unknown_gain")
    for key, value in (
        ("selection.min_gain", min_gain),
        ("selection.min_unknown_gain", min_unknown_gain),
    ):
        if value < 0:
            raise ConfigError(f"ключ {key}: прирост не может быть отрицательным ({value})")

    unreliable_below = _get(raw, "unreliable_below", int)
    if unreliable_below < 1:
        raise ConfigError(f"ключ unreliable_below: нужно целое ≥ 1, а записано {unreliable_below}")

    return EnsembleConfig(
        split=_split_name(raw, "split"),
        seed=_get(raw, "seed", int),
        classifier=Path(_get(raw, "classifier", str)),
        anomaly=AnomalyConfig(
            candidates=candidates,
            train_sample=train_sample,
            calibration_share=_share(raw, "anomaly.calibration_share"),
            anomaly_fpr=_share(raw, "anomaly.anomaly_fpr"),
            exclude_features=tuple(exclude),
        ),
        meta=MetaConfig(candidates=tuple(meta_cands), folds=folds, gap_ms=gap_ms),
        hidden_classes=tuple(hidden),
        selection=EnsembleSelection(min_gain=min_gain, min_unknown_gain=min_unknown_gain),
        unreliable_below=unreliable_below,
        output_anomaly=Path(_get(raw, "output.anomaly", str)),
        output_ensemble=Path(_get(raw, "output.ensemble", str)),
        raw=raw,
        audit=_parse_audit(raw),
    )


def load_ensemble_config(path: str | Path = DEFAULT_ENSEMBLE_CONFIG) -> EnsembleConfig:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"не найден файл конфига {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: не читается как YAML: {exc}") from exc
    return parse_ensemble_config(raw)
