"""Артефакт детектора: сохранение, загрузка и проверка входа (research R6, FR-006, FR-007).

Каталог `models/detector/`:
- `model.joblib` — конвейер «предобработка → модель» победившего кандидата;
- `model_card.json` — всё, что нужно знать о детекторе без загрузки модели: версия, классы,
  порог, список признаков, версия схемы, версия данных, метрики, сид, версии библиотек.

Это граница между ML и SOC: `mlsiem.soc` знает только `load_detector()` и `Detector`, и ему
всё равно, победил логрег или бустинг.

Загрузчик строгий: чужая мажорная версия схемы или нехватка признака во входе — отказ
с понятным сообщением. Модель, молча получившая «не те» признаки, выдаёт уверенную чепуху,
и это хуже любой ошибки.
"""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from mlsiem.data.captures import atomic_path
from mlsiem.data.extract import read_parquet_metadata

MODEL_FILE = "model.joblib"
CARD_FILE = "model_card.json"


class DetectorLoadError(ValueError):
    """Артефакт детектора отсутствует или повреждён."""


class DetectorInputError(ValueError):
    """Вход несовместим с детектором (версия схемы, нет признака)."""


def detector_version(config_raw: dict, input_hashes: dict, *, today: datetime | None = None) -> str:
    """`YYYYMMDD-<хеш8>`: хеш — от конфига эксперимента и хешей входных данных.

    Хеш и есть «личность» детектора: тот же конфиг и те же данные — тот же хеш. Дата — только
    для человека (видно, когда обучен); повтор в тот же день даёт ту же версию целиком.
    Ключ `output` (куда сохранить) в хеш не входит: место на диске модель не меняет.
    """
    config = {k: v for k, v in config_raw.items() if k != "output"}
    payload = json.dumps(
        {"config": config, "data": input_hashes}, sort_keys=True, ensure_ascii=False
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8]
    day = (today or datetime.now(UTC)).strftime("%Y%m%d")
    return f"{day}-{digest}"


def library_versions() -> dict[str, str]:
    import sklearn

    versions = {
        "python": platform.python_version(),
        "scikit-learn": sklearn.__version__,
        "numpy": np.__version__,
        "polars": pl.__version__,
    }
    try:
        import lightgbm

        versions["lightgbm"] = lightgbm.__version__
    except ImportError:  # pragma: no cover — lightgbm в зависимостях, но карточка не должна падать
        pass
    return versions


def major(version: str) -> str:
    return str(version).split(".", 1)[0]


def check_schema_and_features(
    expected_schema: str,
    features: list[str],
    schema_version: str | None,
    columns: list[str],
    who: str = "детектор",
) -> None:
    """Общая проверка входа модели (FR-007, фича 004 FR-014): та же мажорная версия схемы
    и на месте все признаки. `who` — чьё имя назвать в сообщении («детектор», «эксперт
    аномалий»): при отказе ансамбля аналитик должен понять, какой именно эксперт недоволен."""
    if schema_version is None:
        raise DetectorInputError(
            f"у входа не указана версия схемы признаков — ожидалась схема {expected_schema}"
        )
    if major(schema_version) != major(expected_schema):
        raise DetectorInputError(
            f"несовместимая версия схемы признаков: ожидалась схема "
            f"{major(expected_schema)}.x ({who} обучен на {expected_schema}), "
            f"получена {schema_version}"
        )
    missing = [f for f in features if f not in set(columns)]
    if missing:
        raise DetectorInputError(
            f"во входе нет признаков, на которых обучен {who}: {', '.join(missing[:10])}"
            + (f" и ещё {len(missing) - 10}" if len(missing) > 10 else "")
        )


@dataclass
class Detector:
    """Загруженный детектор: конвейер + карточка."""

    pipeline: Any
    card: dict

    @property
    def version(self) -> str:
        return self.card["detector_version"]

    @property
    def classes(self) -> list[str]:
        return list(self.card["classes"])

    @property
    def threshold(self) -> float:
        return float(self.card["threshold"])

    @property
    def features(self) -> list[str]:
        return list(self.card["features"])

    @property
    def schema_version(self) -> str:
        return self.card["schema_version"]

    def check_input(self, schema_version: str | None, columns: list[str]) -> None:
        """FR-007: мажорная версия схемы входа совпадает с детектором и есть все признаки."""
        check_schema_and_features(
            self.schema_version, self.features, schema_version, columns, "детектор"
        )

    def check_parquet(self, path: Path) -> None:
        """То же для parquet-файла: версия схемы — из метаданных `mlsiem.schema_version`."""
        import pyarrow.parquet as pq

        meta = read_parquet_metadata(Path(path))
        self.check_input(meta.get("mlsiem.schema_version"), pq.read_schema(path).names)

    def predict_proba(self, df: pl.DataFrame) -> np.ndarray:
        """Вероятности классов (столбцы — в порядке `classes`). Берутся ТОЛЬКО `features`."""
        X = df.select(pl.col(self.features).cast(pl.Float32).fill_null(0)).to_numpy()
        return self.pipeline.predict_proba(X)


def save_detector(pipeline: Any, card: dict, out_dir: Path) -> None:
    """Атомарно пишет `model.joblib` и `model_card.json`."""
    import joblib

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with atomic_path(out_dir / MODEL_FILE) as tmp:
        joblib.dump(pipeline, tmp)
    with atomic_path(out_dir / CARD_FILE) as tmp:
        tmp.write_text(json.dumps(card, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


REQUIRED_CARD_FIELDS = (
    "detector_version",
    "candidate",
    "classes",
    "threshold",
    "features",
    "schema_version",
)


def load_detector(path: Path = Path("models/detector")) -> Detector:
    """Загружает детектор; нет файлов или они битые — `DetectorLoadError` с понятным текстом."""
    import joblib

    path = Path(path)
    model_file, card_file = path / MODEL_FILE, path / CARD_FILE
    if not model_file.exists() or not card_file.exists():
        raise DetectorLoadError(
            f"нет артефакта детектора в {path} (ожидались {MODEL_FILE} и {CARD_FILE}) — "
            "сначала обучите его: `uv run mlsiem detect train`"
        )
    try:
        card = json.loads(card_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DetectorLoadError(f"{card_file} повреждён: {exc}") from exc
    if not isinstance(card, dict):
        raise DetectorLoadError(f"{card_file} повреждён: ожидался JSON-объект")
    missing = [f for f in REQUIRED_CARD_FIELDS if f not in card]
    if missing:
        raise DetectorLoadError(f"{card_file} повреждён: нет полей {missing}")
    try:
        pipeline = joblib.load(model_file)
    except Exception as exc:  # joblib/pickle бросают что угодно на битом файле
        raise DetectorLoadError(f"{model_file} не загружается (повреждён?): {exc}") from exc
    if not hasattr(pipeline, "predict_proba"):
        raise DetectorLoadError(f"{model_file}: внутри не модель (нет predict_proba)")
    model_classes = [str(c) for c in getattr(pipeline, "classes_", card["classes"])]
    if model_classes != list(card["classes"]):
        raise DetectorLoadError(
            f"классы модели {model_classes} не совпадают с карточкой {card['classes']} — "
            "файлы от разных обучений?"
        )
    return Detector(pipeline=pipeline, card=card)
