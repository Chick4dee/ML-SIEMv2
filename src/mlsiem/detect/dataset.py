"""Данные для детектора: часть разбиения 001 → X (только поля `feature`), y (класс).

Главное правило (FR-004): в модель идут ровно `SCHEMA.feature_columns()` в порядке схемы.
Адреса, порты, время, DPI-поля и метки в X не попадают никогда — список не пишется руками,
он берётся из схемы. Пропуски → 0 (в выходе nfstream их практически нет, но правило явное).

Чтение ленивое (polars scan): из parquet берутся только нужные колонки нужных потоков,
так что train на 1.4 млн строк × 58 признаков занимает в памяти ~330 МБ, а не гигабайты.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import polars as pl

from mlsiem.data import captures as cap
from mlsiem.data.split import PARTS, SPLIT_DATASET

FEATURES_DTYPE = pl.Float32


def feature_columns() -> list[str]:
    from mlsiem.data.schema import SCHEMA

    return SCHEMA.feature_columns()


@dataclass
class Part:
    """Одна часть разбиения, готовая для модели."""

    X: pl.DataFrame  # только признаки, float32, без пропусков
    y: np.ndarray  # канонические классы (строки)
    flow_uid: np.ndarray

    def X_numpy(self) -> np.ndarray:
        return self.X.to_numpy()


def _split_files(split_name: str, data_dir: Path) -> tuple[Path, Path]:
    if split_name not in SPLIT_DATASET:
        raise ValueError(f"неизвестное разбиение {split_name!r}")
    table = Path(data_dir) / "splits" / f"{split_name}.parquet"
    manifest = Path(data_dir) / "splits" / f"{split_name}.json"
    if not table.exists() or not manifest.exists():
        raise ValueError(
            f"нет разбиения {split_name} в {Path(data_dir) / 'splits'} — сначала выполните "
            f"`uv run mlsiem data split --name {split_name}` (фича 001)"
        )
    return table, manifest


def flow_files(split_name: str, data_dir: Path = Path("data")) -> list[Path]:
    """Parquet-файлы потоков датасета разбиения; все захваты обязаны быть `done`."""
    dataset_dir = Path(data_dir) / "flows" / SPLIT_DATASET[split_name]
    manifests = [
        m
        for p in sorted(dataset_dir.glob("*.json"))
        if p.name != "schema.json" and (m := cap.read_manifest(p)) is not None
    ]
    if not manifests:
        raise ValueError(f"в {dataset_dir} нет готовых захватов — сначала `mlsiem data flows`")
    not_done = [m.capture_id for m in manifests if m.status != "done"]
    if not_done:
        raise ValueError(
            f"захваты не готовы (status != done): {not_done} — перезапустите `mlsiem data flows`"
        )
    return [dataset_dir / f"{m.capture_id}.parquet" for m in manifests]


def scan_part(
    split_name: str, part: str, *, data_dir: Path = Path("data"), columns: list[str] | None = None
) -> pl.LazyFrame:
    """Ленивый join «таблица разбиения ⋈ потоки 001» для одной части, по порядку flow_uid."""
    if part not in PARTS:
        raise ValueError(f"неизвестная часть {part!r}: ожидалось одно из {PARTS}")
    table, _ = _split_files(split_name, data_dir)
    files = flow_files(split_name, data_dir)
    cols = ["flow_uid", *[c for c in (columns or []) if c != "flow_uid"]]
    uids = pl.scan_parquet(table).filter(pl.col("part") == part).select("flow_uid")
    return (
        pl.scan_parquet(files).select(cols).join(uids, on="flow_uid", how="semi").sort("flow_uid")
    )


def load_part(
    split_name: str, part: str, *, data_dir: Path = Path("data"), columns: list[str] | None = None
) -> Part:
    """X (58 признаков float32, пропуски → 0), y и flow_uid части разбиения.

    columns — если нужно взять не все признаки (для экспериментов); по умолчанию — вся
    группа `feature` схемы в её порядке.
    """
    feats = columns or feature_columns()
    df = scan_part(split_name, part, data_dir=data_dir, columns=[*feats, "label"]).collect()
    if df.height == 0:
        raise ValueError(f"в части {part} разбиения {split_name} нет потоков")
    X = df.select(pl.col(feats).cast(FEATURES_DTYPE).fill_null(0))
    return Part(X=X, y=df["label"].to_numpy(), flow_uid=df["flow_uid"].to_numpy())


def data_hashes(split_name: str, data_dir: Path = Path("data")) -> dict:
    """Версия данных из манифеста 001: хеш таблицы разбиения и хеши входных захватов."""
    _, manifest = _split_files(split_name, data_dir)
    m = json.loads(manifest.read_text(encoding="utf-8"))
    return {"split_hash": m["hash"], "input_hashes": m["input_hashes"]}
