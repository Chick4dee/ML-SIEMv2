"""Синтетические потоки в формате фичи 001 — чтобы весь код 002 тестировался без датасетов.

Что получается:
- два «дня» UNSW (22-1-2015 и 17-2-2015) по одному захвату, 6 часов трафика в каждом;
- фоновый `benign` с IP 59.166.0.x;
- атаки 4 классов сериями (всплесками) с трёх адресов 175.45.176.1–3 — как в настоящем
  UNSW-NB15, где все атаки идут с 175.45.176.0–3. Между всплесками одного источника и класса
  бывают паузы и меньше, и больше 15 минут — группировка в инциденты будет что проверять;
- у каждого класса атак свой заметный сдвиг признаков, так что детектор учится за секунды.

Всё детерминировано (сид 0): одна и та же таблица при каждом запуске.

`build_synthetic_split` раскладывает потоки на диск ровно как 001 (parquet + манифест на
захват, schema.json) и строит разбиения `unsw_time` и `unsw_cross_day` настоящим кодом 001.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import polars as pl

from mlsiem.data import captures as cap
from mlsiem.data.config import load_config
from mlsiem.data.extract import content_hash, write_flows_parquet
from mlsiem.data.schema import SCHEMA
from mlsiem.data.split import build_split

REPO = Path(__file__).parents[2]
DAYS = {
    "22-1-2015": datetime(2015, 1, 22, 9, tzinfo=UTC),
    "17-2-2015": datetime(2015, 2, 17, 9, tzinfo=UTC),
}
ATTACK_CLASSES = ("exploits", "dos", "reconnaissance", "fuzzers")
ATTACKERS = ("175.45.176.1", "175.45.176.2", "175.45.176.3")
TARGETS = tuple(f"149.171.126.{i}" for i in range(10, 16))
SPAN_MS = 6 * 3600 * 1000
FEATURES = SCHEMA.feature_columns()
DTYPES = SCHEMA.dtypes()

# Сдвиг признаков по классу: у каждого класса своё подмножество признаков заметно больше фона
SHIFTS = {
    "exploits": (slice(0, 15), 2.5),
    "dos": (slice(10, 30), 3.0),
    "reconnaissance": (slice(25, 45), -1.5),
    "fuzzers": (slice(40, 58), 2.0),
}


def _features(rng: np.random.Generator, n: int, label: str) -> np.ndarray:
    x = rng.normal(3.0, 1.0, size=(n, len(FEATURES)))
    if label in SHIFTS:
        cols, delta = SHIFTS[label]
        x[:, cols] += delta
    return np.expm1(np.clip(x, 0, None))  # неотрицательные «счётчики» с тяжёлым хвостом


def _day_rows(rng: np.random.Generator, day: str, n_benign: int) -> list[dict]:
    t0 = int(DAYS[day].timestamp() * 1000)
    rows: list[dict] = []

    def add(label: str, src: str, dst: str, start: int) -> None:
        rows.append({"label": label, "src_ip": src, "dst_ip": dst, "start": start})

    for start in rng.integers(0, SPAN_MS, size=n_benign):
        add(
            "benign",
            f"59.166.0.{rng.integers(0, 10)}",
            f"149.171.126.{rng.integers(0, 10)}",
            t0 + int(start),
        )

    # Всплески атак: примерно каждые 8 минут; источник и класс случайны, поэтому у одного
    # ключа (src, класс) паузы между всплесками бывают и меньше, и больше 15 минут
    t = 0
    while t < SPAN_MS - 5 * 60_000:
        label = ATTACK_CLASSES[rng.integers(0, len(ATTACK_CLASSES))]
        src = ATTACKERS[rng.integers(0, len(ATTACKERS))]
        n_targets = 1 if label == "exploits" and rng.random() < 0.5 else 3
        targets = rng.choice(TARGETS, size=n_targets, replace=False)
        start = t
        for _ in range(int(rng.integers(12, 25))):
            add(label, src, str(targets[rng.integers(0, n_targets)]), t0 + start)
            start += int(rng.integers(2_000, 15_000))
        t += int(rng.integers(5, 12)) * 60_000
    return rows


def make_synthetic_flows(*, n_benign_per_day: int = 2500, seed: int = 0) -> dict[str, pl.DataFrame]:
    """capture_id → таблица потоков со всеми колонками схемы (в порядке и с типами схемы)."""
    rng = np.random.default_rng(seed)
    result = {}
    for day in DAYS:
        capture_id = f"unsw_{day}_01"
        rows = sorted(
            _day_rows(rng, day, n_benign_per_day), key=lambda r: (r["start"], r["src_ip"])
        )
        n = len(rows)
        labels = [r["label"] for r in rows]
        x = np.vstack([_features(rng, 1, lab) for lab in labels])
        start = np.array([r["start"] for r in rows], dtype=np.int64)
        duration = rng.integers(1, 3_000, size=n)
        data: dict[str, object] = {
            "flow_uid": [f"{capture_id}/{i}" for i in range(n)],
            "capture_id": [capture_id] * n,
            "src_ip": [r["src_ip"] for r in rows],
            "dst_ip": [r["dst_ip"] for r in rows],
            "src_port": rng.integers(1024, 65535, size=n),
            "dst_port": rng.choice([80, 443, 53, 21, 25, 111], size=n),
            "label_raw": [None if lab == "benign" else lab.capitalize() for lab in labels],
            "label_detail": [None] * n,
            "label": labels,
        }
        for direction in ("bidirectional", "src2dst", "dst2src"):
            data[f"{direction}_first_seen_ms"] = start
            data[f"{direction}_last_seen_ms"] = start + duration
        for j, name in enumerate(FEATURES):
            col = x[:, j]
            data[name] = col if DTYPES[name] == pl.Float64 else np.round(col).astype(np.int64)
        data["protocol"] = rng.choice([6, 17], size=n)
        columns = []
        for c in SCHEMA.columns:
            if c.name in data:
                columns.append(pl.Series(c.name, data[c.name]).cast(c.dtype))
            else:
                columns.append(pl.Series(c.name, [None] * n, dtype=c.dtype))
        result[capture_id] = pl.DataFrame(columns)
    return result


def write_synthetic_flows(
    data_dir: Path, *, n_benign_per_day: int = 2500
) -> dict[str, pl.DataFrame]:
    """Пишет потоки в `data_dir/flows/unsw/` в формате 001: parquet + манифест + schema.json."""
    flows_dir = Path(data_dir) / "flows" / "unsw"
    flows = make_synthetic_flows(n_benign_per_day=n_benign_per_day)
    SCHEMA.to_json(flows_dir / "schema.json")
    for capture_id, df in flows.items():
        write_flows_parquet(
            df, flows_dir / f"{capture_id}.parquet", {"mlsiem.capture_id": capture_id}
        )
        counts = dict(df["label"].value_counts().iter_rows())
        cap.write_manifest(
            cap.CaptureManifest(
                capture_id=capture_id,
                fingerprint={"size": 0, "mtime_ns": 0, "partial_sha256": "synthetic"},
                label_source_fingerprint=None,
                labeling_params_hash=None,
                schema_version=SCHEMA.version,
                labeling_version="1.0.0",
                status="done",
                n_flows=df.height,
                label_counts=counts,
                content_hash=content_hash(df),
            ),
            flows_dir / f"{capture_id}.json",
        )
    return flows


def build_synthetic_split(data_dir: Path, *, n_benign_per_day: int = 2500) -> Path:
    """Потоки + разбиения `unsw_time` и `unsw_cross_day` настоящим кодом 001 → data_dir."""
    data_dir = Path(data_dir)
    write_synthetic_flows(data_dir, n_benign_per_day=n_benign_per_day)
    cfg = load_config(REPO / "configs" / "data.yaml")
    for name in ("unsw_time", "unsw_cross_day"):
        build_split(cfg, name, data_dir=data_dir)
    return data_dir
