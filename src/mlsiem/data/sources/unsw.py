"""Разметка UNSW-NB15: файл NUSW-NB15_GT.csv.

Особенности источника:
- GT перечисляет ТОЛЬКО атаки. Всё, что не сопоставилось, — фон генератора трафика IXIA,
  поэтому несопоставленные потоки получают `benign` (а не `unlabeled`, как в CTU-13).
  Оговорка для отчёта: этот «benign» сгенерирован другим инструментом, чем атаки, — отсюда
  риск, что модель выучит генератор, а не атаку (урок v1).
- Время — epoch-секунды UTC, как и в PCAP: часовой пояс не нужен (в v1 проверено, что
  GT и PCAP дня 22-1-2015 выровнены без сдвига).
- Категории «грязные»: пробелы по краям (` Fuzzers`), Backdoor/Backdoors — чистит taxonomy.
- В строках есть лишняя колонка `.` и длинные описания — читаем всё как строки
  и приводим типы сами.
"""

from __future__ import annotations

from pathlib import Path

import polars as pl

from mlsiem.data.labeling import GT_COLUMNS, protocol_number
from mlsiem.data.taxonomy import to_canonical

DEFAULT_LABEL = "benign"


def load_gt(path: Path) -> pl.DataFrame:
    raw = pl.read_csv(path, infer_schema_length=0, truncate_ragged_lines=True)
    gt = raw.select(
        (pl.col("Start time").str.strip_chars().cast(pl.Int64) * 1000).alias("gt_start_ms"),
        (pl.col("Last time").str.strip_chars().cast(pl.Int64) * 1000).alias("gt_end_ms"),
        pl.col("Source IP").str.strip_chars().alias("src_ip"),
        pl.col("Source Port").str.strip_chars().cast(pl.Int64, strict=False).alias("src_port"),
        pl.col("Destination IP").str.strip_chars().alias("dst_ip"),
        pl.col("Destination Port").str.strip_chars().cast(pl.Int64, strict=False).alias("dst_port"),
        protocol_number("Protocol").alias("protocol"),
        pl.col("Attack category").alias("label_raw"),
        pl.col("Attack Name").alias("label_detail"),
    )
    # Каноническую метку считаем по уникальным подписям: их десяток, а строк — 174 тысячи
    mapping = {v: to_canonical("unsw", v) for v in gt["label_raw"].drop_nulls().unique()}
    return gt.with_columns(
        pl.col("label_raw")
        .replace_strict(mapping, default=None, return_dtype=pl.String)
        .alias("label")
    ).select(GT_COLUMNS)
