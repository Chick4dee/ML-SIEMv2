"""Разметка CTU-13: файлы *.binetflow (выгрузка Argus) в папках сценариев.

Особенности источника:
- Время `StartTime` записано по местным часам стенда в Праге, а PCAP — в UTC. Если читать
  его «как есть», все метки съедут на 1–2 часа (зимой/летом по-разному) и почти ничего
  не сопоставится. Часовой пояс берётся из конфига и переводится в UTC явно.
- Конец записи = начало + `Dur` (секунды с дробной частью).
- Подписи подробные (`flow=From-Botnet-V42-TCP-...`), сводим к botnet / normal / background;
  подробная подпись остаётся в `label_detail`.
- Несопоставленные потоки — `unlabeled`, а не `benign`: в PCAP CTU-13 почти нет нормального
  трафика, и назначать ему «норму» по умолчанию было бы неправдой.

Безопасность: из папки сценария берётся только *.binetflow — рядом лежат бинарники ботнетов.
"""

from __future__ import annotations

from pathlib import Path

import polars as pl

from mlsiem.data.labeling import GT_COLUMNS, protocol_number
from mlsiem.data.taxonomy import UnknownLabelError, to_canonical

DEFAULT_LABEL = "unlabeled"


def find_binetflow(scenario_dir: Path) -> Path:
    files = sorted(Path(scenario_dir).glob("*.binetflow"))
    if len(files) != 1:
        raise FileNotFoundError(
            f"в {scenario_dir} ожидался ровно один *.binetflow, найдено {len(files)}"
        )
    return files[0]


def _port(col: str) -> pl.Expr:
    """Порт: десятичный, шестнадцатеричный (у ICMP там тип/код, `0x0303`) или пустой."""
    raw = pl.col(col).str.strip_chars()
    return (
        pl.when(raw.str.starts_with("0x"))
        .then(raw.str.slice(2).str.to_integer(base=16, strict=False))
        .otherwise(raw.str.to_integer(base=10, strict=False))
        .cast(pl.Int64)
    )


def _reduce_label() -> pl.Expr:
    label = pl.col("Label").str.to_lowercase()
    return (
        pl.when(label.str.contains("botnet"))
        .then(pl.lit("botnet"))
        .when(label.str.contains("normal"))
        .then(pl.lit("normal"))
        .when(label.str.contains("background"))
        .then(pl.lit("background"))
        .otherwise(pl.lit(None, dtype=pl.String))
    )


def load_binetflow(path: Path, timezone: str) -> pl.DataFrame:
    # Только нужные колонки: .binetflow бывает на миллионы строк, и лишние колонки-строки
    # удваивали пик памяти при разметке крошечного по потокам сценария
    raw = pl.read_csv(
        path,
        infer_schema_length=0,
        columns=["StartTime", "Dur", "Proto", "SrcAddr", "Sport", "DstAddr", "Dport", "Label"],
    )
    gt = raw.select(
        pl.col("StartTime")
        .str.strip_chars()
        .str.strptime(pl.Datetime("us"), "%Y/%m/%d %H:%M:%S%.f")
        # Осенний перевод часов даёт час, который встречается дважды; берём первый вариант.
        # Весенний — час, которого не было: такие записи получат null и отбросятся ниже.
        # Захваты CTU-13 сделаны в августе, так что на практике это не срабатывает
        .dt.replace_time_zone(timezone, ambiguous="earliest", non_existent="null")
        .dt.convert_time_zone("UTC")
        .dt.epoch("ms")
        .alias("gt_start_ms"),
        (pl.col("Dur").str.strip_chars().cast(pl.Float64) * 1000)
        .round()
        .cast(pl.Int64)
        .alias("_dur_ms"),
        pl.col("SrcAddr").str.strip_chars().alias("src_ip"),
        _port("Sport").alias("src_port"),
        pl.col("DstAddr").str.strip_chars().alias("dst_ip"),
        _port("Dport").alias("dst_port"),
        protocol_number("Proto").alias("protocol"),
        _reduce_label().alias("label_raw"),
        pl.col("Label").alias("label_detail"),
    )
    unknown = gt.filter(pl.col("label_raw").is_null())["label_detail"].unique().head(5)
    if len(unknown):
        raise UnknownLabelError(
            f"{Path(path).name}: подписи без botnet/normal/background: {unknown.to_list()}"
        )
    mapping = {v: to_canonical("ctu13", v) for v in ("botnet", "normal", "background")}
    return (
        gt.with_columns(
            (pl.col("gt_start_ms") + pl.col("_dur_ms")).alias("gt_end_ms"),
            pl.col("label_raw").replace_strict(mapping, return_dtype=pl.String).alias("label"),
        )
        .filter(pl.col("gt_start_ms").is_not_null())
        .select(GT_COLUMNS)
    )
