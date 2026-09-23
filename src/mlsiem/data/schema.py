"""Схема признаков потока — единственное место, где перечислены колонки и их роли.

Схема версионируется: любая правка списка колонок, типов или настроек nfstream — это новая
версия, и все parquet хранят версию, с которой они записаны. Так будущая модель может
отказаться работать с таблицей, посчитанной «не теми» признаками (train = serve).

Группы колонок:
- key      — идентификация строки (flow_uid, capture_id);
- identity — адреса, порты, MAC: нужны для разметки и анализа, в модель НЕ подаются,
             иначе модель выучит «атакующий IP стенда», а не атаку;
- time     — временные метки: нужны для разбиения, в модель НЕ подаются;
- feature  — поведение потока (объёмы, размеры пакетов, интервалы, флаги) — кандидаты в модель;
- dpi      — что распознал nDPI; пригодность решает аудит артефактов;
- label    — разметка.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import polars as pl

SCHEMA_VERSION = "1.0.0"
GROUPS = ("key", "identity", "time", "feature", "dpi", "label")

# Все настройки NFStreamer. Экстрактор берёт их только отсюда — и для датасетов,
# и для живого трафика в будущем. Значения совпадают с умолчаниями nfstream 6.6,
# но записаны явно: если умолчания в новой версии поменяются, у нас ничего не сдвинется.
EXTRACTOR = {
    "library": "nfstream==6.6.x",
    "statistical_analysis": True,
    "splt_analysis": 0,
    "n_dissections": 20,
    "idle_timeout": 120,
    "active_timeout": 1800,
    "accounting_mode": 0,
}


@dataclass(frozen=True)
class Column:
    name: str
    dtype: pl.DataType
    group: str


def _build_columns() -> tuple[Column, ...]:
    i64, f64, s = pl.Int64(), pl.Float64(), pl.String()
    cols: list[Column] = [Column("flow_uid", s, "key"), Column("capture_id", s, "key")]

    # Порядок ниже повторяет порядок колонок nfstream (кроме выброшенного id) —
    # так таблицу проще сверять с документацией nfstream глазами
    cols.append(Column("expiration_id", i64, "identity"))
    for side in ("src", "dst"):
        cols += [
            Column(f"{side}_ip", s, "identity"),
            Column(f"{side}_mac", s, "identity"),
            Column(f"{side}_oui", s, "identity"),
            Column(f"{side}_port", i64, "identity"),
        ]
    cols += [
        Column("protocol", i64, "feature"),
        Column("ip_version", i64, "identity"),
        Column("vlan_id", i64, "identity"),
        Column("tunnel_id", i64, "identity"),
    ]
    for direction in ("bidirectional", "src2dst", "dst2src"):
        cols += [
            Column(f"{direction}_first_seen_ms", i64, "time"),
            Column(f"{direction}_last_seen_ms", i64, "time"),
            Column(f"{direction}_duration_ms", i64, "feature"),
            Column(f"{direction}_packets", i64, "feature"),
            Column(f"{direction}_bytes", i64, "feature"),
        ]
    # Размеры пакетов (ps) и межпакетные интервалы (piat): min/max целые, mean/stddev дробные
    for stat in ("ps", "piat_ms"):
        for direction in ("bidirectional", "src2dst", "dst2src"):
            cols += [
                Column(f"{direction}_min_{stat}", i64, "feature"),
                Column(f"{direction}_mean_{stat}", f64, "feature"),
                Column(f"{direction}_stddev_{stat}", f64, "feature"),
                Column(f"{direction}_max_{stat}", i64, "feature"),
            ]
    for direction in ("bidirectional", "src2dst", "dst2src"):
        for flag in ("syn", "cwr", "ece", "urg", "ack", "psh", "rst", "fin"):
            cols.append(Column(f"{direction}_{flag}_packets", i64, "feature"))
    cols += [
        Column("application_name", s, "dpi"),
        Column("application_category_name", s, "dpi"),
        Column("application_is_guessed", i64, "dpi"),
        Column("application_confidence", i64, "dpi"),
        Column("requested_server_name", s, "dpi"),
        Column("client_fingerprint", s, "dpi"),
        Column("server_fingerprint", s, "dpi"),
        Column("user_agent", s, "dpi"),
        Column("content_type", s, "dpi"),
    ]
    cols += [
        Column("label_raw", s, "label"),
        Column("label_detail", s, "label"),
        Column("label", s, "label"),
    ]
    return tuple(cols)


@dataclass(frozen=True)
class FeatureSchema:
    version: str
    extractor: dict = field(hash=False)
    columns: tuple[Column, ...]

    def names(self) -> list[str]:
        return [c.name for c in self.columns]

    def columns_of(self, group: str) -> list[str]:
        if group not in GROUPS:
            raise ValueError(f"неизвестная группа колонок: {group!r}")
        return [c.name for c in self.columns if c.group == group]

    def feature_columns(self) -> list[str]:
        """Колонки, которые разрешено подавать в модель без отдельного решения."""
        return self.columns_of("feature")

    def dtypes(self) -> dict[str, pl.DataType]:
        return {c.name: c.dtype for c in self.columns}

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "extractor": self.extractor,
            "columns": [
                {"name": c.name, "dtype": str(c.dtype), "group": c.group} for c in self.columns
            ],
        }

    def to_json(self, path: str | Path) -> None:
        from mlsiem.data.captures import atomic_path  # локально: captures импортирует schema

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with atomic_path(path) as tmp:
            tmp.write_text(
                json.dumps(self.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )

    @classmethod
    def from_json(cls, path: str | Path) -> FeatureSchema:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        # str(pl.Int64()) даёт "Int64" — по этому имени тип и восстанавливается
        columns = tuple(
            Column(c["name"], getattr(pl, c["dtype"])(), c["group"]) for c in data["columns"]
        )
        return cls(version=data["version"], extractor=data["extractor"], columns=columns)


SCHEMA = FeatureSchema(version=SCHEMA_VERSION, extractor=dict(EXTRACTOR), columns=_build_columns())
