"""Сверка результатов v2 с таблицами v1 (F:/GitHubRepos/ML-SIEM/data/processed, только чтение).

Формат v1 (изучен в T045):
- UNSW: `unsw/<день>__<номер>.parquet`, например `22-1-2015__1.parquet` → capture_id
  `unsw_22-1-2015_01`. Класс — колонка `canonical` (уже в канонических классах; несопоставленные
  там `benign`, в `label_class` — `normal`).
- CTU-13: `ctu13/scenario_<NN>.parquet` → `ctu13_NN`. Класс — `label_class`
  (botnet / normal / background), у несопоставленных null. Приводим к нашим классам:
  normal → benign, null → unlabeled. Поскольку несопоставленные потоки в таблицах v1 есть,
  долю сопоставления v1 считаем прямо из них — журнал v1 для этого не нужен.
- `summary.csv` в папках v1 пропускаем — это сводки, не данные.

Что считается расхождением, требующим объяснения (data-model, V1Comparison):
- число потоков отличается больше чем на 5%;
- доля какого-то класса отличается больше чем на 5 процентных пунктов (именно п. п., а не
  относительно: иначе редкий класс 2% → 3% давал бы «+50%» и ложную тревогу);
- для CTU-13 доля сопоставления v2 ниже, чем в v1 (регресс разметки).
Объяснения лежат в configs/v1_diff_notes.yaml и переживают перезапуски.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import polars as pl
import yaml

from mlsiem.data import captures as cap
from mlsiem.data.config import DataConfig

REL_DIFF_LIMIT = 0.05
SHARE_DIFF_LIMIT_PP = 5.0
DEFAULT_NOTES = Path("configs/v1_diff_notes.yaml")


def v1_capture_id(path: Path) -> str | None:
    name = path.stem
    if m := re.fullmatch(r"(\d{1,2}-\d{1,2}-\d{4})__(\d+)", name):
        return f"unsw_{m.group(1)}_{int(m.group(2)):02d}"
    if m := re.fullmatch(r"scenario_(\d+)", name):
        return f"ctu13_{int(m.group(1)):02d}"
    return None


def read_v1(v1_dir: Path) -> dict[str, dict]:
    """capture_id → {n_flows, label_counts, n_matched (только CTU-13)}. Читаются лишь метки."""
    stats: dict[str, dict] = {}
    for path in sorted(Path(v1_dir).glob("*/*.parquet")):
        cid = v1_capture_id(path)
        if cid is None:
            continue
        if cid.startswith("unsw_"):
            labels = pl.scan_parquet(path).select(pl.col("canonical").alias("label")).collect()
            n_matched = None
        else:
            labels = (
                pl.scan_parquet(path)
                .select(
                    pl.col("label_class")
                    .replace({"normal": "benign"})
                    .fill_null("unlabeled")
                    .alias("label")
                )
                .collect()
            )
            n_matched = int((labels["label"] != "unlabeled").sum())
        counts = dict(labels["label"].value_counts().iter_rows())
        stats[cid] = {"n_flows": labels.height, "label_counts": counts, "n_matched": n_matched}
    return stats


def read_v2(data_dir: Path) -> dict[str, dict]:
    stats: dict[str, dict] = {}
    for dataset in ("unsw", "ctu13"):
        for path in sorted((Path(data_dir) / "flows" / dataset).glob("*.json")):
            m = cap.read_manifest(path) if path.name != "schema.json" else None
            if m is None or m.status != "done":
                continue
            stats[m.capture_id] = {
                "n_flows": m.n_flows,
                "label_counts": m.label_counts,
                "n_matched": m.n_matched if dataset == "ctu13" else None,
            }
    return stats


def load_notes(path: Path) -> dict[str, str]:
    if not Path(path).exists():
        return {}
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return {str(k): str(v) for k, v in data.items() if v}


def _shares(counts: dict[str, int], total: int) -> dict[str, float]:
    return {k: v / total for k, v in sorted(counts.items())} if total else {}


def compare(v1: dict[str, dict], v2: dict[str, dict], notes: dict[str, str]) -> pl.DataFrame:
    rows = []
    for cid in sorted(v2):
        b = v2[cid]
        a = v1.get(cid)
        sh2 = _shares(b["label_counts"], b["n_flows"])
        row = {
            "capture_id": cid,
            "in_v1": a is not None,
            "n_flows_v2": b["n_flows"],
            "shares_v2": json.dumps(sh2, ensure_ascii=False),
            "match_rate_v2": b["n_matched"] / b["n_flows"]
            if b["n_matched"] is not None and b["n_flows"]
            else None,
            "explained": notes.get(cid, ""),
        }
        if a is None:
            row.update(
                {
                    "n_flows_v1": None,
                    "rel_diff": None,
                    "shares_v1": None,
                    "max_class_share_diff_pp": None,
                    "match_rate_v1": None,
                }
            )
        else:
            sh1 = _shares(a["label_counts"], a["n_flows"])
            classes = set(sh1) | set(sh2)
            row.update(
                {
                    "n_flows_v1": a["n_flows"],
                    "rel_diff": abs(b["n_flows"] - a["n_flows"]) / a["n_flows"]
                    if a["n_flows"]
                    else None,
                    "shares_v1": json.dumps(sh1, ensure_ascii=False),
                    "max_class_share_diff_pp": 100
                    * max((abs(sh1.get(c, 0) - sh2.get(c, 0)) for c in classes), default=0.0),
                    "match_rate_v1": a["n_matched"] / a["n_flows"]
                    if a["n_matched"] is not None and a["n_flows"]
                    else None,
                }
            )
        rows.append(row)
    columns = [
        "capture_id",
        "in_v1",
        "n_flows_v1",
        "n_flows_v2",
        "rel_diff",
        "shares_v1",
        "shares_v2",
        "max_class_share_diff_pp",
        "match_rate_v1",
        "match_rate_v2",
        "explained",
    ]
    schema = {
        "capture_id": pl.String,
        "in_v1": pl.Boolean,
        "n_flows_v1": pl.Int64,
        "n_flows_v2": pl.Int64,
        "rel_diff": pl.Float64,
        "shares_v1": pl.String,
        "shares_v2": pl.String,
        "max_class_share_diff_pp": pl.Float64,
        "match_rate_v1": pl.Float64,
        "match_rate_v2": pl.Float64,
        "explained": pl.String,
    }
    return pl.DataFrame(rows, schema=schema).select(columns)


def discrepancy_reasons(row: dict) -> list[str]:
    reasons = []
    if not row["in_v1"]:
        return ["захвата нет в v1"]
    if row["rel_diff"] is not None and row["rel_diff"] > REL_DIFF_LIMIT:
        reasons.append(
            f"число потоков: v1 {row['n_flows_v1']}, v2 {row['n_flows_v2']} "
            f"({100 * row['rel_diff']:.1f}%)"
        )
    if (row["max_class_share_diff_pp"] or 0) > SHARE_DIFF_LIMIT_PP:
        reasons.append(f"доля класса разошлась на {row['max_class_share_diff_pp']:.1f} п. п.")
    if (
        row["match_rate_v1"] is not None
        and row["match_rate_v2"] is not None
        and row["match_rate_v2"] < row["match_rate_v1"]
    ):
        reasons.append(
            f"доля сопоставления упала: v1 {row['match_rate_v1']:.4f}, "
            f"v2 {row['match_rate_v2']:.4f}"
        )
    return reasons


def unexplained(table: pl.DataFrame) -> list[dict]:
    """Строки с расхождением сверх порогов и без объяснения. Отсутствие в v1 — пометка,
    а не расхождение: сравнивать не с чем."""
    out = []
    for row in table.iter_rows(named=True):
        if not row["in_v1"] or row["explained"]:
            continue
        reasons = discrepancy_reasons(row)
        if reasons:
            out.append({"capture_id": row["capture_id"], "reason": "; ".join(reasons)})
    return out


def run_compare(
    cfg: DataConfig,
    *,
    v1_dir: Path,
    data_dir: Path = Path("data"),
    notes_path: Path = DEFAULT_NOTES,
) -> tuple[pl.DataFrame, list[dict]]:
    if not Path(v1_dir).is_dir():
        raise ValueError(f"нет папки с таблицами v1: {v1_dir}")
    v2 = read_v2(data_dir)
    if not v2:
        raise ValueError("нет готовых захватов v2 — сначала `mlsiem data flows`")
    table = compare(read_v1(v1_dir), v2, load_notes(notes_path))
    with cap.atomic_path(Path(data_dir) / "compare_v1.csv") as tmp:
        table.write_csv(tmp)
    return table, unexplained(table)
