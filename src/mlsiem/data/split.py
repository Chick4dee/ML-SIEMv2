"""Разбиения train/val/test без утечек (research R7).

Три стратегии:
- `unsw_time` — внутри КАЖДОГО дня UNSW потоки идут по времени, границы — по квантилям
  числа потоков (0.70 / 0.85), а не по часам: трафик неравномерный, и «по часам» части
  получились бы непредсказуемого размера;
- `unsw_cross_day` — первый день целиком → train, второй день: первые 15% потоков → val,
  остальное → test (с зазором). Жёстче: модель учится на одном дне, а проверяется на другом;
- `ctu13_scenario` — сценарий CTU-13 целиком в одной части (из конфига). В test обязано
  быть семейство ботнета, которого нет в train: так проверяется обобщение на новую малварь.

Зазор: вокруг каждой временной границы зона ±gap_ms (10 минут). Поток, чей интервал
[first_seen, last_seen] задевает эту зону, не попадает никуда — иначе одна и та же сессия
(или её кусок, порезанный nfstream) оказалась бы и в train, и в test. Сколько потоков
выброшено и каких классов — пишется в манифест и в отчёт.

Перед записью всё проверяется `check_invariants()`: нарушение — исключение, файлы не пишутся.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import polars as pl

from mlsiem.data import captures as cap
from mlsiem.data.config import DataConfig, SplitConfig
from mlsiem.data.extract import content_hash

PARTS = ("train", "val", "test")
SPLIT_DATASET = {"unsw_time": "unsw", "unsw_cross_day": "unsw", "ctu13_scenario": "ctu13"}
FIRST, LAST = "bidirectional_first_seen_ms", "bidirectional_last_seen_ms"
NEEDED = ["flow_uid", "capture_id", FIRST, LAST, "label"]


class SplitInvariantError(ValueError):
    """Разбиение нарушает инварианты — это утечка, а не предупреждение."""

    def __init__(self, violations: list[str]) -> None:
        self.violations = violations
        super().__init__("нарушены инварианты разбиения:\n  - " + "\n  - ".join(violations))


# ---------------------------------------------------------------- вспомогательное


def _with_group(flows: pl.DataFrame, dataset: str) -> pl.DataFrame:
    """Добавляет колонку group: день UNSW (`22-1-2015`) или номер сценария CTU-13."""
    if dataset == "unsw":
        expr = pl.col("capture_id").str.extract(r"^unsw_(.+)_\d+$", 1)
    else:
        expr = pl.col("capture_id").str.extract(r"^ctu13_(\d+)$", 1).cast(pl.Int64).cast(pl.String)
    return flows.with_columns(expr.alias("group"))


def _day_key(day: str) -> tuple[int, int, int]:
    d, m, y = (int(x) for x in day.split("-"))
    return (y, m, d)


def _boundary(day_flows: pl.DataFrame, q: float) -> int:
    """Время, до которого лежит доля q потоков дня (по началу потока)."""
    starts = day_flows[FIRST].sort()
    idx = min(int(q * len(starts)), len(starts) - 1)
    return int(starts[idx])


def _cut_day(day_flows: pl.DataFrame, bounds: list[int], names: list[str], gap: int):
    """Режет один день по границам. Возвращает (назначения, интервалы частей)."""
    lo = int(day_flows[FIRST].min())
    hi = int(day_flows[LAST].max()) + 1
    # Поток задевает зону зазора, если его интервал пересекается с [b - gap, b + gap]
    in_gap = pl.lit(False)
    for b in bounds:
        in_gap = in_gap | ((pl.col(FIRST) <= b + gap) & (pl.col(LAST) >= b - gap))
    part = pl.lit(names[-1])
    for b, name in reversed(list(zip(bounds, names[:-1], strict=True))):
        part = pl.when(pl.col(FIRST) < b).then(pl.lit(name)).otherwise(part)
    assigned = day_flows.with_columns(
        pl.when(in_gap).then(pl.lit(None, pl.String)).otherwise(part).alias("part")
    )
    edges = [lo] + [x for b in bounds for x in (b - gap, b + gap)] + [hi]
    intervals = {name: (edges[2 * i], edges[2 * i + 1]) for i, name in enumerate(names)}
    return assigned, intervals


# ---------------------------------------------------------------- стратегии


def compute_split(
    flows: pl.DataFrame, name: str, split_cfg: SplitConfig
) -> tuple[pl.DataFrame, dict]:
    """Чистая функция: таблица потоков → (flow_uid/part/… для всех потоков, описание частей).

    part = null означает «исключён зазором».
    """
    dataset = SPLIT_DATASET[name]
    flows = _with_group(flows.select(NEEDED), dataset)
    gap = split_cfg.gap_ms
    parts_info: dict[str, dict] = {p: {"groups": [], "intervals": []} for p in PARTS}
    chunks = []

    if name == "unsw_time":
        q1, q2 = split_cfg.quantiles
        for day in sorted(flows["group"].unique().to_list(), key=_day_key):
            day_flows = flows.filter(pl.col("group") == day)
            bounds = [_boundary(day_flows, q1), _boundary(day_flows, q2)]
            assigned, intervals = _cut_day(day_flows, bounds, list(PARTS), gap)
            chunks.append(assigned)
            for p, (s, e) in intervals.items():
                parts_info[p]["groups"].append(day)
                parts_info[p]["intervals"].append({"group": day, "start_ms": s, "end_ms": e})

    elif name == "unsw_cross_day":
        days = sorted(flows["group"].unique().to_list(), key=_day_key)
        if len(days) != 2:
            raise ValueError(f"для unsw_cross_day нужны ровно два дня UNSW, а есть {days}")
        # Первый день целиком — train. Делить его на train/val нельзя: атаки в разметке дня
        # 22-1-2015 есть только в первых ~40% потоков, и val из конца дня был бы чистым benign
        first_day = flows.filter(pl.col("group") == days[0])
        chunks.append(first_day.with_columns(pl.lit("train").alias("part")))
        parts_info["train"]["groups"].append(days[0])
        parts_info["train"]["intervals"].append(
            {
                "group": days[0],
                "start_ms": int(first_day[FIRST].min()),
                "end_ms": int(first_day[LAST].max()) + 1,
            }
        )
        # Второй день: начало (доля 1 − q2, т. е. 15%) — val для подбора порога, остальное —
        # test, между ними тот же зазор. Модель по-прежнему не видит второй день при обучении
        second_day = flows.filter(pl.col("group") == days[1])
        bound = _boundary(second_day, 1 - split_cfg.quantiles[1])
        assigned, intervals = _cut_day(second_day, [bound], ["val", "test"], gap)
        chunks.append(assigned)
        for p, (st, en) in intervals.items():
            parts_info[p]["groups"].append(days[1])
            parts_info[p]["intervals"].append({"group": days[1], "start_ms": st, "end_ms": en})

    elif name == "ctu13_scenario":
        mapping = {str(s): p for p, scenarios in split_cfg.ctu13_parts.items() for s in scenarios}
        present = set(flows["group"].unique().to_list())
        missing = sorted((set(mapping) - present), key=int)
        if missing:
            raise ValueError(f"для ctu13_scenario нет потоков сценариев {missing}")
        chunks.append(
            flows.with_columns(
                pl.col("group").replace_strict(mapping, return_dtype=pl.String).alias("part")
            )
        )
        for p, scenarios in split_cfg.ctu13_parts.items():
            parts_info[p]["groups"] = [str(s) for s in scenarios]
            parts_info[p]["families"] = sorted({cap.CTU13_FAMILIES[s] for s in scenarios})
        # FR-016a: без незнакомого семейства в test нельзя проверить обобщение на новую малварь
        new_families = set(parts_info["test"]["families"]) - set(parts_info["train"]["families"])
        if not new_families:
            raise ValueError(
                "в test CTU-13 нет семейства ботнета, отсутствующего в train — "
                "поправьте split.ctu13_parts в конфиге"
            )
        parts_info["test"]["new_families"] = sorted(new_families)
    else:
        raise ValueError(f"неизвестное разбиение {name!r}")

    return pl.concat(chunks).sort("flow_uid"), parts_info


def summarize(assigned: pl.DataFrame, parts_info: dict) -> tuple[dict, dict, dict]:
    """Размеры частей, классы по частям, исключённое и отсутствующие классы."""
    all_classes = set(assigned["label"].unique().to_list())
    parts, missing = {}, {}
    for p in PARTS:
        sub = assigned.filter(pl.col("part") == p)
        counts = dict(sub["label"].value_counts().sort("label").iter_rows())
        parts[p] = {**parts_info[p], "n_flows": sub.height, "label_counts": counts}
        missing[p] = sorted(all_classes - set(counts))
    ex = assigned.filter(pl.col("part").is_null())
    excluded = {
        "total": ex.height,
        "by_label": dict(ex["label"].value_counts().sort("label").iter_rows()),
    }
    return parts, excluded, missing


# ---------------------------------------------------------------- инварианты


def check_invariants(assigned: pl.DataFrame, parts: dict, name: str, gap_ms: int) -> None:
    """Проверяет разбиение и бросает SplitInvariantError со списком всех нарушений.

    assigned — flow_uid, group, part (null = исключён), время начала/конца.
    """
    violations: list[str] = []

    dup = assigned.filter(pl.col("flow_uid").is_duplicated())["flow_uid"].unique()
    if len(dup):
        violations.append(f"flow_uid встречается больше одного раза: {dup.head(5).to_list()}")

    # Интервалы частей внутри одной группы (дня) не должны пересекаться
    by_group: dict[str, list[tuple[int, int, str]]] = {}
    for p in PARTS:
        for iv in parts[p].get("intervals", []):
            by_group.setdefault(iv["group"], []).append((iv["start_ms"], iv["end_ms"], p))
    for group, ivs in by_group.items():
        ivs.sort()
        for (s1, e1, p1), (s2, e2, p2) in zip(ivs, ivs[1:], strict=False):
            if s2 < e1:
                violations.append(
                    f"{group}: интервалы {p1} [{s1}, {e1}) и {p2} [{s2}, {e2}) пересекаются"
                )

    # Каждый назначенный поток лежит целиком внутри интервала своей части
    # (для зазорных границ это и есть «поток из зоны зазора не попал ни в одну часть»)
    kept = assigned.filter(pl.col("part").is_not_null())
    if by_group:
        iv_table = pl.DataFrame(
            [(g, p, s, e) for g, ivs in by_group.items() for s, e, p in ivs],
            schema={"group": pl.String, "part": pl.String, "_s": pl.Int64, "_e": pl.Int64},
            orient="row",
        )
        checked = kept.join(iv_table, on=["group", "part"], how="left")
        outside = checked.filter(
            pl.col("_s").is_null() | (pl.col(FIRST) < pl.col("_s")) | (pl.col(LAST) >= pl.col("_e"))
        )
        if outside.height:
            violations.append(
                f"{outside.height} потоков выходят за интервал своей части (задевают зазор): "
                f"{outside['flow_uid'].head(5).to_list()}"
            )

    if name == "ctu13_scenario":
        split_groups = kept.group_by("group").agg(pl.col("part").n_unique().alias("n"))
        bad = split_groups.filter(pl.col("n") > 1)["group"].to_list()
        if bad:
            violations.append(f"сценарии CTU-13 разрезаны между частями: {sorted(bad)}")

    if violations:
        raise SplitInvariantError(violations)


# ---------------------------------------------------------------- сборка и запись


def load_flows_for_split(dataset_dir: Path) -> tuple[pl.DataFrame, dict[str, str]]:
    """Читает только нужные колонки всех parquet датасета и проверяет, что все захваты готовы."""
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
    files = [dataset_dir / f"{m.capture_id}.parquet" for m in manifests]
    flows = pl.scan_parquet(files).select(NEEDED).collect()
    return flows, {m.capture_id: m.content_hash for m in manifests}


def build_split(cfg: DataConfig, name: str, *, data_dir: Path = Path("data")) -> dict:
    dataset = SPLIT_DATASET[name]
    flows, input_hashes = load_flows_for_split(Path(data_dir) / "flows" / dataset)
    assigned, parts_info = compute_split(flows, name, cfg.split)
    check_invariants(assigned, parts_info, name, cfg.split.gap_ms)
    parts, excluded, missing = summarize(assigned, parts_info)

    table = assigned.filter(pl.col("part").is_not_null()).select("flow_uid", "part")
    manifest = {
        "split_name": name,
        "dataset": dataset,
        "parts": parts,
        "params": {
            "quantiles": list(cfg.split.quantiles),
            "gap_ms": cfg.split.gap_ms,
            "seed": cfg.seed,
            "ctu13_parts": {k: list(v) for k, v in cfg.split.ctu13_parts.items()},
        },
        "excluded": excluded,
        "missing_classes": missing,
        "input_hashes": dict(sorted(input_hashes.items())),
        "hash": content_hash(table),
    }
    out = Path(data_dir) / "splits"
    with cap.atomic_path(out / f"{name}.parquet") as tmp:
        table.write_parquet(tmp)
    with cap.atomic_path(out / f"{name}.json") as tmp:
        tmp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def split_hash(assigned: pl.DataFrame) -> str:
    """Хеш таблицы flow_uid → part (для тестов на чистой функции)."""
    table = assigned.filter(pl.col("part").is_not_null()).select("flow_uid", "part")
    return content_hash(table) if table.height else hashlib.sha256(b"").hexdigest()
