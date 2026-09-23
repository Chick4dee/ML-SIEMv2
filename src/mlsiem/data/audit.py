"""Проверка на артефакты датасета (research R8).

Идея: если по ОДНОМУ полю простое дерево глубины 4 уже хорошо угадывает класс на val, то
модель, которой дадут это поле, почти наверняка выучит его, а не саму атаку. Для IP,
портов, времени, MAC и имени сервера это однозначно плохо (dangerous): модель запомнит
адреса стенда UNSW, а в живой сети они другие. Для поведенческих признаков высокая
точность может быть и честной — поэтому они получают мягкий статус suspicious и требуют
ручного разбора.

Метрика — macro PR-AUC (average precision по классам one-vs-rest), базовая линия —
PR-AUC «угадывания по доле класса», то есть средняя доля классов на val. Прирост над ней
(lift) и сравнивается с порогом: так поле не выглядит «сильным» только потому, что
в выборке мало классов.

Выборка — до `sample_per_part` потоков на часть, стратифицированно по классу и с фиксированным
сидом: весь UNSW в дерево не нужен, а результат должен повторяться.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import polars as pl
from sklearn.metrics import average_precision_score
from sklearn.tree import DecisionTreeClassifier

from mlsiem.data import captures as cap
from mlsiem.data.config import AuditConfig, DataConfig
from mlsiem.data.schema import SCHEMA
from mlsiem.data.split import SPLIT_DATASET

AUDITED_GROUPS = ("feature", "identity", "time", "dpi")
# Для этих групп сильное поле — точно утечка; для feature — повод посмотреть глазами
LEAKY_GROUPS = ("identity", "time", "dpi")
IP_FIELDS = ("src_ip", "dst_ip")
# unlabeled в CTU-13 — «мы не знаем», а не класс; учить на нём дерево бессмысленно
IGNORED_LABELS = ("unlabeled",)


def stratified_sample(df: pl.DataFrame, n_max: int, seed: int) -> pl.DataFrame:
    """До n_max строк с сохранением долей классов; одинаково при одинаковом сиде."""
    if df.height <= n_max:
        return df
    frac = n_max / df.height
    df = df.sort("flow_uid")  # иначе результат зависел бы от порядка чтения файлов
    rank = pl.int_range(pl.len()).shuffle(seed=seed).over("label")
    # Хотя бы одна строка редкого класса остаётся: иначе worms из 2 потоков пропал бы совсем
    keep = pl.max_horizontal((pl.len() * frac).floor(), pl.lit(1)).over("label")
    return df.filter(rank < keep)


def _encode(train: pl.Series, val: pl.Series) -> tuple[np.ndarray, np.ndarray]:
    """Числа — как есть (null → -1); строки — частота значения в train (невиданное → 0)."""
    if train.dtype == pl.String:
        freq = train.value_counts()
        mapping = dict(zip(freq[train.name].to_list(), freq["count"].to_list(), strict=True))

        def enc(s: pl.Series) -> np.ndarray:
            return s.replace_strict(mapping, default=0, return_dtype=pl.Int64).to_numpy()

        return enc(train).reshape(-1, 1), enc(val).reshape(-1, 1)
    return (
        train.cast(pl.Float64).fill_null(-1).to_numpy().reshape(-1, 1),
        val.cast(pl.Float64).fill_null(-1).to_numpy().reshape(-1, 1),
    )


def _subnet24(s: pl.Series) -> pl.Series:
    """`10.1.2.3` → `10.1.2`. IPv6 и прочее остаются как есть."""
    return s.str.replace(r"^(\d+\.\d+\.\d+)\.\d+$", "$1")


def pr_auc_macro(y_val: np.ndarray, proba: np.ndarray, classes: list[str]) -> float:
    scores = []
    for i, c in enumerate(classes):
        positives = y_val == c
        if positives.any():
            scores.append(average_precision_score(positives, proba[:, i]))
    return float(np.mean(scores)) if scores else float("nan")


def audit_fields(
    train: pl.DataFrame,
    val: pl.DataFrame,
    fields: list[tuple[str, str]],
    cfg: AuditConfig,
    seed: int,
) -> pl.DataFrame:
    """Чистая функция аудита: (поле, группа) → строка результата."""
    train = train.filter(~pl.col("label").is_in(IGNORED_LABELS))
    val = val.filter(~pl.col("label").is_in(IGNORED_LABELS))
    classes = sorted(set(train["label"].unique().to_list()))
    # Оцениваем только классы, которые есть в train: остальные дерево предсказать не может,
    # и их нулевой AP занизил бы и поле, и базовую линию одинаково — лишний шум
    val = val.filter(pl.col("label").is_in(classes))
    y_train = train["label"].to_numpy()
    y_val = val["label"].to_numpy()
    val_classes = [c for c in classes if (y_val == c).any()]
    baseline = float(np.mean([(y_val == c).mean() for c in val_classes])) if val_classes else 0.0

    rows = []
    for name, group in fields:
        variants = [("raw", train[name], val[name])]
        if name in IP_FIELDS:
            variants.append(("subnet24", _subnet24(train[name]), _subnet24(val[name])))
        for variant, s_train, s_val in variants:
            if not val_classes or len(classes) < 2:
                score = float("nan")
            else:
                x_train, x_val = _encode(s_train, s_val)
                tree = DecisionTreeClassifier(max_depth=cfg.tree_depth, random_state=seed)
                tree.fit(x_train, y_train)
                score = pr_auc_macro(y_val, tree.predict_proba(x_val), list(tree.classes_))
            lift = score - baseline
            if group in LEAKY_GROUPS and lift >= cfg.dangerous_lift:
                status = "dangerous"
            elif group == "feature" and score >= cfg.suspicious_pr_auc:
                status = "suspicious"
            else:
                status = "ok"
            rows.append(
                {
                    "field": name,
                    "group": group,
                    "variant": variant,
                    "pr_auc_macro": score,
                    "baseline": baseline,
                    "lift": lift,
                    "status": status,
                }
            )
    return pl.DataFrame(
        rows,
        schema={
            "field": pl.String,
            "group": pl.String,
            "variant": pl.String,
            "pr_auc_macro": pl.Float64,
            "baseline": pl.Float64,
            "lift": pl.Float64,
            "status": pl.String,
        },
    )


def audited_fields() -> list[tuple[str, str]]:
    return [(c.name, c.group) for c in SCHEMA.columns if c.group in AUDITED_GROUPS]


def run_audit(cfg: DataConfig, split_name: str, *, data_dir: Path = Path("data")) -> pl.DataFrame:
    dataset = SPLIT_DATASET[split_name]
    split_path = Path(data_dir) / "splits" / f"{split_name}.parquet"
    if not split_path.exists():
        raise ValueError(f"нет разбиения {split_path} — сначала `mlsiem data split`")
    fields = audited_fields()
    columns = ["flow_uid", "label"] + [f for f, _ in fields]
    flow_files = sorted((Path(data_dir) / "flows" / dataset).glob("*.parquet"))
    # Лениво: из parquet читаются только нужные колонки и только потоки train/val
    flows = (
        pl.scan_parquet(flow_files)
        .select(columns)
        .join(
            pl.scan_parquet(split_path).filter(pl.col("part").is_in(["train", "val"])),
            on="flow_uid",
            how="inner",
        )
        .collect()
    )
    parts = {
        p: stratified_sample(flows.filter(pl.col("part") == p), cfg.audit.sample_per_part, cfg.seed)
        for p in ("train", "val")
    }
    result = audit_fields(parts["train"], parts["val"], fields, cfg.audit, cfg.seed)
    with cap.atomic_path(Path(data_dir) / "audit" / f"{split_name}.parquet") as tmp:
        result.write_parquet(tmp)
    return result
