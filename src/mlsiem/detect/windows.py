"""Окна потоков: сетка, ключ, идентификатор, метки, сводные признаки и последовательности
(фича 007, research R1–R4, R9, R18).

Окно — это потоки одного атакующего (правило направления 004, `soc/direction.py`), начавшиеся
в пределах интервала фиксированной длины L. Сетка окон фиксирована от начала эпохи:

    window_start_ms = floor(first_seen_ms / L) · L

поэтому окно не зависит от того, с какого потока начался вход, и пакетный прогон, обучение и
онлайн-потребитель получают ровно одни и те же окна (FR-003, FR-016). Для аугментации train
сетка сдвигается (`shift_ms`): start = floor((t − shift) / L) · L + shift.

Главное правило модуля: окна и признаки окна строит ТОЛЬКО он — одна и та же функция для
эксперимента, `soc run` и потребителя 005 (конституция II, train = serve). Всё векторно в
polars: окон десятки тысяч, потоков — полтора миллиона, построчный Python был бы слишком
медленным.

Что в модель НЕ попадает (FR-004): адреса, значения портов, идентификаторы потоков и
абсолютное время. Из них получаются только счётчики, доли и относительные величины внутри
окна («сколько разных целей», «доля потоков к портам < 1024», «секунд от начала окна»).
Тест `test_windows_forbidden.py` проверяет это по именам признаков.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl
import yaml

from mlsiem.data.config import ConfigError, _get, _number
from mlsiem.data.schema import SCHEMA
from mlsiem.data.split import SPLIT_DATASET
from mlsiem.data.taxonomy import UNSW_MAP
from mlsiem.detect.metrics import BENIGN
from mlsiem.soc.direction import DIRECTION_COLUMNS

DEFAULT_WINDOWS_CONFIG = Path("configs/windows.yaml")
FIRST = "bidirectional_first_seen_ms"
LAST = "bidirectional_last_seen_ms"
KNOWN_CANDIDATES = ("lgbm", "gru")
SELECTION_METRICS = ("macro_pr_auc_reliable_val",)
AGGREGATES = ("max",)
# Порт ниже этого — «сервисный» (как в правиле направления 004): доля таких потоков окна —
# признак «ходит по сервисам», а не значение порта
LOW_PORT_BELOW = 1024
PROTOCOL_SHARES = {"tcp": (6,), "udp": (17,), "icmp": (1, 58)}

# Порядок классов атак для тай-брейка метки окна (R2): как в таблице UNSW таксономии 001.
# Тот же порядок и у двух классов с одинаковым числом потоков в окне — детерминированно
TAXONOMY_ORDER = list(dict.fromkeys(UNSW_MAP.values()))


# ================================================================ конфиг


@dataclass(frozen=True)
class WindowsConfig:
    """configs/windows.yaml (contracts/cli.md «Конфиг»). Все числа эксперимента — отсюда."""

    split: str
    transfer_split: str
    seed: int
    length_ms: int
    seq_max: int
    train_shifts_ms: tuple[int, ...]
    holdout_share: float
    current_model: str
    current_aggregate: str
    metric: str
    min_class_windows: int
    min_gain: float
    max_drop: float
    single_feature_share: float
    candidates: dict[str, dict[str, Any]]
    output: Path
    raw: dict[str, Any] = field(hash=False, compare=False)


def _unsw_split(raw: dict, key: str) -> str:
    name = _get(raw, key, str)
    if SPLIT_DATASET.get(name) != "unsw":
        raise ConfigError(
            f"ключ {key}: ожидалось разбиение UNSW (unsw_time или unsw_cross_day), "
            f"а записано {name!r}"
        )
    return name


def parse_windows_config(raw: Any) -> WindowsConfig:
    """Проверяет уже прочитанный словарь конфига целиком — до любой работы (как 002/004)."""
    if not isinstance(raw, dict):
        raise ConfigError("конфиг окон: ожидался словарь верхнего уровня")
    length = _get(raw, "window.length_ms", int)
    if length <= 0:
        raise ConfigError(f"ключ window.length_ms: длина окна должна быть > 0, а записано {length}")
    seq_max = _get(raw, "window.seq_max", int)
    if seq_max < 1:
        raise ConfigError(f"ключ window.seq_max: нужно целое ≥ 1, а записано {seq_max}")
    shifts = _get(raw, "window.train_shifts_ms", list)
    if not shifts or not all(isinstance(s, int) and not isinstance(s, bool) for s in shifts):
        raise ConfigError("ключ window.train_shifts_ms: нужен непустой список целых (мс)")
    bad = [s for s in shifts if not 0 <= s < length]
    if bad:
        raise ConfigError(
            f"ключ window.train_shifts_ms: сдвиг должен быть в [0, length_ms = {length}), "
            f"а записано {bad}"
        )
    if 0 not in shifts:
        raise ConfigError(
            "ключ window.train_shifts_ms: нужен сдвиг 0 — основная сетка, на которой живут "
            "val, test и цепочка"
        )
    if len(set(shifts)) != len(shifts):
        raise ConfigError(f"ключ window.train_shifts_ms: сдвиги повторяются: {shifts}")
    holdout = _number(raw, "window.holdout_share")
    if not 0 < holdout < 1:
        raise ConfigError(f"ключ window.holdout_share: нужно 0 < доля < 1, а записано {holdout}")
    metric = _get(raw, "selection.metric", str)
    if metric not in SELECTION_METRICS:
        raise ConfigError(
            f"ключ selection.metric: поддерживается только {list(SELECTION_METRICS)}, "
            f"а записано {metric!r}"
        )
    min_windows = _get(raw, "selection.min_class_windows", int)
    if min_windows < 1:
        raise ConfigError(
            f"ключ selection.min_class_windows: нужно целое ≥ 1, а записано {min_windows}"
        )
    min_gain = _number(raw, "selection.min_gain")
    if min_gain < 0:
        raise ConfigError(
            f"ключ selection.min_gain: прирост не может быть отрицательным ({min_gain})"
        )
    max_drop = _number(raw, "audit.max_drop")
    share = _number(raw, "audit.single_feature_share")
    for key, v in (("audit.max_drop", max_drop), ("audit.single_feature_share", share)):
        if not 0 < v <= 1:
            raise ConfigError(f"ключ {key}: нужно 0 < значение ≤ 1, а записано {v}")
    aggregate = _get(raw, "current_aggregate", str)
    if aggregate not in AGGREGATES:
        raise ConfigError(
            f"ключ current_aggregate: поддерживается {list(AGGREGATES)}, а записано {aggregate!r}"
        )
    cands = _get(raw, "candidates", dict)
    unknown = sorted(set(cands) - set(KNOWN_CANDIDATES))
    if unknown:
        raise ConfigError(
            f"ключ candidates: неизвестные кандидаты {unknown}; поддерживаются "
            f"{list(KNOWN_CANDIDATES)}"
        )
    if "lgbm" not in cands:
        raise ConfigError("ключ candidates: нужен бустинг lgbm — это бейзлайн сравнения (R6)")
    candidates = {n: dict(_get(raw, f"candidates.{n}", dict)) for n in cands}
    return WindowsConfig(
        split=_unsw_split(raw, "split"),
        transfer_split=_unsw_split(raw, "transfer_split"),
        seed=_get(raw, "seed", int),
        length_ms=length,
        seq_max=seq_max,
        train_shifts_ms=tuple(sorted(shifts)),
        holdout_share=holdout,
        current_model=str(_get(raw, "current_model", str)),
        current_aggregate=aggregate,
        metric=metric,
        min_class_windows=min_windows,
        min_gain=min_gain,
        max_drop=max_drop,
        single_feature_share=share,
        candidates=candidates,
        output=Path(_get(raw, "output", str)),
        raw=raw,
    )


def load_windows_config(path: str | Path = DEFAULT_WINDOWS_CONFIG) -> WindowsConfig:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"не найден файл конфига {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: не читается как YAML: {exc}") from exc
    return parse_windows_config(raw)


# ================================================================ окна


# Поля потока, нужные окнам помимо признаков: контекст (цели, порты, время, захват) и поля
# правила направления. Их же кладёт в `window_pending` онлайн-потребитель (R13)
CONTEXT = (
    "flow_uid",
    "capture_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    FIRST,
    LAST,
)
WINDOW_FLOW_COLUMNS = tuple(dict.fromkeys([*CONTEXT, *DIRECTION_COLUMNS]))
# Что берётся из результата правила направления (`soc.direction.sides`)
SIDE_COLUMNS = ("flow_uid", "reversed", "attacker_ip", "victim_ip")


def flow_columns() -> list[str]:
    """Все поля потока, которые нужны окнам и обеим моделям окон, в порядке схемы."""
    feats = SCHEMA.feature_columns()
    return [*WINDOW_FLOW_COLUMNS, *[f for f in feats if f not in WINDOW_FLOW_COLUMNS]]


def window_id_of(attacker_ip: str, window_start_ms: int, length_ms: int) -> str:
    """`w-<хеш16>` от атакующего, начала и длины окна (R1). Детерминирован: не счётчик и не
    зависит от порядка строк — один и тот же в пакете, при обучении и в потребителе."""
    from mlsiem.soc.store import input_digest  # локально: store тянет конфиг SOC

    return (
        "w-" + input_digest(str(attacker_ip), str(int(window_start_ms)), str(int(length_ms)))[:16]
    )


def _victim_port() -> pl.Expr:
    # Порт цели — порт стороны-жертвы: у ответного потока это src_port (R3, правило 004)
    return pl.when(pl.col("reversed")).then(pl.col("src_port")).otherwise(pl.col("dst_port"))


def _attacker_port() -> pl.Expr:
    return pl.when(pl.col("reversed")).then(pl.col("dst_port")).otherwise(pl.col("src_port"))


def assign_windows(
    flows: pl.DataFrame, side: pl.DataFrame, *, length_ms: int, shift_ms: int = 0
) -> pl.DataFrame:
    """Какому окну принадлежит каждый поток: flow_uid, window_id, attacker_ip,
    window_start_ms, shift_ms. Это соответствие переиспользует потребитель (R13)."""
    if length_ms <= 0:
        raise ValueError(f"длина окна должна быть > 0, а передано {length_ms}")
    base = flows.select("flow_uid", pl.col(FIRST).cast(pl.Int64)).join(
        side.select("flow_uid", pl.col("attacker_ip").cast(pl.String)), on="flow_uid", how="inner"
    )
    L, s = int(length_ms), int(shift_ms)
    base = base.with_columns(
        (((pl.col(FIRST) - s) // L) * L + s).alias("window_start_ms"),
        pl.lit(s, dtype=pl.Int32).alias("shift_ms"),
    )
    # Хеш считается на уникальных парах (атакующий, начало) — их в сотни раз меньше потоков
    keys = base.select("attacker_ip", "window_start_ms").unique()
    ids = [
        window_id_of(a, t, L)
        for a, t in zip(
            keys["attacker_ip"].to_list(), keys["window_start_ms"].to_list(), strict=True
        )
    ]
    keys = keys.with_columns(pl.Series("window_id", ids, dtype=pl.String))
    return (
        base.join(keys, on=["attacker_ip", "window_start_ms"], how="left")
        .select("flow_uid", "window_id", "attacker_ip", "window_start_ms", "shift_ms")
        .sort("flow_uid")
    )


def _ordered(
    flows: pl.DataFrame, side: pl.DataFrame, assignment: pl.DataFrame, cols
) -> pl.DataFrame:
    """Потоки окон в каноническом порядке: окно, время начала, flow_uid.

    Порядок важен не только для «первых 128»: суммы и средние считаются в этом порядке, так
    что пакет и потребитель получают одинаковые числа до последнего бита (эквивалентность).
    """
    need = list(dict.fromkeys(["flow_uid", FIRST, *cols]))
    return (
        assignment.join(flows.select([c for c in need if c in flows.columns]), on="flow_uid")
        .join(side.select(SIDE_COLUMNS[:2] + ("victim_ip",)), on="flow_uid", how="left")
        .sort(["window_id", FIRST, "flow_uid"])
    )


def build_windows(
    flows: pl.DataFrame,
    side: pl.DataFrame,
    *,
    length_ms: int,
    seq_max: int,
    shift_ms: int = 0,
    part: str | None = None,
    assignment: pl.DataFrame | None = None,
) -> pl.DataFrame:
    """Кадр окон по data-model «Окно» (без меток — их даёт `window_labels`).

    Колонки: window_id, attacker_ip, window_start_ms, window_end_ms, shift_ms, part, n_flows,
    truncated, flow_uids (по порядку), first_seen_ms, last_seen_ms, capture_id (первого
    потока), targets (list[{ip, n}] по убыванию n), n_dst_ports. Порядок строк — по времени.
    """
    if assignment is None:
        assignment = assign_windows(flows, side, length_ms=length_ms, shift_ms=shift_ms)
    df = _ordered(flows, side, assignment, ["capture_id", LAST, "src_port", "dst_port"])
    df = df.with_columns(_victim_port().alias("_vport"))
    win = df.group_by("window_id", maintain_order=True).agg(
        pl.col("attacker_ip").first(),
        pl.col("window_start_ms").first(),
        pl.col("shift_ms").first(),
        pl.len().cast(pl.Int32).alias("n_flows"),
        pl.col("flow_uid").alias("flow_uids"),
        pl.col(FIRST).min().alias("first_seen_ms"),
        pl.col(LAST).max().alias("last_seen_ms"),
        pl.col("capture_id").first(),
        pl.col("_vport").drop_nulls().n_unique().cast(pl.Int32).alias("n_dst_ports"),
    )
    targets = (
        df.group_by(["window_id", "victim_ip"])
        .agg(pl.len().cast(pl.Int64).alias("n"))
        .sort(["window_id", "n", "victim_ip"], descending=[False, True, False])
        .group_by("window_id", maintain_order=True)
        .agg(pl.struct(pl.col("victim_ip").alias("ip"), "n").alias("targets"))
    )
    return (
        win.join(targets, on="window_id", how="left")
        .with_columns(
            (pl.col("window_start_ms") + int(length_ms)).alias("window_end_ms"),
            (pl.col("n_flows") > int(seq_max)).alias("truncated"),
            pl.lit(part, dtype=pl.String).alias("part"),
        )
        .select(
            "window_id",
            "attacker_ip",
            "window_start_ms",
            "window_end_ms",
            "shift_ms",
            "part",
            "n_flows",
            "truncated",
            "flow_uids",
            "first_seen_ms",
            "last_seen_ms",
            "capture_id",
            "targets",
            "n_dst_ports",
        )
        .sort(["window_start_ms", "attacker_ip", "shift_ms", "window_id"])
    )


def _class_rank() -> pl.Expr:
    order = {c: i for i, c in enumerate(TAXONOMY_ORDER)}
    return pl.col("label").replace_strict(order, default=len(order), return_dtype=pl.Int32)


def window_labels(assignment: pl.DataFrame, labels: pl.DataFrame) -> pl.DataFrame:
    """Метка окна по R2: «атака», если есть хотя бы один атакующий поток; класс — самый
    частый атакующий класс окна, при равенстве — тот, что раньше в таксономии.

    Колонки: window_id, label, n_attack_classes, attack_share (доля атакующих потоков) —
    последние две нужны отчёту о «смешанных» окнах. Метки идут только в оценку, не в модель.
    """
    df = assignment.select("flow_uid", "window_id").join(
        labels.select("flow_uid", "label"), on="flow_uid", how="left"
    )
    df = df.with_columns(pl.col("label").fill_null(BENIGN))
    totals = df.group_by("window_id").agg(
        pl.len().alias("_n"),
        (pl.col("label") != BENIGN).sum().alias("_n_attack"),
        pl.col("label").filter(pl.col("label") != BENIGN).n_unique().alias("n_attack_classes"),
    )
    top = (
        df.filter(pl.col("label") != BENIGN)
        .group_by(["window_id", "label"])
        .agg(pl.len().alias("_c"))
        .with_columns(_class_rank().alias("_rank"))
        .sort(["window_id", "_c", "_rank", "label"], descending=[False, True, False, False])
        .group_by("window_id", maintain_order=True)
        .agg(pl.col("label").first().alias("_top"))
    )
    return (
        totals.join(top, on="window_id", how="left")
        .select(
            "window_id",
            pl.col("_top").fill_null(BENIGN).alias("label"),
            pl.col("n_attack_classes").cast(pl.Int32),
            (pl.col("_n_attack") / pl.col("_n")).cast(pl.Float64).alias("attack_share"),
        )
        .sort("window_id")
    )


# ================================================================ сводные признаки (бустинг)

STATS = ("mean", "max", "std")
# Поведенческие признаки окна (R3) — фиксированный перечень, одно место
W_FEATURES = (
    "w_log_n_flows",
    "w_n_targets",
    "w_n_dst_ports",
    "w_n_src_ports",
    "w_share_tcp",
    "w_share_udp",
    "w_share_icmp",
    "w_share_other",
    "w_span_s",
    "w_gap_mean_s",
    "w_gap_std_s",
    "w_gap_min_s",
    "w_share_reversed",
    "w_share_low_port",
)


def summary_feature_names() -> list[str]:
    """Имена сводных признаков: из схемы 001 (не руками) и перечня `W_FEATURES`."""
    feats = SCHEMA.feature_columns()
    return [f"f_{c}_{s}" for c in feats for s in STATS] + list(W_FEATURES)


def summary_features(
    flows: pl.DataFrame, side: pl.DataFrame, assignment: pl.DataFrame
) -> pl.DataFrame:
    """window_id + сводные признаки окна (≈190), посчитанные по ВСЕМ потокам окна.

    std — генеральная (ddof = 0): у окна из одного потока она 0, а не пропуск. Интервалы
    между стартами у такого окна не определены — пропуск, его закрывает медиана конвейера.
    """
    feats = SCHEMA.feature_columns()
    df = _ordered(flows, side, assignment, [*feats, "src_port", "dst_port"])
    proto = pl.col("protocol").fill_null(-1)
    df = df.with_columns(
        [pl.col(c).cast(pl.Float64).fill_null(0.0).alias(c) for c in feats]
        + [
            _victim_port().alias("_vport"),
            _attacker_port().alias("_aport"),
            pl.col(FIRST).diff().over("window_id").alias("_gap"),
        ]
    )
    known = [p for ps in PROTOCOL_SHARES.values() for p in ps]
    vport = pl.col("_vport")
    aggs = []
    for c in feats:
        aggs += [
            pl.col(c).mean().alias(f"f_{c}_mean"),
            pl.col(c).max().alias(f"f_{c}_max"),
            pl.col(c).std(ddof=0).alias(f"f_{c}_std"),
        ]
    aggs += [
        pl.len().cast(pl.Float64).log1p().alias("w_log_n_flows"),
        pl.col("victim_ip").n_unique().cast(pl.Float64).alias("w_n_targets"),
        vport.drop_nulls().n_unique().cast(pl.Float64).alias("w_n_dst_ports"),
        pl.col("_aport").drop_nulls().n_unique().cast(pl.Float64).alias("w_n_src_ports"),
        *[
            proto.is_in(list(ps)).mean().cast(pl.Float64).alias(f"w_share_{name}")
            for name, ps in PROTOCOL_SHARES.items()
        ],
        (~proto.is_in(known)).mean().cast(pl.Float64).alias("w_share_other"),
        ((pl.col(FIRST).max() - pl.col(FIRST).min()) / 1000.0).alias("w_span_s"),
        (pl.col("_gap").mean() / 1000.0).alias("w_gap_mean_s"),
        (pl.col("_gap").std(ddof=0) / 1000.0).alias("w_gap_std_s"),
        (pl.col("_gap").min() / 1000.0).alias("w_gap_min_s"),
        pl.col("reversed").cast(pl.Float64).mean().alias("w_share_reversed"),
        ((vport >= 0) & (vport < LOW_PORT_BELOW)).cast(pl.Float64).mean().alias("w_share_low_port"),
    ]
    out = df.group_by("window_id", maintain_order=True).agg(aggs)
    return out.select("window_id", *[pl.col(n).cast(pl.Float64) for n in summary_feature_names()])


def summary_matrix(windows: pl.DataFrame, features: pl.DataFrame) -> np.ndarray:
    """Сводные признаки в порядке строк `windows` → float32 [n_windows, n_features]."""
    names = summary_feature_names()
    aligned = windows.select("window_id").join(features, on="window_id", how="left")
    return aligned.select(names).to_numpy().astype(np.float32)


# ================================================================ последовательности (нейросеть)

REL_FEATURES = ("t_from_start_s", "log_gap_s", "new_target", "new_dst_port")
SCALAR_FEATURES = ("w_log_n_flows", "truncated", "w_log_n_targets", "w_log_n_dst_ports")


def seq_feature_names() -> list[str]:
    """62 канала шага последовательности: 58 признаков схемы + 4 относительных поля (R4)."""
    return [*SCHEMA.feature_columns(), *REL_FEATURES]


@dataclass
class SeqScaler:
    """Предобработка последовательностей (сохраняется в артефакт — конституция II).

    Признаки потока: log1p (все неотрицательны: счётчики, байты, интервалы) и стандартизация
    по потокам train. Время от начала окна равномерно на [0, L): оно стандартизуется
    аналитически (среднее L/2, СКО L/√12), без подгонки. Остальные относительные поля уже
    в малом диапазоне (log1p интервала в секундах, флаги 0/1).
    """

    features: list[str]
    mean: np.ndarray
    std: np.ndarray
    length_ms: int

    def transform(self, X: np.ndarray) -> np.ndarray:
        return ((np.log1p(np.clip(X, 0, None)) - self.mean) / self.std).astype(np.float32)


def fit_seq_scaler(train_flows: pl.DataFrame, length_ms: int) -> SeqScaler:
    feats = SCHEMA.feature_columns()
    X = train_flows.select(pl.col(feats).cast(pl.Float64).fill_null(0.0)).to_numpy()
    Z = np.log1p(np.clip(X, 0, None))
    mean = Z.mean(axis=0)
    std = Z.std(axis=0)
    std[std == 0] = 1.0  # постоянный признак: делить на ноль нельзя, смысла в нём и так нет
    return SeqScaler(features=feats, mean=mean, std=std, length_ms=int(length_ms))


# Сколько окон собирать в последовательности за раз: train с аугментацией — ≈58 тыс. окон и
# ≈7 млн строк «поток окна»; частями пиковая память — сам тензор плюс одна часть (R18)
SEQ_CHUNK = 4000


def sequences(
    flows: pl.DataFrame,
    side: pl.DataFrame,
    assignment: pl.DataFrame,
    windows: pl.DataFrame,
    *,
    seq_max: int,
    scaler: SeqScaler,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """(X [n, seq_max, 62] float32, mask [n, seq_max] bool, scalars [n, 4] float32) в порядке
    строк `windows`.

    Шаг — первые по времени `seq_max` потоков окна (порядок: first_seen_ms, flow_uid). Поля
    «новая цель» и «новый порт» считаются по порядку внутри окна; скаляры — по ВСЕМУ окну,
    чтобы нейросеть знала размер окна и после усечения.
    """
    feats = scaler.features
    n = windows.height
    width = len(feats) + len(REL_FEATURES)
    X = np.zeros((n, seq_max, width), dtype=np.float32)
    mask = np.zeros((n, seq_max), dtype=bool)
    scalars = np.zeros((n, len(SCALAR_FEATURES)), dtype=np.float32)
    if n == 0:
        return X, mask, scalars
    L_s = scaler.length_ms / 1000.0
    t_mean, t_std = L_s / 2.0, L_s / math.sqrt(12.0)
    ids = windows["window_id"]
    for lo in range(0, n, SEQ_CHUNK):
        chunk = pl.DataFrame(
            {"window_id": ids[lo : lo + SEQ_CHUNK], "_row": np.arange(lo, min(lo + SEQ_CHUNK, n))}
        )
        asg = assignment.join(chunk, on="window_id", how="inner")
        df = (
            asg.join(flows.select("flow_uid", FIRST, "src_port", "dst_port", *feats), on="flow_uid")
            .join(side.select("flow_uid", "reversed", "victim_ip"), on="flow_uid", how="left")
            .sort(["_row", FIRST, "flow_uid"])
            .with_columns(_victim_port().alias("_vport"))
        )
        per_window = df.group_by("_row").agg(
            pl.len().alias("_n"),
            pl.col("victim_ip").n_unique().alias("_nt"),
            pl.col("_vport").drop_nulls().n_unique().alias("_np"),
        )
        rows_w = per_window["_row"].to_numpy()
        nf = per_window["_n"].to_numpy().astype(np.float64)
        scalars[rows_w, 0] = np.log1p(nf)
        scalars[rows_w, 1] = (nf > seq_max).astype(np.float32)
        scalars[rows_w, 2] = np.log1p(per_window["_nt"].to_numpy().astype(np.float64))
        scalars[rows_w, 3] = np.log1p(per_window["_np"].to_numpy().astype(np.float64))

        df = df.with_columns(
            pl.int_range(pl.len()).over("_row").alias("_rank"),
            pl.col("victim_ip").is_first_distinct().over("_row").alias("_new_t"),
            pl.col("_vport").is_first_distinct().over("_row").alias("_new_p"),
            pl.col(FIRST).diff().over("_row").fill_null(0).alias("_gap"),
        ).filter(pl.col("_rank") < seq_max)
        r = df["_row"].to_numpy()
        k = df["_rank"].to_numpy()
        body = scaler.transform(df.select(pl.col(feats).cast(pl.Float64).fill_null(0.0)).to_numpy())
        t = (df[FIRST].to_numpy() - df["window_start_ms"].to_numpy()) / 1000.0
        rel = np.column_stack(
            [
                (t - t_mean) / t_std,
                np.log1p(np.clip(df["_gap"].to_numpy() / 1000.0, 0, None)),
                df["_new_t"].to_numpy().astype(np.float64),
                df["_new_p"].to_numpy().astype(np.float64),
            ]
        ).astype(np.float32)
        X[r, k, : len(feats)] = body
        X[r, k, len(feats) :] = rel
        mask[r, k] = True
    return X, mask, scalars


# ================================================================ части разбиения для обучения


@dataclass
class PartWindows:
    """Окна одной части разбиения: потоки, стороны, соответствие поток → окно (все сдвиги),
    окна с метками. Потоки чужих частей сюда не попадают физически (SC-004)."""

    part: str
    flows: pl.DataFrame
    side: pl.DataFrame
    assignment: pl.DataFrame
    windows: pl.DataFrame


def windows_of_flows(
    flows: pl.DataFrame,
    side: pl.DataFrame,
    *,
    length_ms: int,
    seq_max: int,
    shifts: tuple[int, ...] | list[int] = (0,),
    part: str | None = None,
) -> tuple[pl.DataFrame, pl.DataFrame]:
    """(соответствие поток → окно по всем сдвигам, окна по всем сдвигам)."""
    assignments, windows = [], []
    for s in shifts:
        a = assign_windows(flows, side, length_ms=length_ms, shift_ms=s)
        windows.append(
            build_windows(
                flows,
                side,
                length_ms=length_ms,
                seq_max=seq_max,
                shift_ms=s,
                part=part,
                assignment=a,
            )
        )
        assignments.append(a)
    return pl.concat(assignments), pl.concat(windows)


def build_part_windows(
    split: str,
    part: str,
    cfg: WindowsConfig,
    *,
    data_dir: Path,
    direction: str,
    shifts: tuple[int, ...] | list[int] = (0,),
) -> PartWindows:
    """Часть разбиения → окна с метками (R1, R2, R9).

    Читаются только нужные колонки (`scan_part`): признаки, контекст, поля правила
    направления и метка. Стороны — той же функцией `sides`, что в цепочке, в режиме
    `grouping.direction` конфига SOC.
    """
    from mlsiem.detect.dataset import scan_part
    from mlsiem.soc.direction import sides

    flows = scan_part(split, part, data_dir=data_dir, columns=[*flow_columns(), "label"]).collect()
    if flows.height == 0:
        raise ValueError(f"в части {part} разбиения {split} нет потоков")
    side = sides(flows, direction).select(SIDE_COLUMNS)
    assignment, windows = windows_of_flows(
        flows, side, length_ms=cfg.length_ms, seq_max=cfg.seq_max, shifts=shifts, part=part
    )
    labels = window_labels(assignment, flows.select("flow_uid", "label"))
    windows = windows.join(labels, on="window_id", how="left")
    return PartWindows(part=part, flows=flows, side=side, assignment=assignment, windows=windows)


def train_holdout_split(
    windows: pl.DataFrame, share: float, length_ms: int
) -> tuple[np.ndarray, np.ndarray]:
    """(маска «обучение», маска «хвост») по строкам окон train (R5).

    Хвост — последние `share` окон основной сетки по времени начала. Обучение — окна любой
    сетки, закончившиеся не позже чем за одно окно до начала хвоста: сдвинутые окна у
    границы иначе перекрывали бы хвост теми же потоками. Окна в зазоре не используются.
    """
    start = windows["window_start_ms"].to_numpy()
    end = windows["window_end_ms"].to_numpy()
    main = windows["shift_ms"].to_numpy() == 0
    main_starts = np.sort(start[main])
    if main_starts.size < 2:
        return np.ones(windows.height, dtype=bool), np.zeros(windows.height, dtype=bool)
    k = min(main_starts.size - 1, max(1, int(round(main_starts.size * (1 - share)))))
    cut = int(main_starts[k])
    holdout = main & (start >= cut)
    fit = end <= cut - int(length_ms)
    return fit, holdout
