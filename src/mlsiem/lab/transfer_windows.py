"""Эксперимент переноса, второй этап: те же рукава на уровне окон потоков (фича 008, после US5).

Окно — как в 007: «атакующий адрес × 60 с», метка окна — класс атаки, если в окне есть хоть один
атакующий поток,
иначе норма. Модель окон — LightGBM на сводных признаках (победитель 007), обучение с ранней
остановкой по
отложенному хвосту train и сдвинутыми окнами 15/30/45 с (аугментация), как в 007. Рукава те же, что
на этапе 1:
`WA` (готовый `models/windows`), `WC0` (UNSW, тот же рецепт), `WB(k)` (стенд), `WC(k)` (UNSW +
стенд).

Окон стенда мало (≈ 270 на val, из них нормальных 183), поэтому пороги — по норме val при долях
ложных окон 5% и 10%
(1% — справочно: это 2 окна), а доверительные интервалы широки. Протокол — дополнение к
`reports/lab_transfer_protocol_20261024.md`, записанное до запуска этапа.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import polars as pl
from scipy.special import softmax

from mlsiem.detect import openset
from mlsiem.detect import windows as W
from mlsiem.detect.metrics import binary_pr_auc
from mlsiem.lab import transfer as T
from mlsiem.lab.dataset import AMBIGUOUS, BENIGN

SHARED = T.SHARED
DEFAULT_FPR = (0.01, 0.05, 0.10)
SHIFTS = (0, 15000, 30000, 45000)
DEFAULT_PARAMS = {
    "n_estimators": 400,
    "learning_rate": 0.05,
    "num_leaves": 63,
    "class_weight": "balanced",
    "early_stopping_rounds": 30,
}
LENGTH_MS = 60000
SEQ_MAX = 128
HOLDOUT_SHARE = 0.10


@dataclass
class WindowSet:
    """Окна одной части: сводные признаки, метки, времена и признак «есть поток резерва»."""

    X: np.ndarray
    y: np.ndarray
    windows: pl.DataFrame  # window_id, window_start_ms, window_end_ms, shift_ms, label
    has_reserve: np.ndarray


@dataclass
class WData:
    unsw: dict[str, WindowSet]  # train / val / test
    stand: pl.DataFrame  # потоки стенда (колонки окон + label, part, repeat, reserve_unknown)
    artifact: tuple | None = None  # (конвейер окон, порог)
    stand_cache: dict | None = None


def _build_set(
    flows: pl.DataFrame, part: str, shifts, *, has_reserve_col: bool = False
) -> WindowSet:
    from mlsiem.detect.windows_experiment import _summary
    from mlsiem.soc.direction import sides

    side = sides(flows, "auto").select(W.SIDE_COLUMNS)
    assignment, windows = W.windows_of_flows(
        flows, side, length_ms=LENGTH_MS, seq_max=SEQ_MAX, shifts=shifts, part=part
    )
    labels = W.window_labels(assignment, flows.select("flow_uid", "label"))
    windows = windows.join(labels, on="window_id", how="left")
    pw = W.PartWindows(part=part, flows=flows, side=side, assignment=assignment, windows=windows)
    X = _summary(pw, windows)
    if has_reserve_col:
        rid = (
            assignment.join(flows.select("flow_uid", "reserve_unknown"), on="flow_uid", how="left")
            .filter(pl.col("reserve_unknown"))
            .select("window_id")
            .unique()["window_id"]
            .to_list()
        )
        reserve = windows["window_id"].is_in(rid).to_numpy()
    else:
        reserve = np.zeros(windows.height, dtype=bool)
    keep = windows["label"].is_not_null().to_numpy() & (windows["label"] != AMBIGUOUS).to_numpy()
    return WindowSet(
        X=X[keep],
        y=windows["label"].to_numpy()[keep],
        windows=windows.filter(pl.Series(keep)),
        has_reserve=reserve[keep],
    )


def stand_windows(data: WData, part: str, k: int | None = None, shifts=(0,)) -> WindowSet:
    """Окна стенда для части (для train — с повторами ≤ k); результат кэшируется."""
    key = (part, k, tuple(shifts))
    data.stand_cache = data.stand_cache if data.stand_cache is not None else {}
    if key not in data.stand_cache:
        df = data.stand.filter(pl.col("part") == part)
        if k is not None:
            df = df.filter(pl.col("repeat") <= k)
        data.stand_cache[key] = _build_set(df, part, shifts, has_reserve_col=True)
    return data.stand_cache[key]


def load_real_wdata(dataset_dir: Path, artifact_dir: Path = Path("models/windows")) -> WData:
    import joblib

    cols = [*W.flow_columns(), "label", "part", "repeat", "reserve_unknown"]
    st = pl.read_parquet(Path(dataset_dir) / "flows.parquet", columns=list(dict.fromkeys(cols)))
    st = st.filter((pl.col("label") != AMBIGUOUS) & (pl.col("part") != "gap"))
    cfg = W.load_windows_config()
    unsw = {}
    for part, shifts in (("train", SHIFTS), ("val", (0,)), ("test", (0,))):
        pw = W.build_part_windows(
            "unsw_time", part, cfg, data_dir=Path("data"), direction="auto", shifts=shifts
        )
        from mlsiem.detect.windows_experiment import _summary

        X = _summary(pw, pw.windows)
        keep = pw.windows["label"].is_not_null().to_numpy()
        unsw[part] = WindowSet(
            X=X[keep],
            y=pw.windows["label"].to_numpy()[keep],
            windows=pw.windows.filter(pl.Series(keep)),
            has_reserve=np.zeros(int(keep.sum()), dtype=bool),
        )
    card = json.loads((Path(artifact_dir) / "window_card.json").read_text(encoding="utf-8"))
    art = (joblib.load(Path(artifact_dir) / "model.joblib"), float(card["threshold"]))
    return WData(unsw=unsw, stand=st, artifact=art)


# ---------------------------------------------------------------------------------- обучение


def build_train(data: WData, arm: str, k: int):
    """X, y и маски «обучение / хвост для ранней остановки» (как R5 в 007), по источникам "
    "отдельно."""
    Xs, ys, fits, holds = [], [], [], []
    sources = []
    if arm in ("C0", "C"):
        sources.append(data.unsw["train"])
    if arm in ("B", "C") and k > 0:
        s = stand_windows(data, "train", k, SHIFTS)
        keep = ~s.has_reserve
        sources.append(
            WindowSet(s.X[keep], s.y[keep], s.windows.filter(pl.Series(keep)), s.has_reserve[keep])
        )
    for s in sources:
        fit, hold = W.train_holdout_split(s.windows, HOLDOUT_SHARE, LENGTH_MS)
        Xs.append(s.X), ys.append(s.y), fits.append(fit), holds.append(hold)
    return np.vstack(Xs), np.concatenate(ys), np.concatenate(fits), np.concatenate(holds)


def fit_arm(X, y, fit, hold, params, seed):
    from mlsiem.detect.windows_experiment import fit_lgbm

    return fit_lgbm(X[fit], y[fit], X[hold], y[hold], params, seed)


# ------------------------------------------------------------------------------------ оценка


def evaluate_set(
    model, classes, val: WindowSet, test: WindowSet, *, fprs, min_class, artifact_threshold=None
) -> dict:
    """Метрики окон стенда; пороги — по нормальным окнам val стенда."""
    vb = val.y == BENIGN
    sv = openset.attack_vs_normal(openset.raw_logits(model, val.X[vb]), classes)
    thr = {f: float(np.quantile(sv, 1 - f)) for f in fprs}
    z = openset.raw_logits(model, test.X)
    s, P = openset.attack_vs_normal(z, classes), softmax(z, axis=1)
    y, reserve = test.y, test.has_reserve
    attack, known = y != BENIGN, ~test.has_reserve
    per = T._per_class_pr_auc(y, P, classes, known, min_class)
    res = {
        "n_windows_test": int(len(y)),
        "n_windows_val_benign": int(vb.sum()),
        "pr_auc_binary": float(binary_pr_auc(attack[known], s[known])),
        "pr_auc_per_class": per,
        "macro_shared4": T._macro(per, SHARED),
        "macro_attack_classes": float(np.mean(list(per.values()))) if per else None,
        "thresholds": {str(f): t for f, t in thr.items()},
        "recall": {},
    }
    for f, t in thr.items():
        alert = s > t
        res["recall"][str(f)] = {
            "all": T._rate(alert, known & attack),
            "benign_fpr": T._rate(alert, ~attack),
            "by_class": T._grouped(alert, known & attack, y),
            "reserve": T._rate(alert, reserve & attack),
        }
    if artifact_threshold is not None and BENIGN in classes:
        alert = (1.0 - P[:, classes.index(BENIGN)]) >= artifact_threshold
        res["at_artifact_threshold"] = {
            "all": T._rate(alert, known & attack),
            "benign_fpr": T._rate(alert, ~attack),
        }
    return res


def evaluate_unsw(model, classes, test: WindowSet, min_class: int = 5) -> dict:
    z = openset.raw_logits(model, test.X)
    P = softmax(z, axis=1)
    attack = test.y != BENIGN
    per = T._per_class_pr_auc(test.y, P, classes, np.ones(len(test.y), dtype=bool), min_class)
    return {
        "n_windows_test": int(len(test.y)),
        "pr_auc_binary": float(binary_pr_auc(attack, openset.attack_vs_normal(z, classes))),
        "pr_auc_per_class": per,
        "macro_shared4": T._macro(per, SHARED),
    }


# -------------------------------------------------------------------------------------- прогон


def run_windows(
    data: WData,
    out_dir: Path,
    *,
    seeds=(0, 1, 2),
    curve=(2, 4),
    params: dict | None = None,
    fprs=DEFAULT_FPR,
    min_class: int = 5,
    on_result: Callable[[dict], None] | None = None,
    log: Callable[[str], None] = print,
) -> list[dict]:
    params = params or DEFAULT_PARAMS
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "results_windows.jsonl"
    done = {T.run_key(r["arm"], r["k"], r["seed"]) for r in T.read_results(path)}
    steps = T.plan(seeds, curve)
    val = stand_windows(data, "val")
    test = stand_windows(data, "test")
    log(
        f"окна стенда: val {len(val.y)} (норма {int((val.y == BENIGN).sum())}), "
        f"test {len(test.y)} (с резервом {int(test.has_reserve.sum())}); "
        f"окна UNSW: train {len(data.unsw['train'].y)}, test {len(data.unsw['test'].y)}"
    )
    for i, (arm, k, seed) in enumerate(steps, 1):
        key = T.run_key(arm, k, seed)
        if key in done:
            log(f"[{i}/{len(steps)}] окна {key}: уже сделано, пропуск")
            continue
        t0 = time.time()
        log(f"[{i}/{len(steps)}] окна {key}: старт")
        if arm == "A":
            if data.artifact is None:
                continue
            model, art_thr = data.artifact
            sizes = {"artifact": "models/windows"}
        else:
            X, y, fit, hold = build_train(data, arm, k)
            sizes = {str(c): int((y == c).sum()) for c in np.unique(y)}
            log(
                f"[{i}/{len(steps)}] окна {key}: обучение {int(fit.sum())} + хвост "
                f"{int(hold.sum())}, {sizes}"
            )
            model = fit_arm(X, y, fit, hold, params, seed)
            art_thr = None
        classes = list(model.classes_)
        stand = evaluate_set(
            model, classes, val, test, fprs=fprs, min_class=min_class, artifact_threshold=art_thr
        )
        unsw = evaluate_unsw(model, classes, data.unsw["test"])
        rec = {
            "arm": arm,
            "k": k,
            "seed": seed,
            "level": "windows",
            "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "total_seconds": round(time.time() - t0, 1),
            "train_sizes": sizes,
            "classes": classes,
            "stand": stand,
            "unsw": unsw,
        }
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        r5 = stand["recall"]["0.05"]["all"]
        log(
            f"[{i}/{len(steps)}] окна {key}: готово за {rec['total_seconds']} с; стенд: PR-AUC "
            "атака/норма "
            f"{stand['pr_auc_binary']:.4f}, macro(4) {stand['macro_shared4']}, полнота окон@5% "
            f"{r5['k'] / max(r5['n'], 1):.3f} ({r5['k']}/{r5['n']}); UNSW PR-AUC "
            f"{unsw['pr_auc_binary']:.4f}"
        )
        if on_result:
            on_result(rec)
    return T.read_results(path)


def report_md(results: list[dict], version: str) -> str:
    def name(r):
        return f"{r['arm']}({r['k']})" if r["arm"] in ("B", "C") else r["arm"]

    order = ["A", "C0", "B(2)", "B(4)", "B(6)", "C(2)", "C(4)", "C(6)"]
    groups: dict[str, list] = {}
    for r in results:
        groups.setdefault(name(r), []).append(r)
    names = [n for n in order if n in groups]
    lines = [
        f"# Перенос на трафик стенда, уровень окон ({version})",
        "",
        "Модель окон — LightGBM на сводных признаках. Пороги — по нормальным окнам val стенда. "
        "Окон мало, "
        "интервалы Уилсона широки: различия в пределах интервала — не различия.",
        "",
        "| метрика | " + " | ".join(f"{n} (сидов {len(groups[n])})" for n in names) + " |",
        "|---|" + "---|" * len(names),
    ]

    def cell(vals, fmt="{:.3f}"):
        vals = [v for v in vals if v is not None]
        if not vals:
            return "—"
        return fmt.format(float(np.mean(vals))) + (
            f" ± {np.std(vals):.3f}" if len(vals) > 1 else ""
        )

    rows = {
        "стенд PR-AUC атака/норма": lambda r: r["stand"]["pr_auc_binary"],
        "стенд macro PR-AUC (4 общих)": lambda r: r["stand"]["macro_shared4"],
        "UNSW PR-AUC атака/норма": lambda r: r["unsw"]["pr_auc_binary"],
    }
    for f in ("0.01", "0.05", "0.1"):
        rows[f"стенд полнота окон при {float(f):.0%} ложных"] = lambda r, f=f: T._rate_value(
            r["stand"]["recall"][f]["all"]
        )
    for label, fn in rows.items():
        lines.append(
            f"| {label} | " + " | ".join(cell([fn(r) for r in groups[n]]) for n in names) + " |"
        )
    first = {n: groups[n][0] for n in names}
    lines += ["", "## Полнота окон по классам при 5% ложных (первый сид; k/n)", ""]
    classes = sorted({c for r in first.values() for c in r["stand"]["recall"]["0.05"]["by_class"]})
    lines += ["| класс | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for c in classes:
        cells = []
        for n in names:
            x = first[n]["stand"]["recall"]["0.05"]["by_class"].get(c)
            cells.append("—" if x is None else f"{T._rate_value(x):.3f} ({x['k']}/{x['n']})")
        lines.append(f"| {c} | " + " | ".join(cells) + " |")
    lines += ["", "## Окна с резервом «неизвестное» при 5% ложных", ""]
    lines += ["| рукав | полнота (k/n) |", "|---|---|"]
    for n in names:
        x = first[n]["stand"]["recall"]["0.05"]["reserve"]
        lines.append(f"| {n} | {T._rate_value(x):.3f} ({x['k']}/{x['n']}) |")
    return "\n".join(lines) + "\n"


def write_report(results, reports_dir: Path, version: str) -> Path:
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    md = reports_dir / f"lab_transfer_windows_{version}.md"
    md.write_text(report_md(results, version), encoding="utf-8")
    (reports_dir / f"lab_transfer_windows_{version}.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    return md
