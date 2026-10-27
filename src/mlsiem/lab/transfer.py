"""Эксперимент переноса: даёт ли обучение на данных стенда прирост на трафике стенда (фича 008,
после US5).

Протокол — `reports/lab_transfer_protocol_20261024.md` (записан до результатов). Здесь сравниваются
рукава:

- **A** — готовый `models/detector` (UNSW), без переобучения;
- **C0** — UNSW, тот же рецепт, что у C (контроль: отделяет эффект рецепта и урезания данных от
  эффекта стенда);
- **B(k)** — только обучающая часть стенда, повторы ≤ k;
- **C(k)** — UNSW + обучающая часть стенда, повторы ≤ k.

Порог каждого рукава при доле ложных срабатываний f — квантиль 1−f скоров нормы **val стенда**
(строгое `>`),
скор атаки — логит «не норма» (вероятность насыщается). Одинаково для всех рукавов, поэтому
сравнение полноты при
фиксированной доле ложных честное. Тест стенда (повторы 9–10) используется только для итоговой
оценки.

Каждый прогон дописывается в `results.jsonl` сразу после окончания, готовые пропускаются при
повторном запуске:
сбой или остановка посреди эксперимента не теряют сделанного. Хронология — в `log.md` каталога
результатов.
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
from sklearn.metrics import average_precision_score

from mlsiem.detect import openset
from mlsiem.detect.candidates import build_candidate
from mlsiem.detect.dataset import feature_columns
from mlsiem.detect.metrics import binary_pr_auc
from mlsiem.lab.dataset import AMBIGUOUS, BENIGN
from mlsiem.lab.shortcuts import wilson

SHARED = (
    "dos",
    "exploits",
    "fuzzers",
    "reconnaissance",
)  # классы, которые есть и у UNSW, и у стенда
DEFAULT_FPR = (0.001, 0.01, 0.05)
CAP_BENIGN_UNSW = 300_000
CAP_CLASS = 50_000
DEFAULT_PARAMS = {
    "n_estimators": 400,
    "learning_rate": 0.05,
    "num_leaves": 63,
    "class_weight": "balanced",
}


@dataclass
class Data:
    """Всё, что нужно эксперименту; тесты подставляют маленькие синтетические данные."""

    # потоки набора стенда: признаки + label, part, repeat, tool, source, variant, reserve_unknown
    stand: pl.DataFrame
    unsw_train: tuple[np.ndarray, np.ndarray]
    unsw_test: tuple[np.ndarray, np.ndarray]
    artifact: tuple | None = None  # (конвейер, порог артефакта) — рукав A


def load_real_data(dataset_dir: Path, artifact_dir: Path = Path("models/detector")) -> Data:
    import joblib

    from mlsiem.detect.dataset import load_part

    feats = feature_columns()
    meta = ["label", "part", "repeat", "tool", "source", "variant", "reserve_unknown"]
    stand = pl.read_parquet(Path(dataset_dir) / "flows.parquet", columns=[*feats, *meta])
    stand = stand.filter((pl.col("label") != AMBIGUOUS) & (pl.col("part") != "gap"))
    tr, te = load_part("unsw_time", "train"), load_part("unsw_time", "test")
    card = json.loads((Path(artifact_dir) / "model_card.json").read_text(encoding="utf-8"))
    return Data(
        stand=stand,
        unsw_train=(tr.X.to_numpy(), np.asarray(tr.y)),
        unsw_test=(te.X.to_numpy(), np.asarray(te.y)),
        artifact=(joblib.load(Path(artifact_dir) / "model.joblib"), float(card["threshold"])),
    )


# ----------------------------------------------------------------------------------------- данные


def _cap(X: np.ndarray, y: np.ndarray, seed: int, cap_benign: int, cap_class: int):
    """Не более `cap_benign` потоков нормы и `cap_class` потоков каждого другого класса "
    "(детерминированно)."""
    rng = np.random.default_rng(seed)
    keep = []
    for label in np.unique(y):
        idx = np.flatnonzero(y == label)
        cap = cap_benign if label == BENIGN else cap_class
        if len(idx) > cap:
            idx = rng.choice(idx, size=cap, replace=False)
        keep.append(idx)
    keep = np.sort(np.concatenate(keep))
    return X[keep], y[keep]


def _stand_xy(df: pl.DataFrame, feats: list[str]):
    X = df.select(feats).cast(pl.Float32).fill_null(0).to_numpy()
    return X, df["label"].to_numpy()


def build_train(data: Data, arm: str, k: int, seed: int, cap_benign: int, cap_class: int):
    """Обучающая выборка рукава. Резерв «неизвестное» в обучение не попадает никогда."""
    feats = feature_columns()
    parts_X, parts_y = [], []
    if arm in ("C0", "C"):
        X, y = _cap(*data.unsw_train, seed, cap_benign, cap_class)
        parts_X.append(X), parts_y.append(y)
    if arm in ("B", "C") and k > 0:
        s = data.stand.filter(
            (pl.col("part") == "train") & (pl.col("repeat") <= k) & ~pl.col("reserve_unknown")
        )
        X, y = _cap(*_stand_xy(s, feats), seed, cap_class, cap_class)
        parts_X.append(X), parts_y.append(y)
    X, y = np.vstack(parts_X), np.concatenate(parts_y)
    return X, y


# --------------------------------------------------------------------------------------- метрики


def _rate(alert: np.ndarray, group: np.ndarray) -> dict:
    n = int(group.sum())
    return {"k": int((alert & group).sum()), "n": n}


def _grouped(alert: np.ndarray, base: np.ndarray, values: np.ndarray, min_n: int = 1) -> dict:
    out = {}
    for v in np.unique(values[base & (values != None)]):  # noqa: E711 — значения могут быть None
        m = base & (values == v)
        if m.sum() >= min_n:
            out[str(v)] = _rate(alert, m)
    return out


def _per_class_pr_auc(y, P, classes, mask, min_n) -> dict:
    out = {}
    for c in classes:
        if c == BENIGN:
            continue
        pos = (y == c) & mask
        if pos.sum() >= min_n:
            out[c] = float(average_precision_score(pos[mask], P[mask, classes.index(c)]))
    return out


def _macro(per: dict, names) -> float | None:
    vals = [per[c] for c in names if c in per]
    return float(np.mean(vals)) if vals and all(c in per for c in names) else None


def evaluate_stand(
    model,
    classes: list[str],
    stand: pl.DataFrame,
    feats: list[str],
    *,
    fprs,
    min_test: int,
    artifact_threshold=None,
) -> dict:
    """Оценка на тесте стенда; пороги — по норме val стенда."""
    val = stand.filter((pl.col("part") == "val") & (pl.col("label") == BENIGN))
    test = stand.filter(pl.col("part") == "test")
    zv = openset.raw_logits(model, val.select(feats).cast(pl.Float32).fill_null(0).to_numpy())
    sv = openset.attack_vs_normal(zv, classes)
    thr = {f: float(np.quantile(sv, 1 - f)) for f in fprs}
    zt = openset.raw_logits(model, test.select(feats).cast(pl.Float32).fill_null(0).to_numpy())
    st, P = openset.attack_vs_normal(zt, classes), softmax(zt, axis=1)
    y = test["label"].to_numpy()
    reserve = test["reserve_unknown"].to_numpy()
    tool, source, variant = (test[c].to_numpy() for c in ("tool", "source", "variant"))
    attack = y != BENIGN
    known = ~reserve
    per = _per_class_pr_auc(y, P, classes, known, min_test)
    res = {
        "n_test": int(test.height),
        "n_val_benign": int(val.height),
        "pr_auc_binary": float(binary_pr_auc(attack[known], st[known])),
        "pr_auc_binary_with_reserve": float(binary_pr_auc(attack, st)),
        "pr_auc_per_class": per,
        "macro_shared4": _macro(per, SHARED),
        "macro_attack_classes": float(np.mean(list(per.values()))) if per else None,
        "thresholds": {str(f): t for f, t in thr.items()},
        "recall": {},
    }
    for f, t in thr.items():
        alert = st > t
        res["recall"][str(f)] = {
            "all": _rate(alert, known & attack),
            "benign_fpr": _rate(alert, ~attack),
            "by_class": _grouped(alert, known & attack, y),
            "by_tool": _grouped(alert, known & attack, tool),
            "by_source": _grouped(alert, known & attack, source),
            "reserve_by_variant": _grouped(alert, reserve & attack, variant),
        }
    if artifact_threshold is not None and BENIGN in classes:
        alert = (1.0 - P[:, classes.index(BENIGN)]) >= artifact_threshold
        res["at_artifact_threshold"] = {
            "all": _rate(alert, known & attack),
            "benign_fpr": _rate(alert, ~attack),
            "by_class": _grouped(alert, known & attack, y),
        }
    return res


def evaluate_unsw(
    model, classes: list[str], X: np.ndarray, y: np.ndarray, *, min_test: int = 20
) -> dict:
    """Оценка на собственном тесте UNSW: не забыла ли модель исходный домен."""
    z = openset.raw_logits(model, X)
    P = softmax(z, axis=1)
    attack = y != BENIGN
    per = _per_class_pr_auc(y, P, classes, np.ones(len(y), dtype=bool), min_test)
    return {
        "n_test": int(len(y)),
        "pr_auc_binary": float(binary_pr_auc(attack, openset.attack_vs_normal(z, classes))),
        "pr_auc_per_class": per,
        "macro_shared4": _macro(per, SHARED),
        "macro_attack_classes": float(np.mean(list(per.values()))) if per else None,
    }


# ------------------------------------------------------------------------------------- прогон


def plan(seeds=(0, 1, 2), curve=(2, 4)) -> list[tuple[str, int, int | None]]:
    """Порядок прогонов: сначала основные рукава на первом сиде (первые результаты быстро), затем
    остальные сиды,
    затем кривая обучения (сид 0)."""
    s0, rest = seeds[0], seeds[1:]
    out = [("A", 0, None), ("C0", 0, s0), ("C", 6, s0), ("B", 6, s0)]
    for s in rest:
        out += [("C0", 0, s), ("C", 6, s), ("B", 6, s)]
    for k in curve:
        out += [("C", k, s0), ("B", k, s0)]
    return out


def run_key(arm: str, k: int, seed) -> str:
    return f"{arm}|{k}|{seed}"


def read_results(path: Path) -> list[dict]:
    if not Path(path).exists():
        return []
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _versions() -> dict:
    import lightgbm
    import sklearn

    return {
        "lightgbm": lightgbm.__version__,
        "scikit-learn": sklearn.__version__,
        "numpy": np.__version__,
        "polars": pl.__version__,
    }


def run_transfer(
    data: Data,
    out_dir: Path,
    *,
    seeds=(0, 1, 2),
    curve=(2, 4),
    params: dict | None = None,
    fprs=DEFAULT_FPR,
    min_test: int = 100,
    cap_benign: int = CAP_BENIGN_UNSW,
    cap_class: int = CAP_CLASS,
    on_result: Callable[[dict], None] | None = None,
    log: Callable[[str], None] = print,
) -> list[dict]:
    """Выполняет план, возобновляя по `results.jsonl`; возвращает все результаты (старые и "
    "новые)."""
    params = params or DEFAULT_PARAMS
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.jsonl"
    feats = feature_columns()
    done = {run_key(r["arm"], r["k"], r["seed"]) for r in read_results(results_path)}
    steps = plan(seeds, curve)
    log(f"план: {len(steps)} прогонов, готово {len(done)}; версии {_versions()}")
    for i, (arm, k, seed) in enumerate(steps, 1):
        key = run_key(arm, k, seed)
        if key in done:
            log(f"[{i}/{len(steps)}] {key}: уже сделано, пропуск")
            continue
        t0 = time.time()
        log(f"[{i}/{len(steps)}] {key}: старт")
        if arm == "A":
            if data.artifact is None:
                log(f"[{i}/{len(steps)}] {key}: нет артефакта, пропуск")
                continue
            model, art_thr = data.artifact
            sizes = {"artifact": "models/detector"}
        else:
            X, y = build_train(data, arm, k, seed, cap_benign, cap_class)
            sizes = {str(c): int((y == c).sum()) for c in np.unique(y)}
            log(
                f"[{i}/{len(steps)}] {key}: обучающая выборка {sum(sizes.values())} потоков, "
                f"{sizes}"
            )
            model = build_candidate("lgbm", params, seed)
            model.fit(X, y)
            art_thr = None
        fit_s = time.time() - t0
        classes = list(model.classes_)
        stand = evaluate_stand(
            model,
            classes,
            data.stand,
            feats,
            fprs=fprs,
            min_test=min_test,
            artifact_threshold=art_thr,
        )
        unsw = evaluate_unsw(model, classes, *data.unsw_test)
        rec = {
            "arm": arm,
            "k": k,
            "seed": seed,
            "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "fit_seconds": round(fit_s, 1),
            "total_seconds": round(time.time() - t0, 1),
            "train_sizes": sizes,
            "classes": classes,
            "params": params if arm != "A" else None,
            "stand": stand,
            "unsw": unsw,
        }
        with results_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        r1 = stand["recall"]["0.01"]["all"]
        log(
            f"[{i}/{len(steps)}] {key}: готово за {rec['total_seconds']} с; стенд: PR-AUC "
            "атака/норма "
            f"{stand['pr_auc_binary']:.4f}, macro(4 общих) {stand['macro_shared4']}, полнота@1% "
            f"{r1['k'] / max(r1['n'], 1):.3f}; UNSW: PR-AUC атака/норма {unsw['pr_auc_binary']:.4f}"
        )
        if on_result:
            on_result(rec)
    return read_results(results_path)


# ------------------------------------------------------------------------------------ сводка


def _rate_value(r: dict) -> float:
    return r["k"] / r["n"] if r["n"] else float("nan")


def class_recall_macro(rec: dict, f: str = "0.01") -> float | None:
    """Средняя по 4 общим классам полнота при доле ложных `f` (ПОСТ-ФАКТУМ, в протоколе её не было).

    Общая полнота почти целиком определяется классами dos (≈ 73% атакующих потоков теста стенда:
    одиночные пакеты флуда) и reconnaissance (≈ 26%), поэтому у моделей без данных стенда
    прыгает от сида к сиду (0,001–0,725); среднее по классам эту зависимость снимает.
    Классы без потоков в тесте
    в среднее не входят."""
    by = rec["stand"]["recall"][f]["by_class"]
    vals = [_rate_value(by[c]) for c in SHARED if c in by and by[c]["n"] > 0]
    return float(np.mean(vals)) if len(vals) == len(SHARED) else None


def _metric_rows(rec: dict) -> dict:
    s, u = rec["stand"], rec["unsw"]
    out = {
        "стенд PR-AUC атака/норма": s["pr_auc_binary"],
        "стенд macro PR-AUC (4 общих класса)": s["macro_shared4"],
        "стенд macro PR-AUC (все классы атак)": s["macro_attack_classes"],
        "UNSW PR-AUC атака/норма": u["pr_auc_binary"],
        "UNSW macro PR-AUC (4 общих класса)": u["macro_shared4"],
    }
    for f in ("0.001", "0.01", "0.05"):
        out[f"стенд полнота при {float(f):.1%} ложных"] = _rate_value(s["recall"][f]["all"])
    out["стенд средняя по классам полнота при 1% ложных (пост-фактум)"] = class_recall_macro(rec)
    return out


def summarize(results: list[dict]) -> dict:
    """Среднее и разброс по сидам для каждого рукава + проверка критерия значимости C(6) против "
    "C0."""
    groups: dict[str, list[dict]] = {}
    for r in results:
        groups.setdefault(
            f"{r['arm']}({r['k']})" if r["arm"] in ("B", "C") else r["arm"], []
        ).append(r)
    table = {}
    for name, rs in groups.items():
        cols: dict[str, list] = {}
        for r in rs:
            for k, v in _metric_rows(r).items():
                cols.setdefault(k, []).append(v)
        table[name] = {
            "seeds": [r["seed"] for r in rs],
            "metrics": {
                k: {
                    "mean": None if any(x is None for x in v) else float(np.mean(v)),
                    "std": None if any(x is None for x in v) else float(np.std(v)),
                    "values": v,
                }
                for k, v in cols.items()
            },
        }
    return {"table": table, "verdict": _verdict(groups)}


def _verdict(groups: dict) -> dict:
    """Критерий протокола: прирост C(6) − C0 значим, если по сидам один знак и модуль больше
    половины ширины
    интервала Уилсона (полнота) либо разброса между сидами (PR-AUC)."""
    if "C(6)" not in groups or "C0" not in groups:
        return {"status": "нет данных для сравнения C(6) и C0"}
    c6 = {r["seed"]: r for r in groups["C(6)"]}
    c0 = {r["seed"]: r for r in groups["C0"]}
    seeds = sorted(set(c6) & set(c0))
    out = {"seeds": seeds, "checks": {}}
    specs = [
        (
            "полнота при 1% ложных",
            lambda r: _rate_value(r["stand"]["recall"]["0.01"]["all"]),
            "recall",
        ),
        ("macro PR-AUC (4 общих класса)", lambda r: r["stand"]["macro_shared4"], "pr"),
        (
            "средняя по классам полнота при 1% ложных (пост-фактум, не в протоколе)",
            lambda r: class_recall_macro(r),
            "pr",
        ),
        ("PR-AUC атака/норма", lambda r: r["stand"]["pr_auc_binary"], "pr"),
    ]
    for name, fn, kind in specs:
        diffs = [
            fn(c6[s]) - fn(c0[s]) for s in seeds if fn(c6[s]) is not None and fn(c0[s]) is not None
        ]
        if len(diffs) < 2:
            out["checks"][name] = {"status": "мало сидов", "diffs": diffs}
            continue
        if kind == "recall":
            r = c6[seeds[0]]["stand"]["recall"]["0.01"]["all"]
            lo, hi = wilson(r["k"], r["n"])
            width = (hi - lo) / 2
        else:
            width = float(np.std([fn(c0[s]) for s in seeds]))
        same_sign = all(d > 0 for d in diffs) or all(d < 0 for d in diffs)
        big = abs(float(np.mean(diffs))) > width
        out["checks"][name] = {
            "diffs": [round(d, 4) for d in diffs],
            "mean_diff": round(float(np.mean(diffs)), 4),
            "threshold": round(width, 4),
            "significant": bool(same_sign and big),
            "direction": "выше" if np.mean(diffs) > 0 else "ниже",
        }
    sig = [n for n, c in out["checks"].items() if c.get("significant")]
    out["status"] = f"значимо по: {', '.join(sig)}" if sig else "значимого прироста нет"
    return out


def _fmt(x, nd=4) -> str:
    return "—" if x is None or (isinstance(x, float) and np.isnan(x)) else f"{x:.{nd}f}"


def report_md(results: list[dict], version: str) -> str:
    sm = summarize(results)
    order = ["A", "C0", "B(2)", "B(4)", "B(6)", "C(2)", "C(4)", "C(6)"]
    names = [n for n in order if n in sm["table"]]
    metrics = list(next(iter(sm["table"].values()))["metrics"])
    lines = [
        f"# Перенос на трафик стенда: итоги ({version})",
        "",
        "Протокол — `reports/lab_transfer_protocol_20261024.md`. Среднее по сидам (± разброс); у "
        "рукавов с одним сидом "
        "разброс не определён. Порог рукава — по норме val стенда, одинаково для всех.",
        "",
        "## Сводка",
        "",
        "| метрика | "
        + " | ".join(f"{n} (сидов {len(sm['table'][n]['seeds'])})" for n in names)
        + " |",
        "|---|" + "---|" * len(names),
    ]
    for m in metrics:
        cells = []
        for n in names:
            v = sm["table"][n]["metrics"][m]
            cells.append(
                "—"
                if v["mean"] is None
                else f"{v['mean']:.4f}" + (f" ± {v['std']:.4f}" if len(v["values"]) > 1 else "")
            )
        lines.append(f"| {m} | " + " | ".join(cells) + " |")
    v = sm["verdict"]
    lines += ["", "## Критерий протокола: C(6) против контроля C0", "", f"**{v['status']}**", ""]
    for name, c in v.get("checks", {}).items():
        if "mean_diff" in c:
            lines.append(
                f"- {name}: разность по сидам {c['diffs']}, среднее {c['mean_diff']:+.4f} "
                f"({c['direction']}), "
                f"порог {c['threshold']}, значимо: {'да' if c['significant'] else 'нет'}"
            )
        else:
            lines.append(f"- {name}: {c['status']}")
    # полнота по классам и по инструментам при 1% ложных, первый сид каждого рукава
    for key, title in (("by_class", "по классам"), ("by_tool", "по инструментам")):
        lines += ["", f"## Полнота при 1% ложных {title} (первый сид рукава; k/n)", ""]
        first = {}
        for r in results:
            name = f"{r['arm']}({r['k']})" if r["arm"] in ("B", "C") else r["arm"]
            first.setdefault(name, r)
        groups = sorted({g for r in first.values() for g in r["stand"]["recall"]["0.01"][key]})
        cols = [n for n in names if n in first]
        lines += ["| группа | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
        for g in groups:
            cells = []
            for n in cols:
                x = first[n]["stand"]["recall"]["0.01"][key].get(g)
                cells.append("—" if x is None else f"{_rate_value(x):.3f} ({x['k']}/{x['n']})")
            lines.append(f"| {g} | " + " | ".join(cells) + " |")
    lines += ["", "## Резерв «неизвестное» при 1% ложных (первый сид рукава)", ""]
    first = {}
    for r in results:
        first.setdefault(f"{r['arm']}({r['k']})" if r["arm"] in ("B", "C") else r["arm"], r)
    cols = [n for n in names if n in first]
    variants = sorted(
        {g for r in first.values() for g in r["stand"]["recall"]["0.01"]["reserve_by_variant"]}
    )
    lines += ["| вариант | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
    for g in variants:
        cells = []
        for n in cols:
            x = first[n]["stand"]["recall"]["0.01"]["reserve_by_variant"].get(g)
            cells.append("—" if x is None else f"{_rate_value(x):.3f}")
        lines.append(f"| {g} | " + " | ".join(cells) + " |")
    lines += ["", "## Время", "", "| прогон | обучение, с | всего, с |", "|---|---|---|"]
    for r in results:
        lines.append(
            f"| {r['arm']}({r['k']}) сид {r['seed']} | {r['fit_seconds']} | {r['total_seconds']} |"
        )
    return "\n".join(lines) + "\n"


def write_report(
    results: list[dict], out_dir: Path, reports_dir: Path, version: str
) -> tuple[Path, Path]:
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    js = reports_dir / f"lab_transfer_{version}.json"
    js.write_text(
        json.dumps({"summary": summarize(results), "runs": results}, ensure_ascii=False, indent=1)
        + "\n",
        encoding="utf-8",
    )
    md = reports_dir / f"lab_transfer_{version}.md"
    md.write_text(report_md(results, version), encoding="utf-8")
    return md, js
