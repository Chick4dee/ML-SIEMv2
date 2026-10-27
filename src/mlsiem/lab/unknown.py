"""Раздел «неизвестные атаки» оценки набора стенда (фича 008, US5, FR-021…FR-023, R12).

Два вида «неизвестного»:
- **резервные варианты** — инструменты и наборы параметров, которых нет в обучении (флаг
  `reserve_unknown` набора: masscan, gobuster, «маячки»). Класс известен, вариант — нет;
- **класс целиком** (leave-class-out) — обучаем без класса и смотрим, замечает ли модель его потоки
  как необычные. Это ближайшее, что даёт стенд к «атаке вне таксономии».

Для каждой группы считаем полноту всеми способами из `detect.openset` (атака/норма, MSP, энергия и
объединение по p-значениям нормы) при долях ложных срабатываний 0,1 / 1 / 5%. Пороги — квантили
нормы
валидации той же модели. **Контроль** — та же группа, когда она «известна»: для резервного варианта
модель дообучается на его первом тестовом повторе и проверяется на остальных повторах (те же потоки,
что у «неизвестной» модели); для класса — полная модель без исключения. Разность «контроль −
неизвестное»
показывает цену незнакомства. Блок «на что похоже» — в какие известные классы модель относит потоки.

Граница применимости (FR-023): это «неизвестное в рамках таксономии и стенда», а не реальные
уязвимости нулевого дня.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import numpy as np
import polars as pl

from mlsiem.detect import openset
from mlsiem.detect.dataset import feature_columns
from mlsiem.lab.dataset import BENIGN
from mlsiem.lab.shortcuts import DEFAULT_FPR, DEFAULT_PARAMS, _fit, _usable, wilson

DISCLAIMER = (
    "Граница применимости: результат относится к «неизвестному в рамках таксономии и стенда» — к "
    "вариантам "
    "и классам, которых не было в обучении, — а не к реальным уязвимостям нулевого дня. "
    "Обнаружение "
    "настоящего нулевого дня этим экспериментом не доказывается."
)


def _logits(model, df: pl.DataFrame, feats: list[str]) -> np.ndarray:
    X = df.select(feats).cast(pl.Float32).fill_null(0).to_numpy()
    return openset.raw_logits(model, X)


def _evaluate(model, classes, val_benign, rows, feats, fprs):
    """Полнота по способам для `rows` и распределение предсказанных классов."""
    scores_val = openset.all_scores(_logits(model, val_benign, feats), classes)
    thr, cal = openset.thresholds_for(scores_val, fprs)
    z = _logits(model, rows, feats)
    rec = openset.recall_by_method(openset.all_scores(z, classes), cal, thr, fprs)
    pred = Counter(np.array(classes)[z.argmax(axis=1)].tolist())
    return rec, {c: n / len(rows) for c, n in pred.items()}


def _groups(d: pl.DataFrame, train: pl.DataFrame, min_test: int):
    test = d.filter(pl.col("part") == "test")
    res = test.filter(pl.col("reserve_unknown") & (pl.col("label") != BENIGN))
    variants = []
    for (label, variant), sub in res.group_by(["label", "variant"], maintain_order=True):
        if sub.height >= min_test:
            variants.append((label, variant, sub["tool"][0], sub))
    classes = []
    known = test.filter(~pl.col("reserve_unknown") & (pl.col("label") != BENIGN))
    for label in sorted(known["label"].unique().to_list()):
        sub = known.filter(pl.col("label") == label)
        if sub.height >= min_test and train.filter(pl.col("label") == label).height > 0:
            classes.append((label, sub))
    return variants, classes


def _aggregate(per_seed: list[dict], n: int) -> dict:
    """Среднее по сидам: {способ: {доля: {recall, seeds, ci}}}."""
    out: dict = {}
    for m in per_seed[0]:
        out[m] = {}
        for f in per_seed[0][m]:
            vals = [s[m][f] for s in per_seed]
            mean = float(np.mean(vals))
            lo, hi = wilson(int(round(mean * n)), n)
            out[m][str(f)] = {
                "recall": round(mean, 4),
                "seeds": [round(v, 4) for v in vals],
                "ci": [round(lo, 4), round(hi, 4)],
            }
    return out


def _mean_dict(dicts: list[dict]) -> dict:
    keys = set().union(*dicts)
    return {k: round(float(np.mean([d.get(k, 0.0) for d in dicts])), 4) for k in keys}


def run_unknown(
    labeled: pl.DataFrame,
    *,
    seeds=(0, 1, 2),
    fprs=DEFAULT_FPR,
    min_test_flows: int = 100,
    params: dict | None = None,
    max_train_per_class: int = 30_000,
    log=print,
) -> dict:
    params = params or DEFAULT_PARAMS
    feats = feature_columns()
    d = _usable(labeled)
    train = d.filter((pl.col("part") == "train") & ~pl.col("reserve_unknown"))
    val_benign = d.filter((pl.col("part") == "val") & (pl.col("label") == BENIGN))
    variants, class_groups = _groups(d, train, min_test_flows)
    acc = {
        ("variant", lb, vr): {"unknown": [], "control": [], "pred": []} for lb, vr, _, _ in variants
    }
    acc.update(
        {("class", lb, None): {"unknown": [], "control": [], "pred": []} for lb, _ in class_groups}
    )
    for seed in seeds:
        log(f"[сид {seed}] полная модель")
        m0, c0 = _fit(train, feats, seed, params, max_train_per_class)
        for label, variant, _, rows in variants:
            first = int(rows["repeat"].min())
            held, rest = (
                rows.filter(pl.col("repeat") == first),
                rows.filter(pl.col("repeat") > first),
            )
            if rest.height == 0:
                continue
            log(f"[сид {seed}] вариант {variant} ({label}): неизвестный и контроль")
            unk, pred = _evaluate(m0, c0, val_benign, rest, feats, fprs)
            m1, c1 = _fit(
                pl.concat([train, held.select(train.columns)]),
                feats,
                seed,
                params,
                max_train_per_class,
            )
            ctl, _ = _evaluate(m1, c1, val_benign, rest, feats, fprs)
            a = acc[("variant", label, variant)]
            a["unknown"].append(unk), a["control"].append(ctl), a["pred"].append(pred)
            a["n"] = rest.height
        for label, rows in class_groups:
            log(f"[сид {seed}] класс {label} целиком")
            m, c = _fit(
                train.filter(pl.col("label") != label), feats, seed, params, max_train_per_class
            )
            unk, pred = _evaluate(m, c, val_benign, rows, feats, fprs)
            ctl, _ = _evaluate(m0, c0, val_benign, rows, feats, fprs)
            a = acc[("class", label, None)]
            a["unknown"].append(unk), a["control"].append(ctl), a["pred"].append(pred)
            a["n"] = rows.height
    groups = []
    for (kind, label, variant), a in acc.items():
        if not a["unknown"]:
            continue
        n = a["n"]
        unk, ctl = _aggregate(a["unknown"], n), _aggregate(a["control"], n)
        diff = {
            m: {f: round(ctl[m][f]["recall"] - unk[m][f]["recall"], 4) for f in unk[m]} for m in unk
        }
        groups.append(
            {
                "kind": kind,
                "class": label,
                "variant": variant,
                "n": n,
                "unknown": unk,
                "control": ctl,
                "diff": diff,
                "resembles": _mean_dict(a["pred"]),
            }
        )
    return {
        "disclaimer": DISCLAIMER,
        "methods": list(openset.METHODS),
        "fprs": list(fprs),
        "seeds": list(seeds),
        "groups": groups,
    }


def report_md(rep: dict, version: str) -> str:
    fprs = [str(f) for f in rep["fprs"]]
    lines = [
        f"# Неизвестные атаки на наборе стенда {version}",
        "",
        f"> {rep['disclaimer']}",
        "",
        f"Сиды: {rep['seeds']}. Полнота при доле ложных срабатываний на норме валидации; "
        "«контроль» — "
        "группа известна модели; «разность» = контроль − неизвестное.",
        "",
    ]
    for g in rep["groups"]:
        title = (
            f"Вариант {g['variant']} (класс {g['class']})"
            if g["kind"] == "variant"
            else f"Класс {g['class']} целиком (leave-class-out)"
        )
        lines += [
            f"## {title}",
            "",
            f"Потоков в оценке: {g['n']}.",
            "",
            "| способ | "
            + " | ".join(f"неизв.@{float(f):.1%}" for f in fprs)
            + " | "
            + " | ".join(f"контроль@{float(f):.1%}" for f in fprs)
            + " | "
            + " | ".join(f"разность@{float(f):.1%}" for f in fprs)
            + " |",
            "|---|" + "---|" * (3 * len(fprs)),
        ]
        for m in rep["methods"]:
            u = [f"{g['unknown'][m][f]['recall']:.3f}" for f in fprs]
            c = [f"{g['control'][m][f]['recall']:.3f}" for f in fprs]
            x = [f"{g['diff'][m][f]:+.3f}" for f in fprs]
            lines.append(
                f"| {m} | " + " | ".join(u) + " | " + " | ".join(c) + " | " + " | ".join(x) + " |"
            )
        top = sorted(g["resembles"].items(), key=lambda kv: -kv[1])
        lines += [
            "",
            "На что похоже (в какие классы модель относит эти потоки): "
            + ", ".join(f"{c} {s:.0%}" for c, s in top if s >= 0.005),
            "",
        ]
    return "\n".join(lines) + "\n"


def write_report(
    rep: dict, dataset_dir: Path, reports_dir: Path, version: str
) -> tuple[Path, Path]:
    dataset_dir, reports_dir = Path(dataset_dir), Path(reports_dir)
    dataset_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    js = dataset_dir / "unknown.json"
    js.write_text(json.dumps(rep, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    md = reports_dir / f"lab_unknown_{version}.md"
    md.write_text(report_md(rep, version), encoding="utf-8")
    return md, js
