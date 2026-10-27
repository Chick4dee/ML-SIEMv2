"""Честная оценка переноса модели на трафик стенда (фича 006, US5, R15/R16, конституция III).

Берёт готовый набор стенда (`data/lab/<версия>/flows.parquet` с колонкой `label`) и модель
прогона с её порогом КАК ЕСТЬ (порог не подбирается на стенде — принцип III). Считает:
- PR-AUC macro по представленным классам и «атака/нет» (binary);
- поимку потоков по каждому сценарию (доля с алертом при пороге артефакта);
- FPR и число ложных инцидентов на норме (benign);
- для слабо пойманных сценариев — разбор причины из трёх (R16): класс вне таксономии модели /
  признаки вне диапазона train / потери сенсора.

`ambiguous`-потоки из метрик исключаются, но считаются (FR-020). Запись в MLflow и
`docs/JOURNAL.md` — в CLI; здесь — чистый расчёт отчёта (на нём тесты).
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import polars as pl

from mlsiem.detect.metrics import (
    binary_pr_auc,
    binary_report,
    macro_pr_auc,
    per_class_pr_auc,
)
from mlsiem.lab.dataset import AMBIGUOUS, BENIGN
from mlsiem.soc.verdicts import compute_verdicts

# Причины, по которым сценарий мог не пойматься (R16)
OUT_OF_TAXONOMY = "класс вне таксономии модели"
OUT_OF_DISTRIBUTION = "признаки потоков вне диапазона train"
SENSOR_LOSSES = "потери сенсора (потоки не дошли до модели)"


def _proba_matrix(verdicts: pl.DataFrame, classes: list[str]) -> np.ndarray:
    """Матрица вероятностей классов из колонок p_<класс> вердиктов, в порядке `classes`."""
    cols = [f"p_{c}" for c in classes]
    return verdicts.select(cols).to_numpy()


def evaluate_dataset(
    model,
    labeled: pl.DataFrame,
    records: list[dict],
    *,
    threshold: float | None = None,
    catch_thresholds: dict[str, float] | None = None,
    lossy: bool = False,
    train_ranges: dict[str, tuple[float, float]] | None = None,
    direction: str = "auto",
    by: list[str] | None = None,
    fprs: tuple[float, ...] = (0.001, 0.01, 0.05),
) -> dict:
    """Отчёт оценки (чистый расчёт). `threshold` по умолчанию — порог модели (из артефакта).

    `by` — колонки метаданных набора версии 2 (`tool`, `source`, `variant`): добавляет разбивку
    поимки
    по ним (раздел `breakdown`), в том числе полноту при долях ложных срабатываний `fprs`."""
    threshold = float(model.threshold if threshold is None else threshold)
    classes = list(model.classes)
    catch_thresholds = catch_thresholds or {}

    verdicts = compute_verdicts(model, labeled, direction=direction)
    extra = [c for c in dict.fromkeys([*(by or []), "part"]) if c in labeled.columns]
    v = verdicts.join(labeled.select("flow_uid", "label", *extra), on="flow_uid", how="left")

    # ambiguous — вне метрик, но считаем
    n_ambiguous = int((v["label"] == AMBIGUOUS).sum())
    scored = v.filter(pl.col("label") != AMBIGUOUS)
    y = scored["label"].to_numpy()
    attack = y != BENIGN
    score = scored["attack_score"].to_numpy()
    is_alert = scored["attack_score"].to_numpy() >= threshold

    # PR-AUC по классам, что ЕСТЬ в наборе и в модели (прочие классы набора модель не знает)
    proba = _proba_matrix(scored, classes)
    per_class = per_class_pr_auc(y, proba, classes)
    present = {c: v for c, v in per_class.items() if v is not None}

    # Поимка по сценариям (по классу/имени сценария) + FPR на норме
    catch_by_scenario = {}
    unexplained = []
    # Классы сценариев — из меток самого набора (плюс из журнала, если передан): оценка не
    # зависит от того, дали ли записи журнала, — размеченные потоки говорят сами за себя
    scenario_classes = {c for c in set(y.tolist()) if c not in (BENIGN, AMBIGUOUS)}
    scenario_classes |= {r["expected_class"] for r in records if r["expected_class"] != BENIGN}
    for cls in sorted(scenario_classes):
        mask = y == cls
        if not mask.any():
            continue
        caught = float(is_alert[mask].mean())
        catch_by_scenario[cls] = {"flows": int(mask.sum()), "caught_share": caught}
        need = catch_thresholds.get(cls, 0.0)
        if caught < need:
            unexplained.append(
                {
                    "scenario_class": cls,
                    "caught_share": caught,
                    "threshold": need,
                    "reason": _explain(
                        cls, classes, scored.filter(pl.col("label") == cls), lossy, train_ranges
                    ),
                }
            )

    benign_mask = y == BENIGN
    fpr = float(is_alert[benign_mask].mean()) if benign_mask.any() else None

    breakdown = _breakdown(scored, by or [], threshold, fprs) if by else {}

    return {
        "threshold": threshold,
        "classes": classes,
        "n_scored": int(scored.height),
        "n_ambiguous": n_ambiguous,
        "pr_auc_macro": macro_pr_auc(per_class) if present else None,
        "pr_auc_per_class": per_class,
        "pr_auc_attack": binary_pr_auc(attack, score),
        "binary": binary_report(attack, score, threshold),
        "catch_by_scenario": catch_by_scenario,
        "fpr_normal": fpr,
        "false_incidents": int(is_alert[benign_mask].sum()) if benign_mask.any() else 0,
        "unexplained": unexplained,
        "breakdown": breakdown,
    }


def _breakdown(scored: pl.DataFrame, by: list[str], threshold: float, fprs) -> dict:
    """Поимка атак по значениям метаданных: доля с алертом при пороге артефакта и полнота при долях
    ложных срабатываний. Пороги долей — квантили нормы части val набора (иначе — всей нормы)."""
    benign = scored.filter(pl.col("label") == BENIGN)
    if "part" in benign.columns and benign.filter(pl.col("part") == "val").height >= 100:
        benign = benign.filter(pl.col("part") == "val")
    ref = benign["attack_score"].to_numpy()
    thr = {f: float(np.quantile(ref, 1 - f)) for f in fprs} if len(ref) else {}
    attacks = scored.filter(pl.col("label") != BENIGN)
    out: dict = {}
    for col in by:
        if col not in attacks.columns:
            continue
        rows = []
        sub_all = attacks.filter(pl.col(col).is_not_null())
        for (label, value), sub in sub_all.group_by(["label", col], maintain_order=True):
            sc = sub["attack_score"].to_numpy()
            rows.append(
                {
                    "class": label,
                    col: value,
                    "flows": int(sub.height),
                    "caught_share": float((sc >= threshold).mean()),
                    "recall_at": {str(f): float((sc >= t).mean()) for f, t in thr.items()},
                }
            )
        out[col] = sorted(rows, key=lambda r: (r["class"], str(r[col])))
    return out


def _explain(cls, model_classes, scored_cls, lossy, train_ranges) -> str:
    """Причина слабой поимки сценария (R16): одна из трёх."""
    if cls not in model_classes:
        return OUT_OF_TAXONOMY
    if lossy:
        return SENSOR_LOSSES
    if train_ranges and _share_out_of_range(scored_cls, train_ranges) > 0.5:
        return OUT_OF_DISTRIBUTION
    # По умолчанию — распределение признаков: модель 2015 года видит «чужой» трафик иначе
    return OUT_OF_DISTRIBUTION


def _share_out_of_range(flows: pl.DataFrame, train_ranges: dict[str, tuple[float, float]]) -> float:
    """Средняя доля признаков потока, вышедших за [min,max] train 001."""
    if flows.height == 0:
        return 0.0
    out = []
    for name, (lo, hi) in train_ranges.items():
        if name not in flows.columns:
            continue
        col = flows[name]
        out.append(((col < lo) | (col > hi)).sum() / flows.height)
    return float(np.mean(out)) if out else 0.0


def write_report(report: dict, reports_dir: Path, version: str) -> tuple[Path, Path]:
    """Пишет reports/lab_eval_<версия>.{json,md}; возвращает пути."""
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    js = reports_dir / f"lab_eval_{version}.json"
    md = reports_dir / f"lab_eval_{version}.md"
    js.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md.write_text(_report_md(report, version), encoding="utf-8")
    return md, js


def _fmt(x, fmt="{:.3f}") -> str:
    return "—" if x is None else fmt.format(x)


def _report_md(r: dict, version: str) -> str:
    lines = [
        f"# Оценка переноса модели на набор стенда {version}",
        "",
        f"- порог (из артефакта, не подбирался на стенде): {_fmt(r['threshold'])}",
        f"- PR-AUC macro: {_fmt(r['pr_auc_macro'])}; «атака/нет»: {_fmt(r['pr_auc_attack'])}",
        f"- FPR на норме: {_fmt(r['fpr_normal'])}; ложных инцидентов: {r['false_incidents']}",
        f"- потоков в метриках: {r['n_scored']}; ambiguous (вне метрик): {r['n_ambiguous']}",
        "",
        "## Поимка по сценариям",
        "",
        "| класс | потоков | поймано |",
        "|---|---|---|",
    ]
    for cls, v in sorted(r["catch_by_scenario"].items()):
        lines.append(f"| {cls} | {v['flows']} | {v['caught_share'] * 100:.1f}% |")
    for col, rows in (r.get("breakdown") or {}).items():
        fprs = sorted({f for row in rows for f in row["recall_at"]}, key=float)
        lines += [
            "",
            f"## Поимка по `{col}`",
            "",
            "| класс | "
            + col
            + " | потоков | при пороге артефакта | "
            + " | ".join(f"полнота@{float(f):.1%} ложных" for f in fprs)
            + " |",
            "|---|---|---|---|" + "---|" * len(fprs),
        ]
        for row in rows:
            rec = " | ".join(f"{row['recall_at'][f] * 100:.1f}%" for f in fprs)
            lines.append(
                f"| {row['class']} | {row[col]} | {row['flows']} | "
                f"{row['caught_share'] * 100:.1f}% | {rec} |"
            )
    if r["unexplained"]:
        lines += ["", "## Непойманное — разбор (R16)", ""]
        for u in r["unexplained"]:
            lines.append(
                f"- {u['scenario_class']}: поймано {u['caught_share'] * 100:.1f}% "
                f"(порог {u['threshold'] * 100:.0f}%) → {u['reason']}"
            )
    return "\n".join(lines) + "\n"
