"""Раздел «неизвестные атаки» (фича 008, US5, FR-021…FR-023): резервные варианты, класс целиком, "
"контроль."""

from __future__ import annotations

import numpy as np
import polars as pl

from mlsiem.detect.dataset import feature_columns
from mlsiem.lab import unknown

FAST = {
    "n_estimators": 40,
    "learning_rate": 0.2,
    "num_leaves": 7,
    "class_weight": "balanced",
    "min_child_samples": 5,
}
FEATS = feature_columns()


def _frame(seed: int = 0, n: int = 300) -> pl.DataFrame:
    rng = np.random.default_rng(seed)
    parts = []

    def add(label, variant, part, count, marker, reserve=False, repeat=1):
        X = rng.normal(0, 1, (count, len(FEATS)))
        for col, val in marker.items():
            X[:, FEATS.index(col)] += val
        parts.append(
            pl.DataFrame(X, schema=FEATS).with_columns(
                pl.lit(label).alias("label"),
                pl.lit(variant, dtype=pl.String).alias("variant"),
                pl.lit(variant, dtype=pl.String).alias("tool"),
                pl.lit(part).alias("part"),
                pl.lit(reserve).alias("reserve_unknown"),
                pl.lit(repeat).alias("repeat"),
            )
        )

    for part, rep in (("train", 1), ("val", 7), ("test", 9)):
        add("benign", None, part, n * 2, {}, repeat=rep)
        add("dos", "A", part, n, {FEATS[0]: 6.0}, repeat=rep)
        add("recon", "C", part, n, {FEATS[3]: 6.0}, repeat=rep)
    for rep in (9, 10):  # резерв: только в тесте, два повтора
        add(
            "dos", "familiar", "test", n, {FEATS[0]: 6.0}, reserve=True, repeat=rep
        )  # похож на известный dos
        add(
            "dos", "novel", "test", n, {FEATS[7]: 6.0}, reserve=True, repeat=rep
        )  # маркер, которого не было в обучении
    return pl.concat(parts)


def _run(df):
    return unknown.run_unknown(
        df,
        seeds=(0,),
        min_test_flows=50,
        params=FAST,
        max_train_per_class=1500,
        log=lambda *_: None,
    )


def test_группы_и_оговорка():
    rep = _run(_frame())
    kinds = {(g["kind"], g["class"], g["variant"]) for g in rep["groups"]}
    assert ("variant", "dos", "familiar") in kinds and ("variant", "dos", "novel") in kinds
    assert ("class", "dos", None) in kinds and ("class", "recon", None) in kinds
    assert "нулевых" in rep["disclaimer"] or "нулевого дня" in rep["disclaimer"]


def test_знакомый_вариант_ловится_а_новый_уступает_контролю():
    rep = _run(_frame())
    g = {(x["kind"], x["variant"]): x for x in rep["groups"]}
    familiar, novel = g[("variant", "familiar")], g[("variant", "novel")]
    assert familiar["unknown"]["attack_vs_normal"]["0.01"]["recall"] > 0.9
    # новый маркер: без обучения на нём модель его не видит, контроль (дообученный) видит — разность
    # большая
    assert novel["diff"]["attack_vs_normal"]["0.01"] > 0.5
    assert novel["diff"]["attack_vs_normal"]["0.01"] > familiar["diff"]["attack_vs_normal"]["0.01"]


def test_класс_целиком_и_разбор_на_что_похоже():
    rep = _run(_frame())
    g = {(x["kind"], x["class"]): x for x in rep["groups"]}
    recon = g[("class", "recon")]
    assert recon["control"]["attack_vs_normal"]["0.01"]["recall"] > 0.9
    assert recon["diff"]["attack_vs_normal"]["0.01"] > 0.5
    assert abs(sum(recon["resembles"].values()) - 1.0) < 0.02
    assert "recon" not in recon["resembles"]  # без класса модель его предсказать не может
    # двухклассовая модель (без recon остаются benign и dos): оценки конечны, пороги не NaN
    assert all(0.0 <= v["0.01"]["recall"] <= 1.0 for v in recon["unknown"].values())


def test_все_способы_и_доли_присутствуют():
    rep = _run(_frame())
    g = rep["groups"][0]
    assert set(g["unknown"]) == {"attack_vs_normal", "msp", "energy", "combined"}
    assert set(g["unknown"]["combined"]) == {"0.001", "0.01", "0.05"}
    # более мягкая доля ложных срабатываний не снижает полноту
    r = g["unknown"]["combined"]
    assert r["0.001"]["recall"] <= r["0.01"]["recall"] <= r["0.05"]["recall"]


def test_воспроизводимость_по_сиду_и_отчёт(tmp_path):
    df = _frame()
    a, b = _run(df), _run(df)
    assert a == b
    md, js = unknown.write_report(a, tmp_path / "ds", tmp_path / "reports", "v1")
    text = md.read_text(encoding="utf-8")
    assert "нулевого дня" in text and "На что похоже" in text and "leave-class-out" in text
    assert js.exists()
