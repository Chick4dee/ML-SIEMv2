"""Аудит ярлыков набора стенда (фича 008, US4): исключение инструмента и хоста, аудит признаков
окружения.

Синтетика: два класса по два инструмента. «С ярлыком» — у каждого инструмента свой маркер в своём
признаке
(без инструмента модель маркера не видела — полнота обязана упасть). «Без ярлыка» — у всех атак один
общий
признак (исключение инструмента ничего не меняет).
"""

from __future__ import annotations

import numpy as np
import polars as pl
import pytest

from mlsiem.detect.dataset import feature_columns
from mlsiem.lab import shortcuts

FAST = {
    "n_estimators": 40,
    "learning_rate": 0.2,
    "num_leaves": 7,
    "class_weight": "balanced",
    "min_child_samples": 5,
}
FEATS = feature_columns()
IPS = {"s1": "10.0.0.1", "s2": "10.0.0.2"}


def _frame(shortcut: bool, n: int = 300, seed: int = 0, env_signal: bool = False) -> pl.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []

    def add(label, tool, source, part, count, marker):
        X = rng.normal(0, 1, (count, len(FEATS)))
        for col, val in marker.items():
            X[:, FEATS.index(col)] += val
        d = pl.DataFrame(X, schema=FEATS)
        rows.append(
            d.with_columns(
                pl.lit(label).alias("label"),
                pl.lit(tool, dtype=pl.String).alias("tool"),
                pl.lit(source, dtype=pl.String).alias("source"),
                pl.lit(part).alias("part"),
                pl.lit(False).alias("reserve_unknown"),
                pl.lit(IPS.get(source, "10.0.0.9")).alias("src_ip"),
            )
        )

    f = {"dos": {"A": FEATS[1], "B": FEATS[2]}, "recon": {"C": FEATS[3], "D": FEATS[4]}}
    for part in ("train", "val", "test"):
        add("benign", None, None, part, n, {})
        add("benign", None, None, part, n // 2, {})
        for label, tools in f.items():
            for i, (tool, col) in enumerate(tools.items()):
                marker = {col: 6.0} if shortcut else {FEATS[0]: 6.0}
                if env_signal:
                    marker = {"bidirectional_ece_packets": 6.0}
                add(label, tool, "s1" if i == 0 else "s2", part, n, marker)
    return pl.concat(rows)


def test_интервал_уилсона():
    lo, hi = shortcuts.wilson(50, 100)
    assert 0.40 < lo < 0.41 and 0.59 < hi < 0.60
    assert shortcuts.wilson(0, 0) == (0.0, 1.0)
    lo, hi = shortcuts.wilson(100, 100)
    assert hi == pytest.approx(1.0) and lo > 0.95


def test_случаи_исключения_только_с_двумя_инструментами_и_достаточным_тестом():
    df = _frame(True)
    cases = shortcuts.tool_exclusion_cases(df, min_test_flows=50)
    assert set(cases) == {("dos", "A"), ("dos", "B"), ("recon", "C"), ("recon", "D")}
    # тест у инструмента меньше порога — он не входит
    assert ("dos", "A") not in shortcuts.tool_exclusion_cases(df, min_test_flows=10_000)
    # инструмент, который есть только в тесте (резерв), не исключается и не мешает
    extra = df.filter((pl.col("tool") == "A") & (pl.col("part") == "test")).with_columns(
        pl.lit("Z").alias("tool"), pl.lit(True).alias("reserve_unknown")
    )
    assert all(t != "Z" for _, t in shortcuts.tool_exclusion_cases(pl.concat([df, extra]), 50))


def _run(df, **kw):
    return shortcuts.run_exclusion(
        df,
        source_ips=IPS,
        seeds=(0,),
        min_test_flows=50,
        params=FAST,
        max_train_per_class=1500,
        log=lambda *_: None,
        **kw,
    )


def test_ярлык_инструмента_виден_падением_полноты():
    res = _run(_frame(True))
    drops = {(r["class"], r["tool"]): r["drop"]["0.01"] for r in res["tools"]}
    assert all(r["control"]["0.01"]["recall"] > 0.9 for r in res["tools"])
    assert min(drops.values()) > 0.5, drops


def test_без_ярлыка_исключение_инструмента_ничего_не_меняет():
    res = _run(_frame(False))
    drops = [r["drop"]["0.01"] for r in res["tools"]]
    assert max(drops) < 0.15, drops


def test_исключение_хоста_и_воспроизводимость_по_сиду():
    df = _frame(True)
    a, b = _run(df), _run(df)
    assert [h["source"] for h in a["hosts"]] == ["s1", "s2"]
    assert a == b  # тот же сид — те же числа
    for h in a["hosts"]:
        assert set(h["excluded"]) == {"0.001", "0.01", "0.05"}
        assert (
            h["excluded"]["0.01"]["ci"][0]
            <= h["excluded"]["0.01"]["recall"]
            <= h["excluded"]["0.01"]["ci"][1]
        )


def test_аудит_окружения_clean_если_признаки_не_нужны():
    rep = shortcuts.run_env_audit(
        _frame(False),
        env_features=shortcuts.DEFAULT_ENV_FEATURES,
        seeds=(0,),
        params=FAST,
        max_train_per_class=1500,
        log=lambda *_: None,
    )
    assert rep["verdict"] == "clean" and rep["drop"] < 0.05
    assert set(rep["permutation_importance"]) == set(rep["env_features"])


def test_аудит_окружения_suspect_если_сигнал_только_в_признаке_окружения():
    rep = shortcuts.run_env_audit(
        _frame(False, env_signal=True),
        env_features=shortcuts.DEFAULT_ENV_FEATURES,
        seeds=(0,),
        params=FAST,
        max_train_per_class=1500,
        log=lambda *_: None,
    )
    assert rep["verdict"] == "suspect" and rep["drop"] > 0.05
    assert rep["permutation_importance"]["bidirectional_ece_packets"] > 0.05
    assert rep["single_feature_pr_auc"]["bidirectional_ece_packets"] > 0.8


def test_отчёт_содержит_оговорку_и_таблицы(tmp_path):
    df = _frame(True)
    rep = {
        "disclaimer": shortcuts.DISCLAIMER,
        "exclusion": _run(df),
        "env_audit": shortcuts.run_env_audit(
            df,
            env_features=shortcuts.DEFAULT_ENV_FEATURES,
            seeds=(0,),
            params=FAST,
            max_train_per_class=1500,
            log=lambda *_: None,
        ),
    }
    md, js = shortcuts.write_report(rep, tmp_path / "ds", tmp_path / "reports", "v1")
    text = md.read_text(encoding="utf-8")
    assert (
        "нулевого дня" in text
        and "Исключение инструмента" in text
        and "Аудит признаков окружения" in text
    )
    assert js.exists()


def test_запись_в_журнал_идемпотентна(tmp_path, monkeypatch):
    from mlsiem.lab import commands

    monkeypatch.chdir(tmp_path)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "JOURNAL.md").write_text(
        "# Журнал\n\n### Другая запись (2026-01-01)\n\nтекст\n", encoding="utf-8"
    )
    entry = "\n### Ярлыки набора V (2026-10-24)\n\n- итог 1\n"
    commands._journal_append(entry)
    commands._journal_append(entry.replace("итог 1", "итог 2"))  # повторный прогон
    text = (tmp_path / "docs" / "JOURNAL.md").read_text(encoding="utf-8")
    assert text.count("### Ярлыки набора V") == 1 and "итог 2" in text and "итог 1" not in text
    assert "### Другая запись" in text and "текст" in text  # соседние записи целы
