"""Эксперимент переноса (фича 008): рукава, пороги по норме val стенда, возобновление, критерий
значимости.

Синтетика со сдвигом домена: у «UNSW»-атак сигнатура в одних признаках, у стендовых — в других.
Рукава без данных
стенда стенд не видят, рукава с данными стенда — видят; на этом проверяются и механика, и критерий
протокола.
"""

from __future__ import annotations

import json

import numpy as np
import polars as pl

from mlsiem.detect.candidates import build_candidate
from mlsiem.detect.dataset import feature_columns
from mlsiem.lab import transfer

FEATS = feature_columns()
FAST = {
    "n_estimators": 40,
    "learning_rate": 0.2,
    "num_leaves": 7,
    "class_weight": "balanced",
    "min_child_samples": 5,
}
UNSW_SIG = {"dos": 0, "exploits": 1, "fuzzers": 2, "reconnaissance": 3}
STAND_SIG = {"dos": 20, "exploits": 21, "fuzzers": 22, "reconnaissance": 23}
TOOLS = {
    "dos": ["hping", "slow"],
    "exploits": ["nikto", "sqlmap"],
    "fuzzers": ["ffuf", "gobuster"],
    "reconnaissance": ["nmap", "masscan"],
}


def _block(rng, n, sig_col=None):
    X = rng.normal(0, 1, (n, len(FEATS))).astype(np.float32)
    if sig_col is not None:
        X[:, sig_col] += 6.0
    return X


def _unsw(seed=0, n=400):
    rng = np.random.default_rng(seed)
    X, y = [_block(rng, n * 3)], ["benign"] * (n * 3)
    for c, col in UNSW_SIG.items():
        X.append(_block(rng, n, col))
        y += [c] * n
    return np.vstack(X), np.array(y)


def _stand(seed=1, n=60, sig_map=None) -> pl.DataFrame:
    sig_map = sig_map or STAND_SIG
    rng = np.random.default_rng(seed)
    rows = []

    def add(label, part, repeat, tool=None, source=None, variant=None, reserve=False, count=n):
        sig = sig_map.get(label)
        d = pl.DataFrame(_block(rng, count, sig), schema=FEATS)
        rows.append(
            d.with_columns(
                pl.lit(label).alias("label"),
                pl.lit(part).alias("part"),
                pl.lit(repeat).alias("repeat"),
                pl.lit(tool, dtype=pl.String).alias("tool"),
                pl.lit(source, dtype=pl.String).alias("source"),
                pl.lit(variant, dtype=pl.String).alias("variant"),
                pl.lit(reserve).alias("reserve_unknown"),
            )
        )

    for part, reps in (("train", range(1, 7)), ("val", (7, 8)), ("test", (9, 10))):
        for rep in reps:
            add("benign", part, rep, count=n * 3)
            for c, tools in TOOLS.items():
                for i, t in enumerate(tools):
                    add(c, part, rep, tool=t, source=["attacker", "attacker_a2"][i], variant=t)
    add(
        "dos",
        "test",
        9,
        tool="reserve_tool",
        source="attacker",
        variant="reserve_variant",
        reserve=True,
    )
    return pl.concat(rows)


def _data(with_artifact=True) -> transfer.Data:
    Xu, yu = _unsw()
    Xt, yt = _unsw(seed=5, n=150)
    art = None
    if with_artifact:
        model = build_candidate("lgbm", FAST, 0)
        model.fit(Xu, yu)
        art = (model, 0.5)
    return transfer.Data(stand=_stand(), unsw_train=(Xu, yu), unsw_test=(Xt, yt), artifact=art)


def _run(tmp_path, **kw):
    kw.setdefault("seeds", (0, 1))
    kw.setdefault("curve", (2,))
    return transfer.run_transfer(
        _data(),
        tmp_path,
        params=FAST,
        min_test=20,
        cap_benign=1000,
        cap_class=300,
        log=lambda *_: None,
        **kw,
    )


def test_порядок_плана_сначала_основные_рукава():
    p = transfer.plan((0, 1, 2), (2, 4))
    assert [a for a, _, _ in p[:4]] == ["A", "C0", "C", "B"]
    assert (
        len(p) == 4 + 3 * 2 + 4
    )  # основные на сиде 0, три рукава на двух остальных сидах, кривая из двух размеров
    assert p[-1][2] == 0  # кривая обучения — на первом сиде


def test_урезание_детерминировано_и_зависит_от_сида():
    rng = np.random.default_rng(0)
    X, y = rng.normal(size=(1000, 3)), np.array(["benign"] * 700 + ["dos"] * 300)
    a = transfer._cap(X, y, 0, 100, 50)
    assert (a[1] == "benign").sum() == 100 and (a[1] == "dos").sum() == 50
    assert np.array_equal(a[0], transfer._cap(X, y, 0, 100, 50)[0])
    assert not np.array_equal(a[0], transfer._cap(X, y, 1, 100, 50)[0])


def test_обучение_берёт_повторы_до_k_и_не_берёт_резерв():
    data = _data(with_artifact=False)
    X, y = transfer.build_train(data, "B", 2, 0, 1000, 10_000)
    train = data.stand.filter(
        (pl.col("part") == "train") & (pl.col("repeat") <= 2) & ~pl.col("reserve_unknown")
    )
    assert len(y) == train.height  # только повторы 1–2 и ничего из резерва
    Xc, yc = transfer.build_train(data, "C0", 0, 0, 1000, 10_000)
    assert len(yc) == (data.unsw_train[1] != "benign").sum() + min(
        1000, (data.unsw_train[1] == "benign").sum()
    )
    Xn, yn = transfer.build_train(data, "C", 6, 0, 1000, 10_000)
    assert len(yn) > len(yc)


def test_сквозной_прогон_данные_стенда_дают_прирост_только_там_где_он_есть(tmp_path):
    res = _run(tmp_path)
    assert len(res) == 9  # A, 3 рукава × 2 сида, кривая C(2) и B(2)
    by = {(r["arm"], r["k"], r["seed"]): r for r in res}

    def rec(r):
        x = r["stand"]["recall"]["0.01"]["all"]
        return x["k"] / x["n"]

    assert (
        rec(by[("A", 0, None)]) < 0.3 and rec(by[("C0", 0, 0)]) < 0.3
    )  # без стенда сигнатуры стенда не видны
    assert rec(by[("C", 6, 0)]) > 0.9 and rec(by[("B", 6, 0)]) > 0.9
    # доля ложных на норме теста не превышает заявленную заметно (порог по val, разные части одного
    # распределения)
    for r in res:
        fp = r["stand"]["recall"]["0.01"]["benign_fpr"]
        assert fp["k"] / fp["n"] < 0.05
    # не забыли исходный домен: UNSW-тест у C(6) остаётся хорошим, у B(6) без UNSW — нет
    assert by[("C", 6, 0)]["unsw"]["pr_auc_binary"] > 0.9
    assert by[("B", 6, 0)]["unsw"]["pr_auc_binary"] < by[("C", 6, 0)]["unsw"]["pr_auc_binary"]
    # резерв оценивается отдельно и в обучение не попадал
    assert "reserve_variant" in by[("C", 6, 0)]["stand"]["recall"]["0.01"]["reserve_by_variant"]
    # у артефакта есть оценка при его собственном пороге
    assert "at_artifact_threshold" in by[("A", 0, None)]["stand"]


def test_возобновление_не_повторяет_готовое(tmp_path):
    _run(tmp_path)
    lines = (tmp_path / "results.jsonl").read_text(encoding="utf-8").splitlines()
    messages = []
    transfer.run_transfer(
        _data(),
        tmp_path,
        seeds=(0, 1),
        curve=(2,),
        params=FAST,
        min_test=20,
        cap_benign=1000,
        cap_class=300,
        log=messages.append,
    )
    assert (tmp_path / "results.jsonl").read_text(encoding="utf-8").splitlines() == lines
    assert sum("уже сделано" in m for m in messages) == 9


def test_критерий_значимости_и_отчёт(tmp_path):
    res = _run(tmp_path)
    sm = transfer.summarize(res)
    checks = sm["verdict"]["checks"]
    assert checks["полнота при 1% ложных"]["significant"] is True
    assert checks["полнота при 1% ложных"]["direction"] == "выше"
    assert sm["verdict"]["status"].startswith("значимо по")
    md, js = transfer.write_report(res, tmp_path, tmp_path / "reports", "test")
    text = md.read_text(encoding="utf-8")
    assert (
        "Критерий протокола" in text
        and "Полнота при 1% ложных по классам" in text
        and "reserve_variant" in text
    )
    assert (
        json.loads(js.read_text(encoding="utf-8"))["summary"]["verdict"]["status"]
        == sm["verdict"]["status"]
    )


def test_без_различия_критерий_говорит_что_прироста_нет(tmp_path):
    # стенд — тот же домен, что UNSW (те же сигнатуры): добавка данных стенда ничего не меняет
    Xu, yu = _unsw()
    data = transfer.Data(
        stand=_stand(sig_map=UNSW_SIG), unsw_train=(Xu, yu), unsw_test=_unsw(seed=5, n=150)
    )
    res = transfer.run_transfer(
        data,
        tmp_path,
        seeds=(0, 1, 2),
        curve=(),
        params=FAST,
        min_test=20,
        cap_benign=1000,
        cap_class=300,
        log=lambda *_: None,
    )
    assert "значимого прироста нет" in transfer.summarize(res)["verdict"]["status"]
