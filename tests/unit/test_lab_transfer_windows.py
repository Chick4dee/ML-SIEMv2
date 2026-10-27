"""Эксперимент переноса на окнах (фича 008, этап 2): механика на синтетических окнах.

Сами окна строятся функциями 007 (их тесты — там); здесь окна подставлены в кэш готовыми, чтобы
проверить рукава,
маски ранней остановки, пороги по норме val, резерв и возобновление.
"""

from __future__ import annotations

import numpy as np
import polars as pl

from mlsiem.detect import windows as W
from mlsiem.lab import transfer_windows as TW

NFEAT = 8
UNSW_SIG = {"dos": 0, "exploits": 1, "fuzzers": 2, "reconnaissance": 3}
STAND_SIG = {"dos": 4, "exploits": 5, "fuzzers": 6, "reconnaissance": 7}
FAST = {
    "n_estimators": 40,
    "learning_rate": 0.2,
    "num_leaves": 7,
    "class_weight": "balanced",
    "min_child_samples": 3,
    "early_stopping_rounds": 5,
}


def _set(sig, n_benign, n_attack, seed, shifts=(0,), reserve=0) -> TW.WindowSet:
    rng = np.random.default_rng(seed)
    labels = ["benign"] * n_benign + [c for c in sig for _ in range(n_attack)]
    order = rng.permutation(
        len(labels)
    )  # время окон перемешано по классам; одна и та же для всех сеток
    X, y, starts, shift_col = [], [], [], []
    for s in shifts:
        for pos, idx in enumerate(order):
            label = labels[idx]
            row = rng.normal(0, 1, NFEAT).astype(np.float32)
            if label != "benign":
                row[sig[label]] += 6.0
            X.append(row), y.append(label), starts.append(pos * W_LEN + s), shift_col.append(s)
    n = len(y)
    srt = np.argsort(starts, kind="stable")
    X, y = np.array(X)[srt], np.array(y)[srt]
    starts, shift_col = np.array(starts)[srt], np.array(shift_col)[srt]
    windows = pl.DataFrame(
        {
            "window_id": [f"w{i}" for i in range(n)],
            "window_start_ms": starts,
            "window_end_ms": starts + W_LEN,
            "shift_ms": shift_col,
            "label": y,
        }
    )
    has_reserve = np.zeros(n, dtype=bool)
    if reserve:
        has_reserve[np.flatnonzero(y == "dos")[:reserve]] = True
    return TW.WindowSet(X=X, y=y, windows=windows, has_reserve=has_reserve)


W_LEN = W.LENGTH_MS if hasattr(W, "LENGTH_MS") else TW.LENGTH_MS


def _data(stand_sig=None) -> TW.WData:
    stand_sig = stand_sig or STAND_SIG
    unsw = {
        "train": _set(UNSW_SIG, 150, 30, 0, shifts=(0, 15000)),
        "val": _set(UNSW_SIG, 40, 8, 1),
        "test": _set(UNSW_SIG, 40, 8, 2),
    }
    data = TW.WData(unsw=unsw, stand=pl.DataFrame(), stand_cache={})
    cache = data.stand_cache
    for k in (2, 4, 6):  # окна стенда с повторами ≤ k: чем больше k, тем больше окон
        cache[("train", k, TW.SHIFTS)] = _set(stand_sig, 15 * k, 4 * k, 10 + k, shifts=(0, 15000))
    cache[("val", None, (0,))] = _set(stand_sig, 80, 6, 20)
    cache[("test", None, (0,))] = _set(stand_sig, 80, 10, 21, reserve=3)
    # «готовый артефакт» — модель, обученная только на окнах UNSW (рукав WA)
    X, y, fit, hold = TW.build_train(data, "C0", 0)
    data.artifact = (TW.fit_arm(X, y, fit, hold, FAST, 0), 0.5)
    return data


def _run(tmp_path, data=None, **kw):
    kw.setdefault("seeds", (0, 1))
    kw.setdefault("curve", (2,))
    return TW.run_windows(
        data or _data(), tmp_path, params=FAST, min_class=3, log=lambda *_: None, **kw
    )


def test_обучение_берёт_окна_стенда_только_там_где_нужно():
    data = _data()
    Xc0, yc0, fit0, hold0 = TW.build_train(data, "C0", 0)
    Xb, yb, fitb, holdb = TW.build_train(data, "B", 6)
    Xc, yc, fitc, holdc = TW.build_train(data, "C", 6)
    assert (
        len(yc0) == len(data.unsw["train"].y)
        and len(yb) < len(yc)
        and len(yc) == len(yc0) + len(yb)
    )
    assert not (fitc & holdc).any()  # обучение и хвост не пересекаются
    assert holdc.sum() > 0 and fitc.sum() > len(yc) / 2
    assert "dos" in set(yb) and "reconnaissance" in set(yb)


def test_сквозной_прогон_окна_данные_стенда_дают_прирост(tmp_path):
    res = _run(tmp_path)
    assert len(res) == 9
    by = {(r["arm"], r["k"], r["seed"]): r for r in res}

    def rec(r, f="0.05"):
        x = r["stand"]["recall"][f]["all"]
        return x["k"] / x["n"]

    assert rec(by[("C0", 0, 0)]) < 0.4 and rec(by[("C", 6, 0)]) > 0.8 and rec(by[("B", 6, 0)]) > 0.8
    assert by[("C", 6, 0)]["unsw"]["pr_auc_binary"] > 0.9
    assert by[("A", 0, None)]["level"] == "windows"
    assert by[("A", 0, None)]["stand"]["at_artifact_threshold"]["all"]["n"] > 0
    # окна с резервом считаются отдельно и в «известные» не входят
    r5 = by[("C", 6, 0)]["stand"]["recall"]["0.05"]
    assert r5["reserve"]["n"] == 3 and r5["all"]["n"] == 4 * 10 - 3


def test_возобновление_и_отчёт(tmp_path):
    res = _run(tmp_path)
    lines = (tmp_path / "results_windows.jsonl").read_text(encoding="utf-8").splitlines()
    msgs = []
    TW.run_windows(
        _data(), tmp_path, seeds=(0, 1), curve=(2,), params=FAST, min_class=3, log=msgs.append
    )
    assert (tmp_path / "results_windows.jsonl").read_text(encoding="utf-8").splitlines() == lines
    assert sum("уже сделано" in m for m in msgs) == 9
    md = TW.write_report(res, tmp_path / "reports", "t")
    text = md.read_text(encoding="utf-8")
    assert "уровень окон" in text and "Окна с резервом" in text and "C(6)" in text
