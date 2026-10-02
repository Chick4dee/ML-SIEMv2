"""Эксперимент фичи 007: бустинг окон против нейросети окон против текущей модели (US1).

Порядок строго такой, чтобы test ни на что не влиял (принцип III, research R8):

1. окна `unsw_time`: train (основная сетка + сдвиги 15/30/45 с, R9), val, test — каждая часть
   отдельно, потоки чужих частей в окно не попадают (SC-004);
2. train режется на «обучение» и отложенный хвост по времени (R5) — ранняя остановка обеих
   моделей окон идёт по хвосту, а не по val;
3. участники: `lgbm` на сводных признаках (R3, R6), `gru` на последовательностях (R4, R5) и
   `current` — модель прогона 002/004, у которой оценки потоков сведены к окну максимумом (R7);
4. порог каждого участника — максимум F1 «атака/нет» на val (`choose_threshold`);
5. выбор ТОЛЬКО по val, по macro PR-AUC надёжных классов (≥ `min_class_windows` окон на val):
   шаг 1 — нейросеть против бустинга (+`min_gain`), шаг 2 — победитель против текущей модели
   (+`min_gain`). Функции выбора test на вход не получают (проверяется тестом, SC-002);
6. test — один раз, уже после всех решений (`final_test_metrics`), только в отчёт;
7. победитель сохраняется всегда (R11) с `accepted: false` и `audit_verdict: not_run`: принять
   модель может только аудит (`detect windows-audit`, FR-012). Отрицательный результат —
   законный исход (FR-010): цепочка не меняется.

Результаты: `models/windows/` (карточка, модель, experiment.json), `reports/windows_experiment.md`
и три запуска MLflow-эксперимента `windows` (lgbm, gru, current).
"""

from __future__ import annotations

import gc
import json
import logging
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from mlsiem.data.captures import atomic_path
from mlsiem.data.schema import SCHEMA
from mlsiem.detect import metrics as M
from mlsiem.detect import windows as W
from mlsiem.detect.candidates import LGBM_THREADS
from mlsiem.detect.dataset import data_hashes
from mlsiem.detect.windows_expert import (
    EXPERIMENT_FILE,
    library_versions,
    save_window_expert,
    window_version,
)

log = logging.getLogger("mlsiem")
MLFLOW_EXPERIMENT = "windows"
REPORT_NAME = "windows_experiment.md"
# Допуск воспроизводимости (SC-003): бустинг детерминирован до последнего знака, у GRU на
# видеокарте часть операций cuDNN недетерминирована — допускается разброс в пределах 0.01
REPRO_TOLERANCE = {"lgbm": 0.001, "gru": 0.01}
TITLES = {
    "lgbm": "бустинг окон (LightGBM, сводные признаки)",
    "gru": "нейросеть окон (biGRU, последовательность)",
    "current": "текущая модель, сведённая к окну (max)",
}


# ================================================================ вспомогательное


def peak_memory_mb() -> float | None:
    """Пиковая память процесса (МБ): на Windows — peak working set, иначе текущая RSS."""
    try:
        import psutil

        info = psutil.Process().memory_info()
        return round(getattr(info, "peak_wset", info.rss) / 2**20, 1)
    except Exception:  # psutil в зависимостях, но замер не должен ронять эксперимент
        return None


def resolve_current_dir(value: str) -> Path:
    """`auto` — как в цепочке 004: ансамбль, если обучен, иначе детектор 002."""
    if value != "auto":
        return Path(value)
    if (Path("models/ensemble") / "ensemble_card.json").exists():
        return Path("models/ensemble")
    return Path("models/detector")


def align_proba(proba: np.ndarray, classes: list[str], target: list[str]) -> np.ndarray:
    """Столбцы вероятностей в порядке `target`; класса нет у модели — нули (его PR-AUC тогда
    равен доле класса, как у угадывания: модель его просто не знает)."""
    out = np.zeros((len(proba), len(target)))
    for j, c in enumerate(target):
        if c in classes:
            out[:, j] = proba[:, classes.index(c)]
    return out


def evaluate_windows(
    y: np.ndarray,
    proba: np.ndarray,
    score: np.ndarray,
    classes: list[str],
    threshold: float,
    reliable: list[str],
) -> dict:
    """Метрики участника на одной части: macro надёжных (метрика выбора), macro всех,
    PR-AUC по классам, «атака/нет» и точность/полнота на пороге. `proba` — в порядке
    `classes`; `score` — скор атаки участника (у текущей модели — максимум по потокам)."""
    per_class = M.per_class_pr_auc(y, proba, classes)
    y_attack = np.asarray(y) != M.BENIGN
    return {
        "macro_pr_auc_reliable": M.macro_pr_auc_reliable(per_class, reliable),
        "macro_pr_auc_all": M.macro_pr_auc(per_class),
        "per_class": per_class,
        "pr_auc_binary": M.binary_pr_auc(y_attack, score),
        "binary": M.binary_report(y_attack, score, threshold),
        "n_windows": int(len(y)),
    }


# ================================================================ участники


def fit_lgbm(
    X_fit: np.ndarray,
    y_fit: np.ndarray,
    X_hold: np.ndarray | None,
    y_hold: np.ndarray | None,
    params: dict[str, Any],
    seed: int,
):
    """Конвейер «медиана-заполнение → LightGBM» (R6), ранняя остановка по хвосту train.

    Заполнение обучается отдельно: конвейер sklearn не пропускает eval-набор через свои шаги,
    а LightGBM должен видеть хвост в том же виде, что и train. `keep_empty_features` — иначе
    колонка, целиком пустая в train, молча пропала бы и сдвинула признаки.
    """
    from lightgbm import LGBMClassifier, early_stopping
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline

    params = dict(params)
    rounds = int(params.pop("early_stopping_rounds", 0) or 0)
    imputer = SimpleImputer(strategy="median", keep_empty_features=True).fit(X_fit)
    model = LGBMClassifier(
        deterministic=True,
        force_row_wise=True,
        num_threads=LGBM_THREADS,
        random_state=seed,
        verbose=-1,
        **params,
    )
    kw: dict[str, Any] = {}
    if rounds and X_hold is not None and len(X_hold):
        kw = {
            "eval_set": [(imputer.transform(X_hold), y_hold)],
            "callbacks": [early_stopping(rounds, verbose=False)],
        }
    with warnings.catch_warnings():
        # LightGBM 4.7 объявил eval_set устаревшим в пользу eval_X/eval_y, но в новом пути
        # строковые метки хвоста не кодируются (ValueError «could not convert 'benign'»).
        # Старый путь кодирует их тем же LabelEncoder, что и train, — остаёмся на нём
        warnings.simplefilter("ignore", category=FutureWarning)
        warnings.filterwarnings("ignore", message=".*eval_set.*deprecated.*")
        model.fit(imputer.transform(X_fit), y_fit, **kw)
    return Pipeline([("impute", imputer), ("model", model)])


def current_on_windows(
    model, flows: pl.DataFrame, assignment: pl.DataFrame, windows: pl.DataFrame
) -> tuple[np.ndarray, np.ndarray]:
    """Текущая модель на окнах (R7): вердикты всех потоков → по окну максимум `p_<класс>` по
    каждому классу и максимум `attack_score`. Порядок строк — как у `windows`, столбцов —
    как `model.classes`. «Хоть один поток окна подозрителен» — естественное сведение
    пословной модели к окну; среднее размыло бы одну атаку среди сотни нормальных потоков."""
    classes = model.classes
    v = model.verdict_frame(flows)
    cols = [f"p_{c}" for c in classes]
    agg = (
        assignment.select("flow_uid", "window_id")
        .join(v.select("flow_uid", "attack_score", *cols), on="flow_uid")
        .group_by("window_id")
        .agg([pl.col(c).max() for c in cols] + [pl.col("attack_score").max()])
    )
    aligned = windows.select("window_id").join(agg, on="window_id", how="left")
    return (
        aligned.select(cols).fill_null(0.0).to_numpy().astype(np.float64),
        aligned["attack_score"].fill_null(0.0).to_numpy().astype(np.float64),
    )


# ================================================================ выбор (только val)


def select_nn_vs_boosting(val_metric: dict[str, float], *, min_gain: float, skip_nn: bool) -> dict:
    """Шаг 1 (R8): нейросеть побеждает, только если лучше бустинга на `min_gain` и больше.
    При равном качестве выбирается более простое — бустинг. На вход — ТОЛЬКО метрики val."""
    lgbm = val_metric["lgbm"]
    if skip_nn or "gru" not in val_metric:
        return {
            "winner": "lgbm",
            "gain": None,
            "skipped": True,
            "text": "шаг 1 пропущен (--skip-nn или нет PyTorch): кандидат — бустинг",
        }
    gru = val_metric["gru"]
    gain = gru - lgbm
    if gain >= min_gain:
        text = (
            f"нейросеть лучше бустинга на {gain:+.4f} ({gru:.4f} против {lgbm:.4f}) ≥ {min_gain} "
            "— победитель шага 1: gru"
        )
        return {"winner": "gru", "gain": gain, "skipped": False, "text": text}
    text = (
        f"нейросеть против бустинга {gain:+.4f} ({gru:.4f} против {lgbm:.4f}) < {min_gain} — "
        "при равном качестве выбрано более простое: lgbm"
    )
    return {"winner": "lgbm", "gain": gain, "skipped": False, "text": text}


def select_vs_current(
    winner: str, winner_val: float, current_val: float, *, min_gain: float
) -> dict:
    """Шаг 2 (R8): победитель окон проходит, только если лучше текущей модели на окнах на
    `min_gain`. Иначе — отрицательный результат (FR-010), цепочка не меняется."""
    gain = winner_val - current_val
    if gain >= min_gain:
        text = (
            f"{winner} против текущей модели {gain:+.4f} ({winner_val:.4f} против "
            f"{current_val:.4f}) ≥ {min_gain} — кандидат прошёл выбор, ждёт аудита"
        )
        return {"passed": True, "gain": gain, "text": text}
    text = (
        f"{winner} против текущей модели {gain:+.4f} ({winner_val:.4f} против "
        f"{current_val:.4f}) < {min_gain} — отрицательный результат: окна не дают прироста"
    )
    return {"passed": False, "gain": gain, "text": text}


def final_test_metrics(
    participants: dict[str, dict], y_test: np.ndarray, reliable: list[str], classes: list[str]
) -> dict:
    """Test — один раз и после всех решений: у каждого участника его порог с val."""
    out = {}
    for name, p in participants.items():
        out[name] = evaluate_windows(
            y_test, p["proba_test"], p["score_test"], classes, p["threshold"], reliable
        )
    return out


# ================================================================ данные частей


@dataclass
class Parts:
    train: W.PartWindows
    val: W.PartWindows
    test: W.PartWindows


def _summary(pw: W.PartWindows, windows: pl.DataFrame) -> np.ndarray:
    """Сводные признаки окон части — по сдвигам: вместе четыре сетки train заняли бы ×4
    памяти на промежуточном join (R18)."""
    parts = []
    for s in windows["shift_ms"].unique().sort().to_list():
        a = pw.assignment.filter(pl.col("shift_ms") == s)
        parts.append(W.summary_features(pw.flows, pw.side, a))
    feats = pl.concat(parts)
    return W.summary_matrix(windows, feats)


def _seq(pw: W.PartWindows, windows: pl.DataFrame, cfg: W.WindowsConfig, scaler, y_index):
    from mlsiem.detect.windows_nn import SeqData

    X, mask, scalars = W.sequences(
        pw.flows, pw.side, pw.assignment, windows, seq_max=cfg.seq_max, scaler=scaler
    )
    y = None
    if y_index is not None:
        y = np.array([y_index[c] for c in windows["label"].to_list()], dtype=np.int64)
    return SeqData(X, mask, scalars, y)


def _window_stats(windows: pl.DataFrame) -> dict:
    """Число окон по классам, доли усечённых и смешанных окон (отчёт, edge cases спеки)."""
    attack = windows.filter(pl.col("label") != M.BENIGN)
    return {
        "n_windows": windows.height,
        "by_class": dict(sorted(windows["label"].value_counts().iter_rows())),
        "truncated_share": float(windows["truncated"].mean()) if windows.height else 0.0,
        "mixed_class_share": float((attack["n_attack_classes"] > 1).mean())
        if attack.height
        else 0.0,
        "mixed_benign_share": float((attack["attack_share"] < 1).mean()) if attack.height else 0.0,
        "flows_p50": float(windows["n_flows"].median()) if windows.height else 0.0,
        "flows_p99": float(windows["n_flows"].quantile(0.99)) if windows.height else 0.0,
    }


# ================================================================ эксперимент


def run_windows_experiment(
    cfg: W.WindowsConfig,
    *,
    device: str = "auto",
    skip_nn: bool = False,
    output: Path | None = None,
    mlflow_dir: Path | None = Path("."),
    data_dir: Path = Path("data"),
    reports_dir: Path = Path("reports"),
    direction: str = "auto",
    current_dir: Path | None = None,
    parts: Parts | None = None,
) -> dict:
    """Весь эксперимент US1. Возвращает содержимое experiment.json.

    `mlflow_dir=None` — без MLflow (`--no-mlflow`). `current_dir` и `parts` — для тестов
    (подставить свою текущую модель и уже построенные окна)."""
    from mlsiem.detect.ensemble import load_model

    started_all = time.perf_counter()
    data_dir = Path(data_dir)
    out_dir = Path(output or cfg.output)
    use_nn = not skip_nn and "gru" in cfg.candidates
    if use_nn:
        from mlsiem.detect.windows_nn import device_title, resolve_device

        dev = resolve_device(device)  # нет PyTorch → NNUnavailable ДО какой-либо работы
    else:
        dev = "cpu"
    current_path = Path(current_dir) if current_dir else resolve_current_dir(cfg.current_model)
    current = load_model(current_path)  # битая текущая модель — отказ до построения окон
    data = data_hashes(cfg.split, data_dir)
    version = window_version({**cfg.raw, "direction": direction}, {"split": data})

    # ---- 1. окна
    t0 = time.perf_counter()
    if parts is None:
        log.info("Окна %s: train (сдвиги %s), val, test…", cfg.split, list(cfg.train_shifts_ms))
        mk = lambda part, shifts: W.build_part_windows(  # noqa: E731
            cfg.split, part, cfg, data_dir=data_dir, direction=direction, shifts=shifts
        )
        parts = Parts(mk("train", cfg.train_shifts_ms), mk("val", (0,)), mk("test", (0,)))
    windows_seconds = time.perf_counter() - t0
    tr, va, te = parts.train.windows, parts.val.windows, parts.test.windows
    fit_mask, hold_mask = W.train_holdout_split(tr, cfg.holdout_share, cfg.length_ms)
    tr_fit, tr_hold = tr.filter(pl.Series(fit_mask)), tr.filter(pl.Series(hold_mask))
    y_fit, y_hold = tr_fit["label"].to_numpy(), tr_hold["label"].to_numpy()
    y_val, y_test = va["label"].to_numpy(), te["label"].to_numpy()
    log.info(
        "Окон: train %d (обучение %d, хвост %d), val %d, test %d — %.0f с",
        tr.height,
        tr_fit.height,
        tr_hold.height,
        va.height,
        te.height,
        windows_seconds,
    )
    classes = sorted(set(y_fit.tolist()) | set(y_hold.tolist()))
    if M.BENIGN not in classes:
        raise ValueError("в окнах train нет нормы (benign) — скор атаки не определён")
    eval_classes = sorted(
        set(classes) | set(current.classes) | set(y_val.tolist()) | set(y_test.tolist())
    )
    reliable = M.reliable_classes(y_val, eval_classes, cfg.min_class_windows)
    unreliable = sorted(c for c in set(y_val.tolist()) if c not in reliable)
    log.info("Надёжные классы (≥ %d окон на val): %s", cfg.min_class_windows, reliable)

    participants: dict[str, dict] = {}
    models: dict[str, Any] = {}

    def add(
        name, proba_val, proba_test, cls, score_val, score_test, train_s, predict_s, extra=None
    ):
        pv, pt = (
            align_proba(proba_val, cls, eval_classes),
            align_proba(proba_test, cls, eval_classes),
        )
        thr = M.choose_threshold(y_val != M.BENIGN, score_val)
        participants[name] = {
            "classes": cls,
            "threshold": float(thr),
            "train_seconds": round(train_s, 1),
            "predict_seconds": round(predict_s, 2),
            "proba_val": pv,
            "proba_test": pt,
            "score_val": score_val,
            "score_test": score_test,
            "val": evaluate_windows(y_val, pv, score_val, eval_classes, thr, reliable),
            **(extra or {}),
        }
        log.info(
            "  %s: macro надёжных val %.4f, «атака/нет» val %s, порог %.4f",
            name,
            participants[name]["val"]["macro_pr_auc_reliable"],
            _f(participants[name]["val"]["pr_auc_binary"]),
            thr,
        )

    # ---- 2. бустинг окон
    log.info("Кандидат lgbm: сводные признаки и обучение…")
    t0 = time.perf_counter()
    X_fit, X_hold = _summary(parts.train, tr_fit), _summary(parts.train, tr_hold)
    X_val, X_test = _summary(parts.val, va), _summary(parts.test, te)
    lgbm = fit_lgbm(X_fit, y_fit, X_hold, y_hold, cfg.candidates["lgbm"], cfg.seed)
    train_s = time.perf_counter() - t0
    t0 = time.perf_counter()
    pv, pt = lgbm.predict_proba(X_val), lgbm.predict_proba(X_test)
    cls = [str(c) for c in lgbm.classes_]
    add(
        "lgbm",
        pv,
        pt,
        cls,
        M.attack_score(pv, cls),
        M.attack_score(pt, cls),
        train_s,
        time.perf_counter() - t0,
        {"best_iteration": int(getattr(lgbm.named_steps["model"], "best_iteration_", 0) or 0)},
    )
    models["lgbm"] = lgbm
    del X_fit, X_hold
    gc.collect()

    # ---- 3. нейросеть окон
    gru_hist = None
    if use_nn:
        from mlsiem.detect.windows_nn import n_parameters, predict_gru, train_gru

        log.info("Кандидат gru: последовательности и обучение на %s…", dev)
        t0 = time.perf_counter()
        scaler = W.fit_seq_scaler(parts.train.flows, cfg.length_ms)
        y_index = {c: i for i, c in enumerate(classes)}
        fit_data = _seq(parts.train, tr_fit, cfg, scaler, y_index)
        hold_data = _seq(parts.train, tr_hold, cfg, scaler, y_index)
        seq_seconds = time.perf_counter() - t0
        net, gru_hist = train_gru(
            fit_data, hold_data, len(classes), cfg.candidates["gru"], seed=cfg.seed, device=dev
        )
        del fit_data, hold_data
        gc.collect()
        train_s = time.perf_counter() - t0
        t0 = time.perf_counter()
        val_data, test_data = (
            _seq(parts.val, va, cfg, scaler, None),
            _seq(parts.test, te, cfg, scaler, None),
        )
        pv = predict_gru(net, val_data, device=dev)
        pt = predict_gru(net, test_data, device=dev)
        add(
            "gru",
            pv,
            pt,
            classes,
            M.attack_score(pv, classes),
            M.attack_score(pt, classes),
            train_s,
            time.perf_counter() - t0,
            {
                "epochs": gru_hist.epochs,
                "best_epoch": gru_hist.best_epoch,
                "n_parameters": n_parameters(net),
                "peak_vram_mb": gru_hist.peak_vram_mb,
                "sequence_seconds": round(seq_seconds, 1),
                "train_loss": [round(x, 5) for x in gru_hist.train_loss],
                "holdout_loss": [round(x, 5) for x in gru_hist.holdout_loss],
            },
        )
        models["gru"] = (net, scaler)
        del val_data, test_data
        gc.collect()

    # ---- 4. текущая модель на окнах
    log.info("Текущая модель (%s) на окнах val и test…", current.describe())
    t0 = time.perf_counter()
    pv, sv = current_on_windows(current, parts.val.flows, parts.val.assignment, va)
    pt, st = current_on_windows(current, parts.test.flows, parts.test.assignment, te)
    add(
        "current",
        pv,
        pt,
        list(current.classes),
        sv,
        st,
        0.0,
        time.perf_counter() - t0,
        {"model": current.summary()},
    )

    # ---- 5. выбор — только val
    val_metric = {n: p["val"]["macro_pr_auc_reliable"] for n, p in participants.items()}
    step1 = select_nn_vs_boosting(
        {k: v for k, v in val_metric.items() if k != "current"},
        min_gain=cfg.min_gain,
        skip_nn=not use_nn,
    )
    winner = step1["winner"]
    step2 = select_vs_current(
        winner, val_metric[winner], val_metric["current"], min_gain=cfg.min_gain
    )
    log.info("Шаг 1: %s", step1["text"])
    log.info("Шаг 2: %s", step2["text"])

    # ---- 6. test — один раз, после решений
    test = final_test_metrics(participants, y_test, reliable, eval_classes)
    for name in participants:
        participants[name]["test"] = test[name]

    # ---- 7. артефакт победителя, протокол, отчёт, MLflow
    win = participants[winner]
    selection_reason = step1["text"] + "; " + step2["text"]
    decision = {
        "accepted": False,
        "passed_selection": step2["passed"],
        "step": "vs_current",
        "metric": cfg.metric,
        "reliable_classes": reliable,
        "values": {n: round(float(v), 6) for n, v in val_metric.items()},
        "min_gain": cfg.min_gain,
        "audit_verdict": "not_run",
        "step1": step1["text"],
        "step2": step2["text"],
        "selection_reason": selection_reason,
        "reason": (
            "прошёл выбор, ждёт аудита (`mlsiem detect windows-audit`)"
            if step2["passed"]
            else step2["text"]
        ),
    }
    device_name = device_title(dev) if use_nn else "cpu"
    card = {
        "window_version": version,
        "kind": winner,
        "classes": classes,
        "threshold": win["threshold"],
        "window": {
            "length_ms": cfg.length_ms,
            "key": "attacker_ip",
            "direction": direction,
            "seq_max": cfg.seq_max,
        },
        "summary_features": W.summary_feature_names(),
        "seq_features": W.seq_feature_names(),
        "schema_version": SCHEMA.version,
        "decision": decision,
        "current_model": {
            "kind": current.kind,
            "version": current.version,
            "path": current_path.as_posix(),
        },
        "data": {"split": cfg.split, **data},
        "seed": cfg.seed,
        "device": device_name if winner == "gru" else "cpu",
        "libraries": library_versions(),
    }
    if winner == "gru":
        net, scaler = models["gru"]
        card["gru_params"] = dict(cfg.candidates["gru"])
        save_window_expert(out_dir, kind="gru", model=net, preprocess={"scaler": scaler}, card=card)
    else:
        save_window_expert(out_dir, kind="lgbm", model=models["lgbm"], preprocess={}, card=card)

    exp = {
        "window_version": version,
        "split": cfg.split,
        "seed": cfg.seed,
        "direction": direction,
        "config": cfg.raw,
        "data": card["data"],
        "device": device_name,
        "classes": classes,
        "eval_classes": eval_classes,
        "reliable_classes": reliable,
        "unreliable_classes": unreliable,
        "min_class_windows": cfg.min_class_windows,
        "windows": {
            "train": {**_window_stats(tr), "fit": tr_fit.height, "holdout": tr_hold.height},
            "train_main_grid": _window_stats(tr.filter(pl.col("shift_ms") == 0)),
            "val": _window_stats(va),
            "test": _window_stats(te),
            "seconds": round(windows_seconds, 1),
        },
        "participants": {
            n: {k: v for k, v in p.items() if not k.startswith(("proba_", "score_"))}
            for n, p in participants.items()
        },
        "selection": {"step1": step1, "step2": step2, "winner": winner, "min_gain": cfg.min_gain},
        "decision": decision,
        "current_model": card["current_model"],
        "repro_tolerance": REPRO_TOLERANCE,
        "seconds_total": round(time.perf_counter() - started_all, 1),
        "peak_memory_mb": peak_memory_mb(),
        "libraries": card["libraries"],
    }
    if mlflow_dir is not None:
        exp["mlflow_runs"] = _log_mlflow(mlflow_dir, exp, cfg, version)
    with atomic_path(out_dir / EXPERIMENT_FILE) as tmp:
        tmp.write_text(
            json.dumps(exp, ensure_ascii=False, indent=2, default=_jsonable) + "\n",
            encoding="utf-8",
        )
    with atomic_path(Path(reports_dir) / REPORT_NAME) as tmp:
        tmp.write_text(render_windows_report(exp), encoding="utf-8")
    log.info("Модель окон %s (%s) сохранена в %s", version, winner, out_dir)
    return json.loads(json.dumps(exp, default=_jsonable))


def _jsonable(obj):
    if isinstance(obj, np.generic):
        return obj.item()
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, Path):
        return obj.as_posix()
    raise TypeError(f"не сериализуется в JSON: {type(obj)}")


def _flat(prefix: str, ev: dict) -> dict[str, float]:
    out = {
        f"{prefix}_macro_pr_auc_reliable": ev["macro_pr_auc_reliable"],
        f"{prefix}_macro_pr_auc_all": ev["macro_pr_auc_all"],
    }
    if ev["pr_auc_binary"] is not None:
        out[f"{prefix}_pr_auc_binary"] = ev["pr_auc_binary"]
    out.update({f"{prefix}_pr_auc_{c}": v for c, v in ev["per_class"].items() if v is not None})
    out.update({f"{prefix}_{k}": v for k, v in ev["binary"].items() if v is not None})
    return {k: float(v) for k, v in out.items() if v == v}  # NaN MLflow не принимает


def _log_mlflow(mlflow_dir: Path, exp: dict, cfg: W.WindowsConfig, version: str) -> dict[str, str]:
    """Три запуска MLflow-эксперимента `windows` (R17): конфиг, версия данных, сид, устройство."""
    from mlsiem.detect.experiment import _setup_mlflow, git_commit

    mlflow = _setup_mlflow(Path(mlflow_dir), MLFLOW_EXPERIMENT)
    commit = git_commit() or ""
    ids = {}
    for name, p in exp["participants"].items():
        with mlflow.start_run(run_name=name) as run:
            params = cfg.candidates.get(name, {"aggregate": cfg.current_aggregate})
            mlflow.log_params(
                {
                    **{str(k): v for k, v in params.items()},
                    "participant": name,
                    "seed": cfg.seed,
                    "split": cfg.split,
                    "length_ms": cfg.length_ms,
                    "seq_max": cfg.seq_max,
                    "direction": exp["direction"],
                }
            )
            mlflow.log_metrics(
                {
                    **_flat("val", p["val"]),
                    **_flat("test", p["test"]),
                    "threshold": p["threshold"],
                    "train_seconds": p["train_seconds"],
                    "predict_seconds": p["predict_seconds"],
                }
            )
            mlflow.set_tags(
                {
                    "split_hash": exp["data"]["split_hash"],
                    "schema_version": SCHEMA.version,
                    "window_version": version,
                    "device": exp["device"] if name == "gru" else "cpu",
                    "git_commit": commit,
                    "winner": str(name == exp["selection"]["winner"]),
                }
            )
            mlflow.log_dict({"config": cfg.raw, "data": exp["data"]}, "data_and_config.json")
            ids[name] = run.info.run_id
    return ids


# ================================================================ отчёт


def _f(v) -> str:
    return "—" if v is None or v != v else f"{v:.4f}"


def _p(v) -> str:
    return "—" if v is None else f"{v:.1%}"


def render_windows_report(exp: dict) -> str:
    """Markdown-отчёт: читается в репозитории без MLflow, позволяет проверить решение по
    цифрам val без пересчёта (SC-002)."""
    parts = exp["participants"]
    order = [n for n in ("lgbm", "gru", "current") if n in parts]
    sel, dec = exp["selection"], exp["decision"]
    w = exp["windows"]
    lines = [
        "# Эксперимент окон (фича 007): бустинг против нейросети против текущей модели",
        "",
        f"- Версия модели окон: `{exp['window_version']}`; сохранён победитель `{sel['winner']}`",
        f"- Разбиение: `{exp['split']}` (hash `{exp['data']['split_hash'][:12]}…`), сид "
        f"{exp['seed']}, правило направления `{exp['direction']}`",
        f"- Окно: {exp['config']['window']['length_ms']} мс, последовательность ≤ "
        f"{exp['config']['window']['seq_max']} потоков, сдвиги train "
        f"{exp['config']['window']['train_shifts_ms']} мс",
        f"- Текущая модель: {exp['current_model']['kind']} `{exp['current_model']['version']}`",
        f"- Устройство: {exp['device']}; всего {exp['seconds_total']} с, пиковая память процесса "
        f"{exp['peak_memory_mb']} МБ",
        "- Метрика выбора: macro PR-AUC надёжных классов на val "
        f"(надёжный — ≥ {exp['min_class_windows']} окон на val): "
        f"{', '.join(exp['reliable_classes'])}",
        "",
        "## Участники",
        "",
        "| Участник | macro надёжных val | macro надёжных test | macro всех val | macro всех test "
        "| атака/нет val | атака/нет test | порог | precision test | recall test | обучение, с "
        "| предсказание, с |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for n in order:
        p = parts[n]
        v, t = p["val"], p["test"]
        lines.append(
            f"| {TITLES[n]} | {_f(v['macro_pr_auc_reliable'])} | {_f(t['macro_pr_auc_reliable'])} "
            f"| {_f(v['macro_pr_auc_all'])} | {_f(t['macro_pr_auc_all'])} "
            f"| {_f(v['pr_auc_binary'])} "
            f"| {_f(t['pr_auc_binary'])} | {p['threshold']:.4f} | {_f(t['binary']['precision'])} "
            f"| {_f(t['binary']['recall'])} | {p['train_seconds']} | {p['predict_seconds']} |"
        )
    lines += [
        "",
        "## Решение по шагам (только val)",
        "",
        f"1. **Нейросеть против бустинга**: {sel['step1']['text']}.",
        f"2. **Победитель против текущей модели**: {sel['step2']['text']}.",
        "3. **Аудит на артефакты**: ещё не выполнялся (`mlsiem detect windows-audit`); принять "
        "модель в цепочку может только он (FR-012).",
        "",
        f"Итог: `accepted = {str(dec['accepted']).lower()}`, прошёл выбор — "
        f"{'да' if dec['passed_selection'] else 'нет'}. {dec['reason']}.",
        "",
        "## PR-AUC по классам",
        "",
        "Классы с меньше чем "
        f"{exp['min_class_windows']} окнами на val помечены «ненадёжен»: их PR-AUC почти "
        "случаен и в выбор не входит.",
        "",
        "| Класс | окон val | окон test | "
        + " | ".join(f"{n} val | {n} test" for n in order)
        + " |",
        "|---|---|---|" + "---|" * (2 * len(order)),
    ]
    for c in exp["eval_classes"]:
        mark = "" if c in exp["reliable_classes"] else " (ненадёжен)"
        cells = []
        for n in order:
            cells += [
                _f(parts[n]["val"]["per_class"].get(c)),
                _f(parts[n]["test"]["per_class"].get(c)),
            ]
        lines.append(
            f"| {c}{mark} | {w['val']['by_class'].get(c, 0)} | {w['test']['by_class'].get(c, 0)} | "
            + " | ".join(cells)
            + " |"
        )
    lines += [
        "",
        "## Окна",
        "",
        "| Часть | окон | атакующих | усечённых (> seq_max) | смешанных: несколько классов "
        "| смешанных: атака + норма | потоков p50 / p99 |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, key in (
        ("train (все сетки)", "train"),
        ("train (основная)", "train_main_grid"),
        ("val", "val"),
        ("test", "test"),
    ):
        s = w[key]
        attack = s["n_windows"] - s["by_class"].get(M.BENIGN, 0)
        lines.append(
            f"| {name} | {s['n_windows']} | {attack} | {_p(s['truncated_share'])} | "
            f"{_p(s['mixed_class_share'])} | {_p(s['mixed_benign_share'])} | "
            f"{s['flows_p50']:.0f} / {s['flows_p99']:.0f} |"
        )
    lines += [
        "",
        f"Train: обучение {w['train']['fit']} окон, отложенный хвост {w['train']['holdout']} "
        "(ранняя остановка обеих моделей окон; val в ней не участвует). Построение окон — "
        f"{w['seconds']} с.",
    ]
    if "gru" in parts:
        g = parts["gru"]
        vram = "—" if g["peak_vram_mb"] is None else f"{g['peak_vram_mb']:.0f}"
        lines += [
            "",
            "## Нейросеть",
            "",
            f"Параметров {g['n_parameters']}; эпох {g['epochs']}, лучшая {g['best_epoch']}; "
            f"последовательности {g['sequence_seconds']} с; пиковая видеопамять {vram} МБ.",
        ]
    lines += [
        "",
        "## Воспроизводимость",
        "",
        f"Повтор с тем же сидом: macro бустинга совпадает до {REPRO_TOLERANCE['lgbm']} "
        f"(LightGBM deterministic), нейросети — в пределах {REPRO_TOLERANCE['gru']} (часть "
        "операций cuDNN на видеокарте недетерминирована).",
    ]
    return "\n".join(lines) + "\n"
