"""Проверка модели окон на артефакты и перенос (фича 007, US2, research R10, FR-012).

Зачем. Эксперимент US1 выбрал победителя по val, но «хорошие цифры» на UNSW-NB15 ещё ничего
не доказывают: норму и атаки там генерировали разные инструменты, и модель может узнавать
«почерк генератора» вместо поведения атаки (так в v1 автокодировщик получил «ROC-AUC 0.98»).
Поэтому принять модель окон в цепочку может только этот аудит. Он проверяет:

1. **состав входов** — среди признаков нет адресов, значений портов, идентификаторов и
   абсолютного времени (FR-004); то же проверяет тест `test_windows_forbidden.py`, но отчёт
   должен говорить это сам;
2. **важность** — на что модель реально опирается: у бустинга перестановочная важность
   сводных признаков (`audit_models`), у нейросети — групповая перестановка канала признака
   сразу по всем потокам окна;
3. **одиночные признаки** — какой признак в одиночку даёт почти всё качество модели;
4. **повтор без подозрительных** — модель переобучается тем же протоколом без полей,
   помеченных аудитом данных 001, и без «слишком сильных» одиночных признаков. Если метрика
   выбора на val падает на `audit.max_drop` и больше — вердикт «опирается на артефакты»;
5. **перенос** — победитель без переобучения на test `unsw_cross_day` (с оговоркой 002:
   эта часть пересекается по времени с train `unsw_time`, цифры завышены);
6. **разброс по атакующим адресам** — полнота атакующих окон по каждому адресу. Атакующих в
   UNSW мало (175.45.176.0/24), и сильный перекос значит «узнаёт одного генератора».

Вердикт определяется ТОЛЬКО пунктом 4 (он на val). Перенос и разброс — факты для владельца:
на test решения не принимаются (принцип III). Текущая модель на окнах проходит пункты 5 и 6
для сравнения — её собственный аудит был в 004.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from mlsiem.data.schema import SCHEMA
from mlsiem.detect import metrics as M
from mlsiem.detect import windows as W
from mlsiem.detect.audit_models import permutation_importance_score, single_feature_probe
from mlsiem.detect.windows_experiment import (
    align_proba,
    current_on_windows,
    evaluate_windows,
    fit_lgbm,
)

log = logging.getLogger("mlsiem")

REPORT_NAME = "windows_audit.md"
TOP = 10
# Статусы аудита данных 001, которые НЕ считаются подозрением: `ok` — поле чистое, `n/a` —
# поле не оценивалось (в val меньше двух классов). Считать `n/a` подозрением нельзя: тогда на
# маленьком разбиении подозрительным оказалось бы всё, и «повтор без подозрительных» учился
# бы на пустом входе
DATA_AUDIT_CLEAN = ("ok", "n/a")
TRANSFER_CAVEAT = (
    "оговорка 002: test unsw_cross_day — вторая половина дня 17-2, а train unsw_time содержит "
    "его начало; части пересекаются по времени и генератору, поэтому перенос завышен и "
    "показывает скорее «не сломалась ли модель на соседних данных», чем обобщение"
)


# ================================================================ состав входов (FR-004)


def forbidden_inputs(names: list[str]) -> list[str]:
    """Признаки, похожие на адрес, порт-значение, идентификатор или абсолютное время.

    Правило то же, что в `tests/unit/test_windows_forbidden.py`: запрещённое берётся из групп
    схемы 001 (key, identity, time, dpi, label), а не пишется руками."""
    forbidden = {
        *SCHEMA.columns_of("key"),
        *SCHEMA.columns_of("identity"),
        *SCHEMA.columns_of("time"),
        *SCHEMA.columns_of("dpi"),
        *SCHEMA.columns_of("label"),
        "id",
    }
    patterns = [re.compile(p) for p in (r"_ip$", r"_ip_", r"first_seen_ms", r"last_seen_ms")]
    return [n for n in names if base_feature(n) in forbidden or any(p.search(n) for p in patterns)]


def base_feature(name: str) -> str:
    """`f_<признак>_mean` → `<признак>`: сводный признак окна — статистика признака схемы.
    Поведенческие признаки окна (`w_…`) и каналы последовательности возвращаются как есть."""
    for suffix in ("_mean", "_max", "_std"):
        if name.startswith("f_") and name.endswith(suffix):
            return name[2 : -len(suffix)]
    return name


# ================================================================ подозрительные признаки


def data_audit_fields(split: str, data_dir: Path) -> dict:
    """Поля, помеченные аудитом данных 001 (`data/audit/<split>.parquet`), и их статусы.

    Файла нет (аудит 001 не запускали) — это не ошибка аудита модели, но в отчёте об этом
    сказано прямо: пункт 4 тогда опирается только на одиночные признаки."""
    path = Path(data_dir) / "audit" / f"{split}.parquet"
    if not path.exists():
        return {"found": False, "path": path.as_posix(), "fields": []}
    df = pl.read_parquet(path, columns=["field", "variant", "status"])
    flagged = df.filter(~pl.col("status").is_in(list(DATA_AUDIT_CLEAN)))
    fields = [
        {"field": f, "variant": v, "status": s}
        for f, v, s in flagged.select("field", "variant", "status").iter_rows()
    ]
    return {"found": True, "path": path.as_posix(), "fields": fields}


def window_features_of(fields: list[str], names: list[str]) -> list[str]:
    """Признаки модели окон, построенные из полей `fields`: у сводных — все три статистики
    поля, у последовательности — сам канал. Поле, которого во входе нет (например, DPI-поле
    `requested_server_name`), ничего не даёт: модель окон его и так не видит."""
    wanted = set(fields)
    return [n for n in names if base_feature(n) in wanted]


def _fill_nan(X: np.ndarray) -> np.ndarray:
    """Пропуски → медиана столбца (для зонда: `average_precision_score` не принимает NaN).
    Пропуски в сводных признаках — интервалы окна из одного потока, их и конвейер модели
    закрывает медианой."""
    X = np.array(X, dtype=np.float64, copy=True)
    med = np.nanmedian(np.where(np.isnan(X).all(axis=0), 0.0, X), axis=0)
    rows, cols = np.nonzero(np.isnan(X))
    X[rows, cols] = med[cols]
    return X


# ================================================================ важность нейросети


def group_permutation_importance(
    score_fn,
    seq,
    y_attack: np.ndarray,
    channels: list[str],
    *,
    seed: int,
    top: int = TOP,
) -> dict:
    """Групповая перестановка для GRU (R10): канал признака перемешивается между окнами
    целиком — сразу по всем потокам окна. Перемешивать по отдельным потокам бессмысленно:
    нейросеть смотрит на форму последовательности, и порча одного шага её почти не задевает.

    Паддинг остаётся паддингом (значения за маской обнуляются): иначе перестановка добавила
    бы «потоки», которых не было, и падение метрики было бы не про признак.
    """
    from mlsiem.detect.windows_nn import SeqData

    rng = np.random.default_rng(seed)
    y = np.asarray(y_attack, dtype=bool)
    base = M.binary_pr_auc(y, score_fn(seq))
    if base is None:
        return {"base_pr_auc": None, "n_rows": len(seq), "top": []}
    drops = []
    for j, name in enumerate(channels):
        X = seq.X.copy()
        X[:, :, j] = seq.X[rng.permutation(len(seq)), :, j] * seq.mask
        value = M.binary_pr_auc(y, score_fn(SeqData(X, seq.mask, seq.scalars)))
        drops.append({"feature": name, "drop": float(base - (value or 0.0))})
    drops.sort(key=lambda r: (-r["drop"], r["feature"]))
    return {"base_pr_auc": float(base), "n_rows": len(seq), "top": drops[:top]}


# ================================================================ полнота по атакующим


def recall_by_attacker(windows: pl.DataFrame, score: np.ndarray, threshold: float) -> dict:
    """Полнота атакующих окон по каждому атакующему адресу (R10 п. 6).

    Строки — адреса, у которых есть хоть одно окно-атака: сколько таких окон, сколько поймано
    на пороге модели, полнота. Итог — разброс полноты (мин./макс.) по адресам с ≥ 5 окнами:
    по адресу с одним-двумя окнами полнота 0 или 1 ничего не говорит."""
    df = windows.select("attacker_ip", "label").with_columns(
        pl.Series("caught", np.asarray(score) >= threshold)
    )
    rows = (
        df.filter(pl.col("label") != M.BENIGN)
        .group_by("attacker_ip")
        .agg(pl.len().alias("n_attack_windows"), pl.col("caught").sum().alias("caught"))
        .with_columns((pl.col("caught") / pl.col("n_attack_windows")).alias("recall"))
        .sort(["n_attack_windows", "attacker_ip"], descending=[True, False])
    )
    stable = rows.filter(pl.col("n_attack_windows") >= 5)
    return {
        "rows": [
            {
                "attacker_ip": ip,
                "n_attack_windows": int(n),
                "caught": int(c),
                "recall": round(float(r), 4),
            }
            for ip, n, c, r in rows.iter_rows()
        ],
        "min_recall": float(stable["recall"].min()) if stable.height else None,
        "max_recall": float(stable["recall"].max()) if stable.height else None,
        "n_attackers": rows.height,
    }


# ================================================================ аудит


def _part(cfg: W.WindowsConfig, split: str, part: str, data_dir: Path, direction: str, shifts):
    return W.build_part_windows(
        split, part, cfg, data_dir=data_dir, direction=direction, shifts=shifts
    )


def _retrain_lgbm(
    cfg: W.WindowsConfig,
    train: W.PartWindows,
    X_val: np.ndarray,
    y_val: np.ndarray,
    keep: list[int],
    eval_classes: list[str],
    reliable: list[str],
) -> dict:
    """Бустинг заново тем же протоколом (хвост train, те же параметры, тот же сид), но только
    на столбцах `keep`. Возвращает метрики val без подозрительных признаков."""
    from mlsiem.detect.windows_experiment import _summary

    tr = train.windows
    fit_mask, hold_mask = W.train_holdout_split(tr, cfg.holdout_share, cfg.length_ms)
    tr_fit, tr_hold = tr.filter(pl.Series(fit_mask)), tr.filter(pl.Series(hold_mask))
    X_fit = _summary(train, tr_fit)[:, keep]
    X_hold = _summary(train, tr_hold)[:, keep]
    model = fit_lgbm(
        X_fit,
        tr_fit["label"].to_numpy(),
        X_hold,
        tr_hold["label"].to_numpy(),
        cfg.candidates["lgbm"],
        cfg.seed,
    )
    proba = model.predict_proba(X_val[:, keep])
    cls = [str(c) for c in model.classes_]
    score = M.attack_score(proba, cls)
    thr = M.choose_threshold(y_val != M.BENIGN, score)
    pv = align_proba(proba, cls, eval_classes)
    return evaluate_windows(y_val, pv, score, eval_classes, thr, reliable)


def _retrain_gru(
    cfg: W.WindowsConfig,
    expert,
    train: W.PartWindows,
    val_seq,
    y_val: np.ndarray,
    drop_channels: list[int],
    eval_classes: list[str],
    reliable: list[str],
    device: str,
) -> dict:
    """GRU заново тем же протоколом, но с обнулёнными каналами `drop_channels` во всех частях
    (обнулённый канал — то же, что его отсутствие: после стандартизации 0 — «среднее»)."""
    from mlsiem.detect.windows_experiment import _seq
    from mlsiem.detect.windows_nn import SeqData, predict_gru, train_gru

    classes = expert.classes
    scaler = expert.preprocess["scaler"]
    y_index = {c: i for i, c in enumerate(classes)}
    tr = train.windows
    fit_mask, hold_mask = W.train_holdout_split(tr, cfg.holdout_share, cfg.length_ms)
    fit = _seq(train, tr.filter(pl.Series(fit_mask)), cfg, scaler, y_index)
    hold = _seq(train, tr.filter(pl.Series(hold_mask)), cfg, scaler, y_index)
    for data in (fit, hold):
        data.X[:, :, drop_channels] = 0.0
    params = expert.card.get("gru_params") or cfg.candidates["gru"]
    net, _ = train_gru(fit, hold, len(classes), params, seed=cfg.seed, device=device)
    X = val_seq.X.copy()
    X[:, :, drop_channels] = 0.0
    proba = predict_gru(net, SeqData(X, val_seq.mask, val_seq.scalars), device=device)
    score = M.attack_score(proba, classes)
    thr = M.choose_threshold(y_val != M.BENIGN, score)
    pv = align_proba(proba, classes, eval_classes)
    return evaluate_windows(y_val, pv, score, eval_classes, thr, reliable)


def audit_window_model(
    expert,
    exp: dict,
    cfg: W.WindowsConfig,
    *,
    data_dir: Path = Path("data"),
    device: str = "cpu",
    current=None,
) -> dict:
    """Весь аудит R10 для модели окон `expert` (загружена с `force=True`) и текущей модели.

    `exp` — протокол эксперимента (`experiment.json`): из него берутся разбиение, правило
    направления, классы оценки, надёжные классы и порог текущей модели — аудит смотрит на
    модель в тех же условиях, в каких её выбирали. `current` — для тестов (подставить свою
    текущую модель); по умолчанию грузится та, с которой сравнивал эксперимент."""
    from mlsiem.detect.ensemble import load_model

    started = time.perf_counter()
    data_dir = Path(data_dir)
    direction = exp["direction"]
    split = exp["split"]
    eval_classes = list(exp["eval_classes"])
    reliable = list(exp["reliable_classes"])
    if current is None:
        current = load_model(Path(exp["current_model"]["path"]))
    current_thr = float(exp["participants"]["current"]["threshold"])
    kind = expert.kind
    summary_names = list(expert.card["summary_features"])
    seq_names = list(expert.card["seq_features"])

    # ---- 1. состав входов
    names = summary_names if kind == "lgbm" else seq_names
    inputs = {
        "kind": kind,
        "n_features": len(names),
        "forbidden": forbidden_inputs(names),
        "features_family": "сводные признаки окна"
        if kind == "lgbm"
        else "каналы последовательности потоков",
    }

    # ---- val: база модели
    log.info("Аудит %s: окна val %s…", expert.describe(), split)
    val = _part(cfg, split, "val", data_dir, direction, (0,))
    va = val.windows
    y_val = va["label"].to_numpy()
    y_attack = y_val != M.BENIGN
    X_val = W.summary_matrix(va, W.summary_features(val.flows, val.side, val.assignment))
    val_seq = None
    if kind == "lgbm":
        proba_val = expert.model.predict_proba(X_val)

        def score_summary(X):
            return M.attack_score(expert.model.predict_proba(X), expert.classes)

    else:
        from mlsiem.detect.windows_experiment import _seq
        from mlsiem.detect.windows_nn import predict_gru

        val_seq = _seq(val, va, cfg, expert.preprocess["scaler"], None)
        proba_val = predict_gru(expert.model, val_seq, device=device)
    score_val = M.attack_score(proba_val, expert.classes)
    base = evaluate_windows(
        y_val,
        align_proba(proba_val, expert.classes, eval_classes),
        score_val,
        eval_classes,
        expert.threshold,
        reliable,
    )
    base_binary = base["pr_auc_binary"]
    log.info(
        "  база: macro надёжных val %.4f, «атака/нет» val %s",
        base["macro_pr_auc_reliable"],
        "—" if base_binary is None else f"{base_binary:.4f}",
    )

    # ---- 2. важность
    log.info("  важность признаков…")
    if kind == "lgbm":
        importance = permutation_importance_score(
            score_summary, X_val, y_attack, summary_names, seed=cfg.seed, top=TOP
        )
        importance["method"] = "перестановка сводного признака (permutation importance)"
    else:
        from mlsiem.detect.windows_nn import predict_gru

        importance = group_permutation_importance(
            lambda s: M.attack_score(predict_gru(expert.model, s, device=device), expert.classes),
            val_seq,
            y_attack,
            seq_names,
            seed=cfg.seed,
        )
        importance["method"] = "групповая перестановка канала по всем потокам окна"

    # ---- 3. одиночные признаки: какой один даёт ≥ share качества модели
    flag_at = cfg.single_feature_share * (base_binary or 0.0)
    probe = (
        single_feature_probe(_fill_nan(X_val), y_attack, summary_names, flag_at=flag_at)
        if base_binary is not None
        else []
    )
    single_flagged = [r["feature"] for r in probe if r["flagged"]]

    # ---- 4. повтор без подозрительных
    d_audit = data_audit_fields(split, data_dir)
    audit_field_names = sorted({f["field"] for f in d_audit["fields"]})
    from_data_audit = window_features_of(audit_field_names, summary_names)
    suspicious_summary = sorted(set(from_data_audit) | set(single_flagged))
    if kind == "lgbm":
        removed = suspicious_summary
    else:
        # Нейросеть видит каналы потоков, а не сводные статистики: подозрительный сводный
        # признак f_<поле>_<стат> снимает канал <поле>. Поведенческие признаки окна (w_…) у
        # нейросети каналом не являются — их в отчёте видно, но убрать из входа нечего
        bases = {base_feature(n) for n in suspicious_summary}
        removed = [c for c in seq_names if c in bases]
    retrain: dict[str, Any] = {"done": False, "removed": removed}
    if removed:
        log.info("  повтор без %d подозрительных признаков: %s…", len(removed), removed[:5])
        train = _part(cfg, split, "train", data_dir, direction, cfg.train_shifts_ms)
        if kind == "lgbm":
            keep = [i for i, n in enumerate(summary_names) if n not in set(removed)]
            without = _retrain_lgbm(cfg, train, X_val, y_val, keep, eval_classes, reliable)
        else:
            drop = [seq_names.index(c) for c in removed]
            without = _retrain_gru(
                cfg, expert, train, val_seq, y_val, drop, eval_classes, reliable, device
            )
        del train
        drop_value = base["macro_pr_auc_reliable"] - without["macro_pr_auc_reliable"]
        retrain.update(
            {
                "done": True,
                "macro_pr_auc_reliable_val": without["macro_pr_auc_reliable"],
                "pr_auc_binary_val": without["pr_auc_binary"],
                "per_class_val": without["per_class"],
                "drop": float(drop_value),
            }
        )
    else:
        retrain["drop"] = 0.0
    drop = retrain["drop"]
    verdict = "relies_on_artifacts" if drop >= cfg.max_drop or inputs["forbidden"] else "clean"
    text = _verdict_text(verdict, retrain, inputs, cfg.max_drop)

    # ---- 5. перенос (без переобучения; только факты, вердикт от него не зависит)
    log.info("  перенос на test %s…", cfg.transfer_split)
    transfer = transfer_eval(
        expert,
        cfg,
        data_dir=data_dir,
        direction=direction,
        current=current,
        current_threshold=current_thr,
        device=device,
    )

    # ---- 6. полнота по атакующим адресам: val и test основного разбиения
    log.info("  полнота по атакующим адресам…")
    test = _part(cfg, split, "test", data_dir, direction, (0,))
    per_attacker: dict[str, dict] = {"winner": {}, "current": {}}
    for name, pw, score in (("val", val, score_val), ("test", test, None)):
        if score is None:
            score = M.attack_score(
                expert.proba(pw.flows, pw.side, pw.assignment, pw.windows)[0], expert.classes
            )
        per_attacker["winner"][name] = recall_by_attacker(pw.windows, score, expert.threshold)
        _, cur_score = current_on_windows(current, pw.flows, pw.assignment, pw.windows)
        per_attacker["current"][name] = recall_by_attacker(pw.windows, cur_score, current_thr)

    return {
        "model": {"window_version": expert.version, "kind": kind},
        "current_model": exp["current_model"],
        "split": split,
        "direction": direction,
        "reliable_classes": reliable,
        "verdict": verdict,
        "text": text,
        "max_drop": cfg.max_drop,
        "single_feature_share": cfg.single_feature_share,
        "inputs": inputs,
        "base": {
            "macro_pr_auc_reliable_val": base["macro_pr_auc_reliable"],
            "pr_auc_binary_val": base_binary,
            "per_class_val": base["per_class"],
        },
        "importance": importance,
        "single_feature": {"flag_at": flag_at, "top": probe[:TOP], "flagged": single_flagged},
        "data_audit": {**d_audit, "window_features": from_data_audit},
        "suspicious": suspicious_summary,
        "retrain": retrain,
        "transfer": transfer,
        "per_attacker": per_attacker,
        "seconds": round(time.perf_counter() - started, 1),
    }


def _verdict_text(verdict: str, retrain: dict, inputs: dict, max_drop: float) -> str:
    """Одна фраза вердикта — для карточки (`decision.reason`) и отчёта."""
    if inputs["forbidden"]:
        return f"во входе запрещённые признаки: {', '.join(inputs['forbidden'])}"
    if not retrain["done"]:
        return (
            "подозрительных признаков нет (аудит данных 001 и одиночные признаки чисты) — "
            "повтор не требуется, вердикт clean"
        )
    removed = len(retrain["removed"])
    if verdict == "clean":
        return (
            f"без {removed} подозрительных признаков macro надёжных val падает на "
            f"{retrain['drop']:+.4f} < {max_drop} — модель опирается не на них"
        )
    return (
        f"без {removed} подозрительных признаков macro надёжных val падает на "
        f"{retrain['drop']:+.4f} ≥ {max_drop} — модель опирается на артефакты"
    )


def transfer_eval(
    expert,
    cfg: W.WindowsConfig,
    *,
    data_dir: Path = Path("data"),
    direction: str = "auto",
    current=None,
    current_threshold: float | None = None,
    device: str = "cpu",
) -> dict:
    """Перенос (R10 п. 5): победитель без переобучения на test `transfer_split`, рядом —
    текущая модель на тех же окнах. Надёжные классы считаются по самим окнам переноса тем же
    правилом (`min_class_windows`): набор классов там другой."""
    tp = _part(cfg, cfg.transfer_split, "test", data_dir, direction, (0,))
    y = tp.windows["label"].to_numpy()
    classes = sorted(set(expert.classes) | set(y.tolist()))
    reliable = M.reliable_classes(y, classes, cfg.min_class_windows)
    proba, _ = expert.proba(tp.flows, tp.side, tp.assignment, tp.windows)
    score = M.attack_score(proba, expert.classes)
    out = {
        "split": cfg.transfer_split,
        "part": "test",
        "n_windows": tp.windows.height,
        "n_attack_windows": int((y != M.BENIGN).sum()),
        "reliable_classes": reliable,
        "caveat": TRANSFER_CAVEAT,
        "winner": evaluate_windows(
            y,
            align_proba(proba, expert.classes, classes),
            score,
            classes,
            expert.threshold,
            reliable,
        ),
    }
    if current is not None:
        cur_classes = sorted(set(classes) | set(current.classes))
        pv, sv = current_on_windows(current, tp.flows, tp.assignment, tp.windows)
        pv = align_proba(pv, list(current.classes), cur_classes)
        thr = current_threshold if current_threshold is not None else 0.5
        out["current"] = evaluate_windows(y, pv, sv, cur_classes, thr, reliable)
    return out


# ================================================================ MLflow и отчёт


def log_audit_mlflow(mlflow_dir: Path, run_id: str, audit: dict) -> None:
    """Метрики аудита — в тот же MLflow-запуск победителя (contracts/cli.md)."""
    from mlsiem.detect.experiment import _setup_mlflow
    from mlsiem.detect.windows_experiment import MLFLOW_EXPERIMENT

    mlflow = _setup_mlflow(Path(mlflow_dir), MLFLOW_EXPERIMENT)
    metrics = {"audit_drop": audit["retrain"]["drop"]}
    if audit["retrain"]["done"]:
        metrics["audit_macro_reliable_without"] = audit["retrain"]["macro_pr_auc_reliable_val"]
    t = audit["transfer"]["winner"]
    for key, value in (
        ("transfer_macro_pr_auc_reliable", t["macro_pr_auc_reliable"]),
        ("transfer_pr_auc_binary", t["pr_auc_binary"]),
    ):
        if value is not None and value == value:
            metrics[key] = float(value)
    with mlflow.start_run(run_id=run_id):
        mlflow.log_metrics({k: float(v) for k, v in metrics.items()})
        mlflow.set_tags({"audit_verdict": audit["verdict"]})


def _f(v) -> str:
    return "—" if v is None or v != v else f"{v:.4f}"


def _recall_table(title: str, block: dict) -> list[str]:
    lines = [
        f"**{title}**: адресов с атаками {block['n_attackers']}; разброс полноты по адресам с "
        f"≥ 5 окнами-атаками: {_f(block['min_recall'])} … {_f(block['max_recall'])}",
        "",
        "| атакующий адрес | окон-атак | поймано | полнота |",
        "|---|---|---|---|",
    ]
    for r in block["rows"][:15]:
        lines.append(
            f"| {r['attacker_ip']} | {r['n_attack_windows']} | {r['caught']} | {r['recall']:.3f} |"
        )
    if len(block["rows"]) > 15:
        lines.append(f"| … ещё {len(block['rows']) - 15} | | | |")
    return lines + [""]


def render_audit_report(audit: dict, decision: dict) -> str:
    """Markdown-отчёт `reports/windows_audit.md` со всеми разделами R10."""
    m, inp, imp = audit["model"], audit["inputs"], audit["importance"]
    rt, tr = audit["retrain"], audit["transfer"]
    verdict_ru = {"clean": "чистая (clean)", "relies_on_artifacts": "опирается на артефакты"}
    lines = [
        "# Аудит модели окон на артефакты и перенос (фича 007, US2)",
        "",
        f"- Модель окон: `{m['kind']}` `{m['window_version']}`; текущая модель: "
        f"{audit['current_model']['kind']} `{audit['current_model']['version']}`",
        f"- Разбиение: `{audit['split']}`, правило направления `{audit['direction']}`; "
        f"надёжные классы: {', '.join(audit['reliable_classes'])}",
        f"- **Вердикт: {verdict_ru.get(audit['verdict'], audit['verdict'])}** — {audit['text']}",
        f"- Итоговое решение: `accepted = {str(decision['accepted']).lower()}` "
        f"(прошёл выбор — {'да' if decision.get('passed_selection') else 'нет'}; принять можно "
        "только при пройденном выборе и чистом аудите, FR-012). "
        f"Причина в карточке: «{decision.get('reason', '')}»",
        f"- Время аудита: {audit['seconds']} с",
        "",
        "## 1. Состав входов",
        "",
        f"{inp['n_features']} признаков ({inp['features_family']}). Запрещённых (адреса, "
        "значения портов, идентификаторы, абсолютное время, DPI) — "
        + (", ".join(inp["forbidden"]) if inp["forbidden"] else "нет")
        + ".",
        "",
        "## 2. Важность признаков",
        "",
        f"Метод: {imp['method']}; «атака/нет» PR-AUC на val {_f(imp['base_pr_auc'])} "
        f"({imp['n_rows']} окон). Падение PR-AUC при перемешивании признака:",
        "",
        "| признак | падение |",
        "|---|---|",
    ]
    lines += [f"| {r['feature']} | {r['drop']:+.4f} |" for r in imp["top"]]
    sf = audit["single_feature"]
    lines += [
        "",
        "## 3. Одиночные признаки",
        "",
        f"Признак подозрителен, если сам по себе даёт ≥ {audit['single_feature_share']:.0%} "
        f"«атака/нет» PR-AUC модели на val (порог {sf['flag_at']:.4f}). Помечены: "
        + (", ".join(sf["flagged"]) if sf["flagged"] else "нет")
        + ".",
        "",
        "| признак | PR-AUC в одиночку | знак | помечен |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {r['feature']} | {r['pr_auc']:.4f} | {r['sign']} | {'да' if r['flagged'] else ''} |"
        for r in sf["top"]
    ]
    da = audit["data_audit"]
    if da["found"]:
        fields = (
            ", ".join(f"{f['field']} ({f['variant']}: {f['status']})" for f in da["fields"])
            or "нет"
        )
        data_line = (
            f"Аудит данных 001 (`{da['path']}`) пометил поля: {fields}. Из них во входе модели "
            f"окон: {', '.join(da['window_features']) or 'ничего'}."
        )
    else:
        data_line = (
            f"Аудит данных 001 не найден (`{da['path']}`) — подозрительные признаки взяты только "
            "из одиночных (`uv run mlsiem data audit`, чтобы добавить его)."
        )
    lines += [
        "",
        "## 4. Повтор без подозрительных признаков",
        "",
        data_line,
        "",
    ]
    if rt["done"]:
        lines += [
            f"Убраны из входа ({len(rt['removed'])}): {', '.join(rt['removed'])}. Модель "
            "переобучена тем же протоколом (хвост train для ранней остановки, те же параметры и "
            "сид).",
            "",
            "| | macro надёжных val | «атака/нет» val |",
            "|---|---|---|",
            f"| со всеми признаками | {_f(audit['base']['macro_pr_auc_reliable_val'])} | "
            f"{_f(audit['base']['pr_auc_binary_val'])} |",
            f"| без подозрительных | {_f(rt['macro_pr_auc_reliable_val'])} | "
            f"{_f(rt['pr_auc_binary_val'])} |",
            "",
            f"Падение {rt['drop']:+.4f}; порог «опирается на артефакты» — {audit['max_drop']}.",
        ]
    else:
        lines.append("Подозрительных признаков нет — повтор не нужен, падение 0.")
    w, c = tr["winner"], tr.get("current")
    lines += [
        "",
        f"## 5. Перенос на test `{tr['split']}` (без переобучения)",
        "",
        f"Окон {tr['n_windows']}, из них атак {tr['n_attack_windows']}; надёжные классы "
        f"переноса: {', '.join(tr['reliable_classes']) or 'нет'}. Решения по этим цифрам не "
        f"принимаются; {tr['caveat']}.",
        "",
        "| участник | macro надёжных | «атака/нет» PR-AUC | precision | recall |",
        "|---|---|---|---|---|",
        f"| модель окон ({m['kind']}) | {_f(w['macro_pr_auc_reliable'])} | "
        f"{_f(w['pr_auc_binary'])} | {_f(w['binary']['precision'])} | "
        f"{_f(w['binary']['recall'])} |",
    ]
    if c is not None:
        lines.append(
            f"| текущая модель на окнах | {_f(c['macro_pr_auc_reliable'])} | "
            f"{_f(c['pr_auc_binary'])} | {_f(c['binary']['precision'])} | "
            f"{_f(c['binary']['recall'])} |"
        )
    pa = audit["per_attacker"]
    lines += [
        "",
        "## 6. Полнота по атакующим адресам",
        "",
        "Сильный перекос (один адрес ловится всегда, другой — никогда) означает, что модель "
        "узнаёт «почерк» конкретного генератора, а не поведение атаки.",
        "",
    ]
    for part in ("val", "test"):
        lines += _recall_table(f"Модель окон, {part}", pa["winner"][part])
        lines += _recall_table(f"Текущая модель на окнах, {part}", pa["current"][part])
    return "\n".join(lines).rstrip() + "\n"


# ================================================================ команда целиком


class AuditInputMissing(RuntimeError):
    """Рядом с моделью окон нет протокола эксперимента — аудиту не с чем работать."""


def run_windows_audit(
    cfg: W.WindowsConfig,
    *,
    model_dir: Path | None = None,
    data_dir: Path = Path("data"),
    device: str = "auto",
    reports_dir: Path = Path("reports"),
    mlflow_dir: Path | None = Path("."),
    current_dir: Path | None = None,
) -> tuple[dict, dict]:
    """`detect windows-audit`: аудит → решение в карточке → отчёт → MLflow.

    Возвращает (аудит, обновлённая карточка). Версия модели не меняется (T035)."""
    import json

    from mlsiem.data.captures import atomic_path
    from mlsiem.detect.windows_expert import EXPERIMENT_FILE, load_window_expert, update_decision

    model_dir = Path(model_dir or cfg.output)
    exp_file = model_dir / EXPERIMENT_FILE
    if not exp_file.exists():
        raise AuditInputMissing(
            f"нет {exp_file} — сначала запустите эксперимент `uv run mlsiem detect windows`"
        )
    exp = json.loads(exp_file.read_text(encoding="utf-8"))
    expert = load_window_expert(model_dir, force=True)
    if expert.version != exp["window_version"]:
        raise AuditInputMissing(
            f"модель окон {expert.version} и протокол {exp['window_version']} от разных запусков "
            "— перезапустите `mlsiem detect windows`"
        )
    dev = "cpu"
    if expert.kind == "gru":
        from mlsiem.detect.windows_nn import resolve_device

        dev = resolve_device(device)
    current = None
    if current_dir is not None:
        from mlsiem.detect.ensemble import load_model

        current = load_model(Path(current_dir))
    audit = audit_window_model(expert, exp, cfg, data_dir=data_dir, device=dev, current=current)
    card = update_decision(model_dir, audit)
    with atomic_path(Path(reports_dir) / REPORT_NAME) as tmp:
        tmp.write_text(render_audit_report(audit, card["decision"]), encoding="utf-8")
    run_id = (exp.get("mlflow_runs") or {}).get(expert.kind)
    if mlflow_dir is not None and run_id:
        log_audit_mlflow(mlflow_dir, run_id, audit)
    log.info("Аудит %s: %s", expert.describe(), audit["text"])
    return audit, card


# ================================================================ разбор ошибок (US4)

ERRORS_REPORT_NAME = "windows_errors.md"
# Корзины размера окна (число потоков): одиночный поток, «пачка», типичное окно, до предела
# последовательности и усечённые (> seq_max 128 — нейросеть видит только начало)
SIZE_BUCKETS = ((1, 1, "1"), (2, 10, "2–10"), (11, 64, "11–64"), (65, 128, "65–128"))
MAX_EXAMPLES = 20


def size_bucket(n: int) -> str:
    for lo, hi, name in SIZE_BUCKETS:
        if lo <= n <= hi:
            return name
    return ">128"


def confusion_by_class(y_true, y_pred, classes: list[str]) -> dict:
    """Матрица ошибок: строки — истинный класс окна, столбцы — предсказанный (на пороге
    модели; ниже порога — benign). Только классы, встретившиеся хоть где-то, в порядке
    `classes`, незнакомые — в конце по алфавиту."""
    y_true, y_pred = list(y_true), list(y_pred)
    seen = set(y_true) | set(y_pred)
    labels = [c for c in dict.fromkeys(classes) if c in seen]
    labels += sorted(seen - set(labels))
    matrix = {t: {p: 0 for p in labels} for t in labels}
    for t, p in zip(y_true, y_pred, strict=True):
        matrix[t][p] += 1
    return {"labels": labels, "matrix": matrix}


def quality_by_size(n_flows, y_attack, score, is_alert) -> list[dict]:
    """Качество по корзинам размера окна: окон, атак, PR-AUC «атака/нет», полнота атак и
    ложные тревоги на норме — видно, на каких окнах модель слепнет."""
    n_flows = np.asarray(n_flows)
    y = np.asarray(y_attack, dtype=bool)
    s = np.asarray(score, dtype=np.float64)
    a = np.asarray(is_alert, dtype=bool)
    buckets = np.array([size_bucket(int(n)) for n in n_flows])
    rows = []
    for name in [b[2] for b in SIZE_BUCKETS] + [">128"]:
        m = buckets == name
        if not m.any():
            continue
        yb, ab = y[m], a[m]
        rows.append(
            {
                "bucket": name,
                "n_windows": int(m.sum()),
                "n_attack": int(yb.sum()),
                "pr_auc_binary": M.binary_pr_auc(yb, s[m]),
                "recall": float(ab[yb].mean()) if yb.any() else None,
                "false_alerts": int((ab & ~yb).sum()),
            }
        )
    return rows


def flows_caught(assignment: pl.DataFrame, flow_alerts: pl.DataFrame) -> pl.DataFrame:
    """window_id → «поймано потоками»: хоть один поток окна — алерт текущей модели."""
    return (
        assignment.select("flow_uid", "window_id")
        .join(flow_alerts.select("flow_uid", "is_alert"), on="flow_uid", how="left")
        .group_by("window_id")
        .agg(pl.col("is_alert").fill_null(False).any().alias("caught_by_flows"))
    )


def catch_table(frame: pl.DataFrame) -> list[dict]:
    """По классам атакующих окон: сколько поймали только окна, только потоки, обе, никто.

    `frame`: label, window_alert (bool), caught_by_flows (bool). Норма не входит — у неё
    «поймано» значит «ложная тревога», это отдельная строка отчёта."""
    w, f = pl.col("window_alert"), pl.col("caught_by_flows")
    out = (
        frame.filter(pl.col("label") != M.BENIGN)
        .group_by("label")
        .agg(
            pl.len().alias("n_windows"),
            (w & ~f).sum().alias("only_windows"),
            (~w & f).sum().alias("only_flows"),
            (w & f).sum().alias("both"),
            (~w & ~f).sum().alias("none"),
        )
        .sort(["n_windows", "label"], descending=[True, False])
    )
    return [{k: (v if k == "label" else int(v)) for k, v in r.items()} for r in out.to_dicts()]


def missed_examples(frame: pl.DataFrame, limit: int = MAX_EXAMPLES) -> list[dict]:
    """До `limit` пропущенных атакующих окон — самые «уверенно пропущенные» (наименьший
    скор) с подсказкой, почему: размер, доля атакующих потоков, поймали ли их потоки."""
    cols = [
        "window_id",
        "attacker_ip",
        "label",
        "n_flows",
        "attack_share",
        "attack_score",
        "caught_by_flows",
    ]
    return (
        frame.filter((pl.col("label") != M.BENIGN) & ~pl.col("window_alert"))
        .sort(["attack_score", "window_id"])
        .head(limit)
        .select(cols)
        .to_dicts()
    )


def error_analysis(expert, current, pw: W.PartWindows) -> dict:
    """Разбор ошибок модели окон на части `pw` (основная сетка) рядом с моделью потоков.

    Окна и вердикты эксперт строит сам (`WindowExpert.verdicts`) — так же, как в цепочке;
    метки и доля атакующих потоков берутся из `pw.windows`. «Поймано потоками» — хоть один
    поток окна стал алертом текущей модели на ЕЁ пороге (как в цепочке 002–005)."""
    res = expert.verdicts(pw.flows, pw.side)
    v = res.verdicts.select(
        "window_id", "predicted_class", "attack_score", pl.col("is_alert").alias("window_alert")
    )
    fv = current.verdict_frame(pw.flows).select("flow_uid", "is_alert")
    frame = (
        pw.windows.filter(pl.col("shift_ms") == 0)
        .select("window_id", "attacker_ip", "label", "n_flows", "attack_share")
        .join(v, on="window_id", how="inner")
        .join(flows_caught(res.assignment, fv), on="window_id", how="left")
        .with_columns(pl.col("caught_by_flows").fill_null(False))
        .sort("window_id")
    )
    y = frame["label"].to_numpy()
    y_attack = y != M.BENIGN
    alerts = frame["window_alert"].to_numpy()
    benign = ~y_attack
    return {
        "model": {"window_version": expert.version, "kind": expert.kind},
        "current_model": {"kind": current.kind, "version": current.version},
        "part": pw.part,
        "n_windows": frame.height,
        "n_attack_windows": int(y_attack.sum()),
        "recall": float(alerts[y_attack].mean()) if y_attack.any() else None,
        "false_alerts": int((alerts & benign).sum()),
        "fpr": float(alerts[benign].mean()) if benign.any() else None,
        "flows_false_alerts": int((frame["caught_by_flows"].to_numpy() & benign).sum()),
        "confusion": confusion_by_class(
            y, frame["predicted_class"].to_list(), [M.BENIGN, *expert.classes]
        ),
        "by_size": quality_by_size(frame["n_flows"], y_attack, frame["attack_score"], alerts),
        "catch": catch_table(frame),
        "missed": missed_examples(frame),
    }


def render_errors_report(err: dict) -> str:
    """Markdown `reports/windows_errors.md`: матрица, размеры окон, окна против потоков,
    примеры пропусков. Выводы словами владелец дописывает в журнал."""
    m = err["model"]
    cm = err["confusion"]
    lines = [
        f"# Разбор ошибок модели окон на {err['part']} (фича 007, US4)",
        "",
        f"- Модель окон: `{m['kind']}` `{m['window_version']}`; модель потоков: "
        f"{err['current_model']['kind']} `{err['current_model']['version']}`",
        f"- Окон {err['n_windows']}, атакующих {err['n_attack_windows']}; полнота окон "
        f"{_f(err['recall'])}; ложных окон на норме {err['false_alerts']} (FPR {_f(err['fpr'])})",
        f"- Окон нормы, где модель потоков подняла хоть один алерт: {err['flows_false_alerts']}",
        "",
        "## Матрица ошибок (строки — истина, столбцы — предсказание)",
        "",
        "| истина \\ предсказание | " + " | ".join(cm["labels"]) + " |",
        "|---|" + "---|" * len(cm["labels"]),
    ]
    for t in cm["labels"]:
        cells = " | ".join(str(cm["matrix"][t][p]) for p in cm["labels"])
        lines.append(f"| {t} | {cells} |")
    lines += [
        "",
        "## Качество по размеру окна (число потоков)",
        "",
        "| потоков | окон | атак | «атака/нет» PR-AUC | полнота атак | ложных на норме |",
        "|---|---|---|---|---|---|",
    ]
    lines += [
        f"| {r['bucket']} | {r['n_windows']} | {r['n_attack']} | {_f(r['pr_auc_binary'])} | "
        f"{_f(r['recall'])} | {r['false_alerts']} |"
        for r in err["by_size"]
    ]
    lines += [
        "",
        "## Окна против потоков по классам атакующих окон",
        "",
        "«Поймано потоками» — хоть один поток окна стал алертом модели потоков на её пороге.",
        "",
        "| класс | окон | только окна | только потоки | обе | никто |",
        "|---|---|---|---|---|---|",
    ]
    lines += [
        f"| {r['label']} | {r['n_windows']} | {r['only_windows']} | {r['only_flows']} | "
        f"{r['both']} | {r['none']} |"
        for r in err["catch"]
    ]
    lines += [
        "",
        f"## Пропущенные атакующие окна (до {MAX_EXAMPLES}, с наименьшим скором)",
        "",
        "| окно | атакующий | класс | потоков | доля атакующих потоков | скор | потоки поймали |",
        "|---|---|---|---|---|---|---|",
    ]
    lines += [
        f"| {r['window_id']} | {r['attacker_ip']} | {r['label']} | {r['n_flows']} | "
        f"{r['attack_share']:.2f} | {r['attack_score']:.4f} | "
        f"{'да' if r['caught_by_flows'] else 'нет'} |"
        for r in err["missed"]
    ]
    if not err["missed"]:
        lines.append("| — | | | | | | |")
    return "\n".join(lines) + "\n"


def run_windows_errors(
    cfg: W.WindowsConfig,
    *,
    model_dir: Path | None = None,
    part: str = "test",
    data_dir: Path = Path("data"),
    reports_dir: Path = Path("reports"),
    current_dir: Path | None = None,
) -> dict:
    """`detect windows-errors`: разбор на части `part` основного разбиения → отчёт."""
    import json

    from mlsiem.data.captures import atomic_path
    from mlsiem.detect.ensemble import load_model
    from mlsiem.detect.windows_expert import EXPERIMENT_FILE, load_window_expert

    model_dir = Path(model_dir or cfg.output)
    exp_file = model_dir / EXPERIMENT_FILE
    if not exp_file.exists():
        raise AuditInputMissing(
            f"нет {exp_file} — сначала запустите эксперимент `uv run mlsiem detect windows`"
        )
    exp = json.loads(exp_file.read_text(encoding="utf-8"))
    expert = load_window_expert(model_dir, force=True)
    current = load_model(Path(current_dir or exp["current_model"]["path"]))
    pw = _part(cfg, exp["split"], part, Path(data_dir), exp["direction"], (0,))
    err = error_analysis(expert, current, pw)
    with atomic_path(Path(reports_dir) / ERRORS_REPORT_NAME) as tmp:
        tmp.write_text(render_errors_report(err), encoding="utf-8")
    return err
