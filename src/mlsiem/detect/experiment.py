"""Эксперимент: обучить кандидатов, честно сравнить, выбрать и сохранить детектор (US1).

Порядок строго такой, чтобы test ни на что не влиял (принцип III):
1. train `unsw_time` → обучение каждого кандидата;
2. val → порог (максимум F1) и macro PR-AUC для выбора победителя;
3. test → метрики для отчёта (у всех кандидатов, но в выборе не участвуют);
4. победитель без переобучения → test `unsw_cross_day` (перенос на другой день, FR-008).

Результаты: runs в MLflow (по одному на кандидата), `experiment.json` и артефакт детектора
в `models/detector/`, человекочитаемый отчёт `reports/detector_experiment.md`.

MLflow: метаданные — в SQLite `mlflow.db`, файлы — в `mlruns/`. Файловое хранилище
`./mlruns` без базы MLflow 3.x больше не принимает («maintenance mode»).
"""

from __future__ import annotations

import gc
import json
import logging
import os
import subprocess
import time
from pathlib import Path

import numpy as np

from mlsiem.data.captures import atomic_path
from mlsiem.data.schema import SCHEMA
from mlsiem.detect import metrics as M
from mlsiem.detect.artifact import detector_version, library_versions, save_detector
from mlsiem.detect.candidates import build_candidate, select_winner
from mlsiem.detect.config import BASELINE, DetectConfig
from mlsiem.detect.dataset import data_hashes, feature_columns, load_part

log = logging.getLogger("mlsiem")
MLFLOW_EXPERIMENT = "detector"
REPORT_NAME = "detector_experiment.md"


# ---------------------------------------------------------------- вспомогательное


def git_commit() -> str | None:
    """Текущий коммит (для воспроизводимости). Нет git или не репозиторий — None."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10, check=True
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _setup_mlflow(mlflow_dir: Path):
    """Подключает MLflow: база `<dir>/mlflow.db`, файлы runs — `<dir>/mlruns/`."""
    os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
    for name in ("mlflow", "alembic"):
        logging.getLogger(name).setLevel(logging.WARNING)
    import mlflow

    mlflow_dir = Path(mlflow_dir).resolve()
    mlflow_dir.mkdir(parents=True, exist_ok=True)
    mlflow.set_tracking_uri("sqlite:///" + (mlflow_dir / "mlflow.db").as_posix())
    if mlflow.get_experiment_by_name(MLFLOW_EXPERIMENT) is None:
        mlflow.create_experiment(
            MLFLOW_EXPERIMENT, artifact_location=(mlflow_dir / "mlruns").as_uri()
        )
    mlflow.set_experiment(MLFLOW_EXPERIMENT)
    return mlflow


def evaluate(y: np.ndarray, proba: np.ndarray, classes: list[str], threshold: float) -> dict:
    """PR-AUC по классам и macro + бинарные метрики при пороге — для одной части."""
    per_class = M.per_class_pr_auc(y, proba, classes)
    scores = M.attack_score(proba, classes)
    return {
        "macro_pr_auc": M.macro_pr_auc(per_class),
        "per_class": per_class,
        "binary": M.binary_report(y != M.BENIGN, scores, threshold),
        "classes_without_examples": M.classes_without_examples(per_class),
        "n_flows": len(y),
    }


def _flat_metrics(prefix: str, ev: dict) -> dict[str, float]:
    """Метрики части в плоском виде для MLflow (None пропускаются)."""
    out = {f"{prefix}_macro_pr_auc": ev["macro_pr_auc"]}
    out.update({f"{prefix}_pr_auc_{c}": v for c, v in ev["per_class"].items() if v is not None})
    out.update({f"{prefix}_{k}": v for k, v in ev["binary"].items() if v is not None})
    return out


# ---------------------------------------------------------------- эксперимент


def run_experiment(
    cfg: DetectConfig,
    *,
    data_dir: Path = Path("data"),
    reports_dir: Path = Path("reports"),
    mlflow_dir: Path = Path("."),
) -> dict:
    """Весь эксперимент US1. Возвращает содержимое experiment.json."""
    data_dir = Path(data_dir)
    feats = feature_columns()
    data = data_hashes(cfg.split, data_dir)
    transfer_data = data_hashes(cfg.transfer_split, data_dir)
    version = detector_version(cfg.raw, {"split": data, "transfer": transfer_data})
    mlflow = _setup_mlflow(mlflow_dir)
    commit = git_commit()

    log.info("Загружаю %s: train / val / test…", cfg.split)
    train = load_part(cfg.split, "train", data_dir=data_dir)
    val = load_part(cfg.split, "val", data_dir=data_dir)
    test = load_part(cfg.split, "test", data_dir=data_dir)
    X_train = train.X_numpy()
    X_val, X_test = val.X_numpy(), test.X_numpy()
    log.info(
        "train %d, val %d, test %d потоков, признаков %d",
        len(train.y),
        len(val.y),
        len(test.y),
        len(feats),
    )

    candidates: list[dict] = []
    pipelines = {}
    for name, params in cfg.candidates.items():
        log.info("Кандидат %s: обучение…", name)
        started = time.perf_counter()
        pipe = build_candidate(name, params, cfg.seed)
        pipe.fit(X_train, train.y)
        train_seconds = time.perf_counter() - started
        classes = [str(c) for c in pipe.classes_]

        proba_val = pipe.predict_proba(X_val)
        threshold = M.choose_threshold(val.y != M.BENIGN, M.attack_score(proba_val, classes))
        ev_val = evaluate(val.y, proba_val, classes, threshold)
        ev_test = evaluate(test.y, pipe.predict_proba(X_test), classes, threshold)
        log.info(
            "Кандидат %s: %.0f с, macro PR-AUC val %.4f / test %.4f, порог %.4f",
            name,
            train_seconds,
            ev_val["macro_pr_auc"],
            ev_test["macro_pr_auc"],
            threshold,
        )

        with mlflow.start_run(run_name=name) as run:
            mlflow.log_params({**params, "candidate": name, "seed": cfg.seed, "split": cfg.split})
            mlflow.log_metrics(
                {
                    **_flat_metrics("val", ev_val),
                    **_flat_metrics("test", ev_test),
                    "threshold": threshold,
                    "train_seconds": train_seconds,
                }
            )
            mlflow.set_tags(
                {
                    "split_hash": data["split_hash"],
                    "schema_version": SCHEMA.version,
                    "git_commit": commit or "",
                    "detector_version": version,
                }
            )
            mlflow.log_dict(
                {"split": data, "transfer": transfer_data, "config": cfg.raw},
                "data_and_config.json",
            )
        candidates.append(
            {
                "name": name,
                "params": params,
                "classes": classes,
                "threshold": threshold,
                "train_seconds": round(train_seconds, 1),
                "val": ev_val,
                "test": ev_test,
                "mlflow_run_id": run.info.run_id,
            }
        )
        pipelines[name] = pipe

    classes = candidates[0]["classes"]
    prior = {
        "val": M.prior_baseline(train.y, val.y, classes),
        "test": M.prior_baseline(train.y, test.y, classes),
    }
    results = {c["name"]: {"macro_pr_auc_val": c["val"]["macro_pr_auc"]} for c in candidates}
    winner, rule_text = select_winner(results, baseline=BASELINE, min_gain=cfg.selection.min_gain)
    win = next(c for c in candidates if c["name"] == winner)
    log.info("Победитель: %s — %s", winner, rule_text)

    # Память: train больше не нужен, а впереди ещё test второго разбиения
    del X_train, train, X_val, X_test
    gc.collect()

    log.info("Перенос: %s на test %s…", winner, cfg.transfer_split)
    transfer_part = load_part(cfg.transfer_split, "test", data_dir=data_dir)
    win_pipe = pipelines[winner]
    transfer = evaluate(
        transfer_part.y,
        win_pipe.predict_proba(transfer_part.X_numpy()),
        win["classes"],
        win["threshold"],
    )
    transfer["split"] = cfg.transfer_split

    card = {
        "detector_version": version,
        "candidate": winner,
        "classes": win["classes"],
        "threshold": win["threshold"],
        "features": feats,
        "schema_version": SCHEMA.version,
        "data": {
            "split": cfg.split,
            "split_hash": data["split_hash"],
            "input_hashes": data["input_hashes"],
            "transfer_split": cfg.transfer_split,
            "transfer_split_hash": transfer_data["split_hash"],
        },
        "metrics": {"val": win["val"], "test": win["test"], "transfer_test": transfer},
        "seed": cfg.seed,
        "libraries": library_versions(),
        "git_commit": commit,
        "mlflow_run_id": win["mlflow_run_id"],
    }
    experiment = {
        "detector_version": version,
        "split": cfg.split,
        "transfer_split": cfg.transfer_split,
        "seed": cfg.seed,
        "config": cfg.raw,
        "data": card["data"],
        "candidates": candidates,
        "prior_baseline": prior,
        "selection_rule": {
            "metric": cfg.selection.metric,
            "min_gain": cfg.selection.min_gain,
            "baseline": BASELINE,
            "text": rule_text,
        },
        "winner": winner,
        "transfer": transfer,
        "classes_without_examples": {
            "val": win["val"]["classes_without_examples"],
            "test": win["test"]["classes_without_examples"],
            "transfer_test": transfer["classes_without_examples"],
        },
    }

    out = Path(cfg.output)
    save_detector(win_pipe, card, out)
    with atomic_path(out / "experiment.json") as tmp:
        tmp.write_text(
            json.dumps(experiment, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    with atomic_path(Path(reports_dir) / REPORT_NAME) as tmp:
        tmp.write_text(render_report(experiment), encoding="utf-8")
    log.info("Детектор %s сохранён в %s", version, out)
    return experiment


# ---------------------------------------------------------------- отчёт


def _f(v: float | None) -> str:
    return "—" if v is None else f"{v:.4f}"


def render_report(exp: dict) -> str:
    """Markdown-отчёт эксперимента: читается в репозитории без MLflow."""
    classes = exp["candidates"][0]["classes"]
    lines = [
        "# Эксперимент детектора (фича 002)",
        "",
        f"- Версия детектора: `{exp['detector_version']}`",
        f"- Разбиение: `{exp['split']}` (hash `{exp['data']['split_hash'][:12]}…`), "
        f"сид {exp['seed']}",
        "- Метрика выбора: macro PR-AUC на val; test — только для отчёта",
        "",
        "## Кандидаты",
        "",
        "| Кандидат | macro PR-AUC val | macro PR-AUC test | порог | F1 val | F1 test "
        "| обучение, с |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in exp["candidates"]:
        lines.append(
            f"| {c['name']} | {_f(c['val']['macro_pr_auc'])} | {_f(c['test']['macro_pr_auc'])} | "
            f"{c['threshold']:.4f} | {_f(c['val']['binary']['f1'])} | "
            f"{_f(c['test']['binary']['f1'])} | "
            f"{c['train_seconds']} |"
        )
    p = exp["prior_baseline"]
    lines += [
        f"| prior (доли классов) | {_f(p['val']['macro_pr_auc'])} | "
        f"{_f(p['test']['macro_pr_auc'])} | — | — | — | — |",
        "",
        "## PR-AUC по классам",
        "",
        "| Класс | "
        + " | ".join(f"{c['name']} val | {c['name']} test" for c in exp["candidates"])
        + " | prior test |",
        "|---|" + "---|" * (2 * len(exp["candidates"]) + 1),
    ]
    for cls in classes:
        cells = []
        for c in exp["candidates"]:
            cells += [_f(c["val"]["per_class"].get(cls)), _f(c["test"]["per_class"].get(cls))]
        lines.append(
            f"| {cls} | " + " | ".join(cells) + f" | {_f(p['test']['per_class'].get(cls))} |"
        )
    t = exp["transfer"]
    lines += [
        "",
        "## Выбор",
        "",
        f"Правило: победитель — наибольший macro PR-AUC на val; если прирост над бейзлайном "
        f"`{exp['selection_rule']['baseline']}` меньше "
        f"{exp['selection_rule']['min_gain']} — бейзлайн.",
        "",
        f"**Победитель: `{exp['winner']}`** — {exp['selection_rule']['text']}.",
        "",
        "## Перенос на другой день",
        "",
        f"Победитель без переобучения на test `{t['split']}`: "
        f"macro PR-AUC {_f(t['macro_pr_auc'])}, "
        f"precision {_f(t['binary']['precision'])}, recall {_f(t['binary']['recall'])}, "
        f"F1 {_f(t['binary']['f1'])} (порог с val `{exp['split']}`).",
        "",
        "Замечание (research R4): test `unsw_cross_day` — вторая половина дня 17-2-2015, а train "
        "`unsw_time` содержит начало того же дня, так что это проверка «на другом отрезке», а не "
        "честный перенос на невиданный день. Честная проверка — обучить победителя на train "
        "`unsw_cross_day` (только день 22-1-2015); отложено до следующего эксперимента.",
        "",
        "## Классы без примеров",
        "",
    ]
    empty = exp["classes_without_examples"]
    if any(empty.values()):
        for part, cls in empty.items():
            if cls:
                lines.append(f"- {part}: {', '.join(cls)} — PR-AUC не считается, в macro не входит")
    else:
        lines.append("Во всех оцениваемых частях есть примеры всех классов.")
    return "\n".join(lines) + "\n"
