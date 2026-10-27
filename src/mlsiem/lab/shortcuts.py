"""Аудит «ярлыков» набора стенда (фича 008, US4, R10–R11, FR-012…FR-014).

Вопрос один: не выучила ли модель «этот инструмент / этот адрес = эта атака» вместо настоящего
поведения трафика. Два способа проверить:

1. **Исключение инструмента и хоста (R10).** Обучаем бейзлайн (LightGBM кандидата 002) на обучающей
   части набора, но БЕЗ одного инструмента класса (или без одного адреса-источника), и смотрим
   полноту на тестовых потоках именно этого инструмента (адреса). Контроль — та же модель, но
   обученная с ним. Если без инструмента полнота резко падает, модель держится за инструмент, а не
   за поведение. Порог — квантиль нормы валидации (доля ложных срабатываний 0,1 / 1 / 5%), на
   стенде порог не подбирается (конституция III). Для полноты — интервал Уилсона.
2. **Аудит признаков окружения (R11).** Часть признаков зависит от сетевого стека и инструмента, а
   не от атаки (флаги ECE/CWR/URG, минимальный/максимальный размер пакета). Смотрим перестановочную
   важность, одиночную силу признака и переобучаем модель без них: если качество падает больше
   порога — вердикт `suspect`.

Обучающая выборка ограничена `max_train_per_class` потоками на класс (класс dos — 750 тысяч потоков
одиночных SYN, обучать на всех незачем), отбор детерминирован сидом. Класс из менее чем
`min_test_flows` тестовых потоков в средние не входит (SC-002).
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np
import polars as pl

from mlsiem.detect import openset
from mlsiem.detect.candidates import build_candidate
from mlsiem.detect.dataset import feature_columns
from mlsiem.detect.metrics import binary_pr_auc
from mlsiem.lab.dataset import AMBIGUOUS, BENIGN

DEFAULT_PARAMS = {
    "n_estimators": 150,
    "learning_rate": 0.08,
    "num_leaves": 63,
    "class_weight": "balanced",
}
DEFAULT_FPR = (0.001, 0.01, 0.05)
DEFAULT_ENV_FEATURES = (
    "bidirectional_ece_packets",
    "bidirectional_cwr_packets",
    "bidirectional_urg_packets",
    "bidirectional_min_ps",
    "bidirectional_max_ps",
)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Интервал Уилсона для доли k из n (95%); при n=0 — (0, 1)."""
    if n <= 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def _usable(df: pl.DataFrame) -> pl.DataFrame:
    """Без неоднозначных и зазоров между частями: ни в обучении, ни в оценке они не участвуют."""
    return df.filter((pl.col("label") != AMBIGUOUS) & (pl.col("part") != "gap"))


def _cap_train(train: pl.DataFrame, per_class: int, seed: int) -> pl.DataFrame:
    """Не более `per_class` потоков каждого класса (детерминированно по сиду)."""
    parts = []
    for label in train["label"].unique().sort().to_list():
        sub = train.filter(pl.col("label") == label)
        parts.append(
            sub.sample(n=min(sub.height, per_class), seed=seed) if sub.height > per_class else sub
        )
    return pl.concat(parts)


def _fit(train: pl.DataFrame, features: list[str], seed: int, params: dict, per_class: int):
    """Обучает бейзлайн на ограниченной выборке; возвращает (модель, классы по порядку)."""
    tr = _cap_train(train, per_class, seed)
    X = tr.select(features).cast(pl.Float32).fill_null(0).to_numpy()
    model = build_candidate("lgbm", params, seed)
    model.fit(X, tr["label"].to_numpy())
    return model, list(model.classes_)


def _scores(model, classes: list[str], df: pl.DataFrame, features: list[str]) -> np.ndarray:
    """Скор атаки — ЛОГИТ «не норма» (`ln Σ_{c≠benign} exp z − z_benign`), а не `1 − P(benign)`:
    вероятность у уверенной модели насыщается до 1.0, пороги на 0,1/1/5% совпадают,
    и полнота перестаёт зависеть от доли ложных срабатываний."""
    X = df.select(features).cast(pl.Float32).fill_null(0).to_numpy()
    return openset.attack_vs_normal(openset.raw_logits(model, X), classes)


def _thresholds(val_benign_scores: np.ndarray, fprs) -> dict[float, float]:
    """Порог скора атаки для доли ложных срабатываний f — квантиль 1−f нормы валидации."""
    return {f: float(np.quantile(val_benign_scores, 1 - f)) for f in fprs}


def _recall(scores: np.ndarray, thr: dict[float, float]) -> dict[float, dict]:
    n = len(scores)
    out = {}
    for f, t in thr.items():
        k = int((scores > t).sum())  # строго выше: при ничьях на пороге доля ложных остаётся ≤ f
        lo, hi = wilson(k, n)
        out[f] = {
            "recall": k / n if n else None,
            "k": k,
            "n": n,
            "ci": [round(lo, 4), round(hi, 4)],
        }
    return out


def _mean_over_seeds(per_seed: list[dict[float, dict]]) -> dict[str, dict]:
    """Среднее полноты по сидам; интервал Уилсона — для среднего при числе тестовых потоков n."""
    res = {}
    for f in per_seed[0]:
        rec = [s[f]["recall"] for s in per_seed]
        n = per_seed[0][f]["n"]
        mean = float(np.mean(rec))
        lo, hi = wilson(int(round(mean * n)), n)
        res[str(f)] = {
            "recall": round(mean, 4),
            "seeds": [round(r, 4) for r in rec],
            "n": n,
            "ci": [round(lo, 4), round(hi, 4)],
        }
    return res


def tool_exclusion_cases(labeled: pl.DataFrame, min_test_flows: int) -> list[tuple[str, str]]:
    """Пары (класс, инструмент), для которых исключение имеет смысл: у класса в обучении есть ДРУГОЙ
    инструмент (иначе класса в обучении не останется), а сам инструмент есть и в обучении,
    и в тесте."""
    d = _usable(labeled).filter(pl.col("label") != BENIGN).filter(~pl.col("reserve_unknown"))
    cases = []
    for label in sorted(d["label"].unique().to_list()):
        sub = d.filter(pl.col("label") == label)
        train_tools = set(
            sub.filter(pl.col("part") == "train")["tool"].drop_nulls().unique().to_list()
        )
        for tool in sorted(train_tools):
            test_n = sub.filter((pl.col("part") == "test") & (pl.col("tool") == tool)).height
            if len(train_tools) >= 2 and test_n >= min_test_flows:
                cases.append((label, tool))
    return cases


def run_exclusion(
    labeled: pl.DataFrame,
    *,
    source_ips: dict[str, str],
    seeds=(0, 1, 2),
    fprs=DEFAULT_FPR,
    min_test_flows: int = 100,
    params: dict | None = None,
    max_train_per_class: int = 30_000,
    log=print,
) -> dict:
    """Исключение инструмента (R10) и хоста: полнота без него против контроля, по сидам."""
    params = params or DEFAULT_PARAMS
    feats = feature_columns()
    d = _usable(labeled)
    train, val, test = (d.filter(pl.col("part") == p) for p in ("train", "val", "test"))
    val_benign = val.filter(pl.col("label") == BENIGN)
    test_attack = test.filter((pl.col("label") != BENIGN) & ~pl.col("reserve_unknown"))
    cases = tool_exclusion_cases(labeled, min_test_flows)
    hosts = [
        (name, ip)
        for name, ip in source_ips.items()
        if test_attack.filter(pl.col("source") == name).height >= min_test_flows
    ]

    control_scores: dict[int, dict] = {}
    out_tools = {c: {"control": [], "excluded": []} for c in cases}
    out_hosts = {n: {"control": [], "excluded": []} for n, _ in hosts}
    for seed in seeds:
        log(f"[сид {seed}] контроль: обучение на всех данных")
        model, classes = _fit(train, feats, seed, params, max_train_per_class)
        thr = _thresholds(_scores(model, classes, val_benign, feats), fprs)
        control_scores[seed] = (model, classes, thr)
        for label, tool in cases:
            rows = test_attack.filter((pl.col("label") == label) & (pl.col("tool") == tool))
            out_tools[(label, tool)]["control"].append(
                _recall(_scores(model, classes, rows, feats), thr)
            )
        for name, _ in hosts:
            rows = test_attack.filter(pl.col("source") == name)
            out_hosts[name]["control"].append(_recall(_scores(model, classes, rows, feats), thr))
        for label, tool in cases:
            log(f"[сид {seed}] без инструмента {tool} (класс {label})")
            tr = train.filter(~((pl.col("label") == label) & (pl.col("tool") == tool)))
            m, cl = _fit(tr, feats, seed, params, max_train_per_class)
            thr_x = _thresholds(_scores(m, cl, val_benign, feats), fprs)
            rows = test_attack.filter((pl.col("label") == label) & (pl.col("tool") == tool))
            out_tools[(label, tool)]["excluded"].append(_recall(_scores(m, cl, rows, feats), thr_x))
        for name, ip in hosts:
            log(f"[сид {seed}] без адреса {name} ({ip})")
            tr = train.filter((pl.col("source") != name) | pl.col("source").is_null())
            tr = tr.filter(pl.col("src_ip") != ip)  # и нормальные потоки с этого адреса
            m, cl = _fit(tr, feats, seed, params, max_train_per_class)
            thr_x = _thresholds(
                _scores(m, cl, val_benign.filter(pl.col("src_ip") != ip), feats), fprs
            )
            rows = test_attack.filter(pl.col("source") == name)
            out_hosts[name]["excluded"].append(_recall(_scores(m, cl, rows, feats), thr_x))

    tools = []
    for (label, tool), r in out_tools.items():
        ctrl, excl = _mean_over_seeds(r["control"]), _mean_over_seeds(r["excluded"])
        tools.append(
            {
                "class": label,
                "tool": tool,
                "control": ctrl,
                "excluded": excl,
                "drop": {f: round(ctrl[f]["recall"] - excl[f]["recall"], 4) for f in ctrl},
            }
        )
    host_rows = []
    for name, r in out_hosts.items():
        ctrl, excl = _mean_over_seeds(r["control"]), _mean_over_seeds(r["excluded"])
        host_rows.append(
            {
                "source": name,
                "control": ctrl,
                "excluded": excl,
                "drop": {f: round(ctrl[f]["recall"] - excl[f]["recall"], 4) for f in ctrl},
            }
        )
    return {"tools": tools, "hosts": host_rows, "fprs": list(fprs), "seeds": list(seeds)}


def run_env_audit(
    labeled: pl.DataFrame,
    *,
    env_features,
    seeds=(0, 1, 2),
    drop_threshold: float = 0.05,
    params: dict | None = None,
    max_train_per_class: int = 30_000,
    log=print,
) -> dict:
    """Аудит признаков окружения (R11): качество «атака/норма» с ними и без, важность, одиночная "
    "сила."""
    params = params or DEFAULT_PARAMS
    feats = feature_columns()
    env = [f for f in env_features if f in feats]
    rest = [f for f in feats if f not in env]
    d = _usable(labeled).filter(~pl.col("reserve_unknown"))
    train, test = d.filter(pl.col("part") == "train"), d.filter(pl.col("part") == "test")
    y_test = (test["label"] != BENIGN).to_numpy()
    full, without, importance = [], [], {f: [] for f in env}
    for seed in seeds:
        log(f"[сид {seed}] аудит окружения: все признаки / без {len(env)} признаков окружения")
        model, cl = _fit(train, feats, seed, params, max_train_per_class)
        base = binary_pr_auc(y_test, _scores(model, cl, test, feats))
        full.append(base)
        m2, cl2 = _fit(train, rest, seed, params, max_train_per_class)
        without.append(binary_pr_auc(y_test, _scores(m2, cl2, test, rest)))
        # перестановочная важность: на сколько падает PR-AUC при перемешивании одного признака
        sample = test.sample(n=min(test.height, 60_000), seed=seed)
        ys = (sample["label"] != BENIGN).to_numpy()
        ref = binary_pr_auc(ys, _scores(model, cl, sample, feats))
        for f in env:
            shuffled = sample.with_columns(pl.col(f).shuffle(seed=seed))
            importance[f].append(ref - binary_pr_auc(ys, _scores(model, cl, shuffled, feats)))
    single = {}
    for f in env:
        x = test[f].cast(pl.Float64).fill_null(0).to_numpy()
        single[f] = round(max(binary_pr_auc(y_test, x), binary_pr_auc(y_test, -x)), 4)
    drop = float(np.mean(full) - np.mean(without))
    return {
        "env_features": env,
        "pr_auc_full": round(float(np.mean(full)), 4),
        "pr_auc_without_env": round(float(np.mean(without)), 4),
        "drop": round(drop, 4),
        "threshold": drop_threshold,
        "permutation_importance": {f: round(float(np.mean(v)), 4) for f, v in importance.items()},
        "single_feature_pr_auc": single,
        "verdict": "suspect" if drop > drop_threshold else "clean",
        "seeds": list(seeds),
    }


DISCLAIMER = (
    "Эксперимент оценивает устойчивость модели к «ярлыкам» ИЗ НАБОРА СТЕНДА (инструмент, адрес "
    "источника, "
    "признаки окружения). Он не доказывает обнаружение реальных уязвимостей нулевого дня."
)


def report_md(rep: dict, version: str) -> str:
    fprs = [str(f) for f in rep["exclusion"]["fprs"]]
    lines = [
        f"# Ярлыки набора стенда {version}",
        "",
        DISCLAIMER,
        "",
        f"Сиды: {rep['exclusion']['seeds']}. Полнота при доле ложных срабатываний на норме "
        "валидации; "
        "в скобках интервал Уилсона 95%.",
        "",
        "## Исключение инструмента",
        "",
        "| класс | инструмент | "
        + " | ".join(f"контроль@{float(f):.1%}" for f in fprs)
        + " | "
        + " | ".join(f"без него@{float(f):.1%}" for f in fprs)
        + " |",
        "|---|---|" + "---|" * (2 * len(fprs)),
    ]
    for r in rep["exclusion"]["tools"]:
        c = [f"{r['control'][f]['recall']:.3f}" for f in fprs]
        x = [
            f"{r['excluded'][f]['recall']:.3f} "
            f"({r['excluded'][f]['ci'][0]:.2f}–{r['excluded'][f]['ci'][1]:.2f})"
            for f in fprs
        ]
        lines.append(
            f"| {r['class']} | {r['tool']} | " + " | ".join(c) + " | " + " | ".join(x) + " |"
        )
    lines += [
        "",
        "## Исключение адреса источника",
        "",
        "| источник | "
        + " | ".join(f"контроль@{float(f):.1%}" for f in fprs)
        + " | "
        + " | ".join(f"без него@{float(f):.1%}" for f in fprs)
        + " |",
        "|---|" + "---|" * (2 * len(fprs)),
    ]
    for r in rep["exclusion"]["hosts"]:
        c = [f"{r['control'][f]['recall']:.3f}" for f in fprs]
        x = [
            f"{r['excluded'][f]['recall']:.3f} "
            f"({r['excluded'][f]['ci'][0]:.2f}–{r['excluded'][f]['ci'][1]:.2f})"
            for f in fprs
        ]
        lines.append(f"| {r['source']} | " + " | ".join(c) + " | " + " | ".join(x) + " |")
    a = rep["env_audit"]
    lines += [
        "",
        "## Аудит признаков окружения",
        "",
        f"**Вердикт: {a['verdict']}** — PR-AUC «атака/норма» с признаками {a['pr_auc_full']}, без "
        "них "
        f"{a['pr_auc_without_env']} (падение {a['drop']}, порог {a['threshold']}).",
        "",
        "| признак | перестановочная важность | одиночный PR-AUC |",
        "|---|---|---|",
    ]
    for f in a["env_features"]:
        lines.append(
            f"| {f} | {a['permutation_importance'][f]} | {a['single_feature_pr_auc'][f]} |"
        )
    return "\n".join(lines) + "\n"


def write_report(
    rep: dict, dataset_dir: Path, reports_dir: Path, version: str
) -> tuple[Path, Path]:
    dataset_dir, reports_dir = Path(dataset_dir), Path(reports_dir)
    dataset_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    js = dataset_dir / "shortcuts.json"
    js.write_text(json.dumps(rep, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    md = reports_dir / f"lab_shortcuts_{version}.md"
    md.write_text(report_md(rep, version), encoding="utf-8")
    return md, js


def run_shortcuts(
    labeled: pl.DataFrame, *, source_ips: dict[str, str], cfg: dict, seeds=None, log=print
) -> dict:
    """Весь аудит: исключение инструмента/хоста и признаки окружения; `cfg` — раздел `shortcuts` "
    "конфига."""
    seeds = tuple(seeds if seeds is not None else cfg.get("seeds", (0, 1, 2)))
    fprs = tuple(cfg.get("fpr_levels", DEFAULT_FPR))
    min_test = int(cfg.get("min_test_flows", 100))
    return {
        "disclaimer": DISCLAIMER,
        "exclusion": run_exclusion(
            labeled, source_ips=source_ips, seeds=seeds, fprs=fprs, min_test_flows=min_test, log=log
        ),
        "env_audit": run_env_audit(
            labeled,
            env_features=cfg.get("env_features", DEFAULT_ENV_FEATURES),
            seeds=seeds,
            drop_threshold=float(cfg.get("audit_drop_threshold", 0.05)),
            log=log,
        ),
    }
