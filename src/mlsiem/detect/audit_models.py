"""Аудит артефактов экспертов и мета-слоя (фича 004, research R6, FR-012, принцип III).

Зачем. В UNSW-NB15 норму и атаки генерировали разные инструменты. Модель может научиться
отличать не «поведение атаки», а «почерк генератора» — например, один признак, который у
всех атак случайно одинаковый. Цифры тогда выходят прекрасными, а на живом трафике модель
бесполезна. Именно так в v1 автокодировщик получил «ROC-AUC 0.98». Поэтому у каждого
эксперта проверяется:

- однопризнаковый зонд: PR-AUC «атака / не атака» на val для КАЖДОГО признака в одиночку
  (и для его знака — атака может быть и «меньше»). Признак, который один даёт PR-AUC ≥ 0.9,
  помечается: одним числом настоящие атаки обычно не отделяются;
- перестановочная важность: насколько падает PR-AUC скора эксперта, если перемешать
  один признак, — на что эксперт реально опирается;
- для стекинга — веса логистической регрессии по входам: не держится ли решение целиком
  на одном эксперте.

Решение по помеченным признакам (исключить через `anomaly.exclude_features` или оставить
с пометкой «завышено») принимает владелец; модуль только собирает факты и пишет абзац.
"""

from __future__ import annotations

from collections.abc import Callable

import numpy as np

from mlsiem.detect.metrics import binary_pr_auc


def single_feature_probe(
    X_val: np.ndarray, y_attack: np.ndarray, features: list[str], *, flag_at: float = 0.9
) -> list[dict]:
    """PR-AUC каждого признака в одиночку (лучший из знаков «больше» и «меньше»).

    Возвращает список по убыванию PR-AUC: признак, PR-AUC, знак, помечен ли. Без атак или
    без нормы в val метрика не определена — возвращается пустой список.
    """
    y = np.asarray(y_attack, dtype=bool)
    if not y.any() or y.all():
        return []
    rows = []
    for j, name in enumerate(features):
        col = np.asarray(X_val[:, j], dtype=np.float64)
        up, down = binary_pr_auc(y, col), binary_pr_auc(y, -col)
        sign, value = ("+", up) if up >= down else ("−", down)
        rows.append(
            {"feature": name, "pr_auc": float(value), "sign": sign, "flagged": value >= flag_at}
        )
    rows.sort(key=lambda r: (-r["pr_auc"], r["feature"]))
    return rows


def permutation_importance_score(
    score_fn: Callable[[np.ndarray], np.ndarray],
    X_val: np.ndarray,
    y_attack: np.ndarray,
    features: list[str],
    *,
    seed: int,
    top: int = 10,
    max_rows: int | None = None,
) -> dict:
    """Падение PR-AUC «атака/не атака» скора эксперта при перемешивании каждого признака.

    Детерминировано: и подвыборка строк, и перестановки — от одного сида. Подвыборка
    (`max_rows`) нужна ради времени: 58 пересчётов скора на 250 тыс. потоков — долго, а
    порядок важностей на 50 тыс. тот же.
    """
    rng = np.random.default_rng(seed)
    X = np.asarray(X_val)
    y = np.asarray(y_attack, dtype=bool)
    if max_rows is not None and len(X) > max_rows:
        idx = np.sort(rng.choice(len(X), size=max_rows, replace=False))
        X, y = X[idx], y[idx]
    base = binary_pr_auc(y, score_fn(X))
    if base is None:
        return {"base_pr_auc": None, "n_rows": int(len(X)), "top": []}
    drops = []
    for j, name in enumerate(features):
        Xp = X.copy()
        Xp[:, j] = Xp[rng.permutation(len(Xp)), j]
        value = binary_pr_auc(y, score_fn(Xp))
        drops.append({"feature": name, "drop": float(base - (value or 0.0))})
    drops.sort(key=lambda r: (-r["drop"], r["feature"]))
    return {"base_pr_auc": float(base), "n_rows": int(len(X)), "top": drops[:top]}


def meta_weights(stack_model, input_names: list[str], expert_of: dict[str, str]) -> dict:
    """Вклад экспертов в стекинг: доли суммы |весов| логрега по входам каждого эксперта.

    `expert_of` — вход → эксперт (`logp_exploits` → `classifier`, `anomaly_pct` → `anomaly`).
    Входы стандартизуются внутри мета-модели, так что веса сравнимы между собой.
    """
    per_class = stack_model.weights(input_names)
    totals: dict[str, float] = {}
    for weights in per_class.values():
        for name, w in weights.items():
            totals[expert_of[name]] = totals.get(expert_of[name], 0.0) + abs(w)
    s = sum(totals.values()) or 1.0
    return {
        "by_expert": {k: round(v / s, 4) for k, v in sorted(totals.items())},
        "per_class": {c: {k: round(v, 4) for k, v in w.items()} for c, w in per_class.items()},
    }


def audit_text(probe: list[dict], excluded: list[str] | tuple[str, ...]) -> str:
    """Абзац «что подозрительно и что решено» для отчёта и карточки."""
    flagged = [r for r in probe if r["flagged"]]
    if not flagged:
        return (
            "Ни один признак в одиночку не отделяет атаки от нормы на val (PR-AUC ниже порога "
            "пометки) — грубых артефактов генератора зонд не нашёл."
        )
    names = ", ".join(f"{r['feature']} ({r['pr_auc']:.3f})" for r in flagged)
    text = (
        f"Подозрение на артефакт генератора: признаки, в одиночку отделяющие атаки от нормы, — "
        f"{names}. Цифры эксперта, опирающегося на них, вероятно, завышены."
    )
    if excluded:
        text += f" Исключены из входа по решению владельца: {', '.join(excluded)}."
    else:
        text += (
            " Пока оставлены с пометкой «завышено»; исключить — через "
            "anomaly.exclude_features в configs/ensemble.yaml и перезапуск эксперимента."
        )
    return text


def audit_expert(
    score_fn: Callable[[np.ndarray], np.ndarray],
    X_val: np.ndarray,
    y_attack: np.ndarray,
    features: list[str],
    *,
    seed: int,
    flag_at: float,
    top: int,
    max_rows: int,
    excluded: list[str] | tuple[str, ...] = (),
) -> dict:
    """Полный аудит эксперта: зонд + перестановочная важность + вывод словами."""
    probe = single_feature_probe(X_val, y_attack, features, flag_at=flag_at)
    perm = permutation_importance_score(
        score_fn, X_val, y_attack, features, seed=seed, top=top, max_rows=max_rows
    )
    return {
        "probe_top": probe[:top],
        "flagged_features": [r["feature"] for r in probe if r["flagged"]],
        "flag_at": flag_at,
        "permutation": perm,
        "excluded_features": list(excluded),
        "text": audit_text(probe, excluded),
    }
