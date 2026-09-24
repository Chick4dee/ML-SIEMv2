"""Кандидаты-детекторы и правило выбора победителя (research R1, R4, R7).

Каждый кандидат — `sklearn.Pipeline` «предобработка → модель». Предобработка живёт внутри
конвейера и сохраняется вместе с моделью: при инференсе нельзя «забыть» log1p или взять
другое масштабирование (train = serve, принцип II).

- `logreg` — бейзлайн: log1p (признаки потоков — счётчики и байты с тяжёлым хвостом),
  стандартизация, мультиклассовая логистическая регрессия (lbfgs детерминирован).
- `lgbm` — LightGBM на сырых признаках: деревьям масштаб не важен. Для воспроизводимости
  (SC-002) — deterministic, force_row_wise и фиксированное число потоков.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

# Фиксированное число потоков LightGBM: от него зависит порядок суммирования, а значит —
# последние знаки результата. 8 — половина логических ядер машины владельца с запасом
LGBM_THREADS = 8


def _log1p_nonneg(x: np.ndarray) -> np.ndarray:
    # Признаки потоков неотрицательны; clip страхует от случайного −0 или мусора во входе.
    # Функция модульная (не лямбда) — иначе конвейер не сохранится через joblib
    return np.log1p(np.clip(x, 0, None))


def build_candidate(name: str, params: dict[str, Any], seed: int) -> Pipeline:
    """Собирает конвейер кандидата с гиперпараметрами из конфига."""
    params = dict(params)
    if name == "logreg":
        model = LogisticRegression(solver="lbfgs", random_state=seed, **params)
        return Pipeline(
            [
                ("log1p", FunctionTransformer(_log1p_nonneg, validate=False)),
                ("scale", StandardScaler()),
                ("model", model),
            ]
        )
    if name == "lgbm":
        from lightgbm import LGBMClassifier  # тяжёлый импорт — только когда нужен

        # objective не задаём: LGBMClassifier сам берёт multiclass при >2 классах
        # и binary при двух (на реальных данных классов всегда 10)
        model = LGBMClassifier(
            deterministic=True,
            force_row_wise=True,
            num_threads=LGBM_THREADS,
            random_state=seed,
            verbose=-1,
            **params,
        )
        return Pipeline([("model", model)])
    raise ValueError(f"неизвестный кандидат {name!r}: поддерживаются logreg и lgbm")


def select_winner(
    results: dict[str, dict], *, baseline: str = "logreg", min_gain: float
) -> tuple[str, str]:
    """Выбирает победителя ТОЛЬКО по macro PR-AUC на val (research R4).

    results: имя кандидата → словарь, где есть `macro_pr_auc_val`. Метрики test сюда могут
    приходить, но не читаются — выбор по test был бы подгонкой под test.
    Возвращает (победитель, человеческое объяснение выбора).
    """
    if baseline not in results:
        raise ValueError(f"нет результатов бейзлайна {baseline!r}")
    base = results[baseline]["macro_pr_auc_val"]
    best = max(results, key=lambda n: (results[n]["macro_pr_auc_val"], n == baseline))
    best_val = results[best]["macro_pr_auc_val"]
    if best == baseline:
        return baseline, (
            f"бейзлайн {baseline} лучший на val (macro PR-AUC {base:.4f}) — выбран он"
        )
    gain = best_val - base
    if gain >= min_gain:
        return best, (
            f"{best} лучше бейзлайна {baseline} на val на {gain:.4f} macro PR-AUC "
            f"({best_val:.4f} против {base:.4f}) ≥ порога {min_gain} — выбран {best}"
        )
    return baseline, (
        f"{best} лучше бейзлайна {baseline} на val всего на {gain:.4f} macro PR-AUC "
        f"(< порога {min_gain}) — при равном качестве выбран более простой {baseline}"
    )
