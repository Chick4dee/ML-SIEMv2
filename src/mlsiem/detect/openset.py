"""Способы оценки «неизвестного» по сырым выходам классификатора (фича 008, US5, R12, FR-022).

Все оценки считаются по ЛОГИТАМ (сырым выходам бустинга до softmax), а не по вероятностям:
вероятности насыщаются — у уверенной модели `1 − p` округляется до нуля, и разные по «странности»
потоки становятся неразличимы. Логиты и logsumexp такого не страдают.

Четыре оценки; у каждой БОЛЬШЕ = «подозрительнее»:
- `attack_vs_normal` — атака против нормы: `ln Σ_{c≠benign} exp z_c − z_benign` (логит «не норма»);
- `msp` — «не уверена в лучшем классе»: `1 − max softmax`, посчитанная устойчиво как доля всех
  остальных классов, `ln Σ_{c≠argmax} exp z_c − ln Σ exp z_c` (в логарифме, поэтому не насыщается);
- `energy` — энергия `−ln Σ exp z_c`: далёкий от всех классов поток имеет малые логиты;
- `combined` — объединение по p-значениям нормы валидации: для каждой оценки берём эмпирическую
  функцию
  распределения нормы `F_i`, итог — `max_i F_i(s_i)`. Тревога — когда ХОТЬ ОДНА оценка необычна для
  нормы.
  Порог объединения берётся по квантилю нормы валидации, поэтому доля тревог на норме ≈ α.

Модуль ничего не меняет в существующих детекторах: он читает выходы готовой модели.
"""

from __future__ import annotations

import numpy as np
from scipy.special import logsumexp

from mlsiem.detect.metrics import BENIGN

SCORES = ("attack_vs_normal", "msp", "energy")
METHODS = (*SCORES, "combined")


def raw_logits(model, X: np.ndarray) -> np.ndarray:
    """Сырые выходы бустинга LightGBM (n, K) из конвейера `build_candidate("lgbm")`.

    Для логистической регрессии берётся `decision_function`; для остальных — логарифм вероятностей
    (последнее честно лишь как запасной путь: так насыщение возвращается).
    """
    est = model.named_steps["model"] if hasattr(model, "named_steps") else model
    Xt = X
    if hasattr(model, "named_steps"):
        for name, step in model.named_steps.items():
            if name != "model":
                Xt = step.transform(Xt)
    if hasattr(est, "booster_"):
        z = np.asarray(est.predict(Xt, raw_score=True)).reshape(len(Xt), -1)
        if z.shape[1] == 1:
            # двухклассовый бустинг отдаёт один скор s (логит второго класса): пара [−s/2, s/2] даёт
            # те же вероятности через softmax и оценки по двум логитам вместо бесконечностей
            z = np.hstack([-z / 2, z / 2])
        return z
    if hasattr(est, "decision_function"):
        return np.asarray(est.decision_function(Xt)).reshape(len(Xt), -1)
    return np.log(np.clip(est.predict_proba(Xt), 1e-300, None))


def attack_vs_normal(z: np.ndarray, classes: list[str]) -> np.ndarray:
    """`ln Σ_{c≠benign} exp z_c − z_benign`."""
    b = classes.index(BENIGN)
    others = [i for i in range(z.shape[1]) if i != b]
    return logsumexp(z[:, others], axis=1) - z[:, b]


def msp(z: np.ndarray) -> np.ndarray:
    """Логарифм `1 − max softmax`: `ln Σ_{c≠argmax} exp z_c − ln Σ exp z_c` (не насыщается)."""
    total = logsumexp(z, axis=1)
    top = z.argmax(axis=1)
    masked = z.copy()
    masked[np.arange(len(z)), top] = -np.inf
    return logsumexp(masked, axis=1) - total


def energy(z: np.ndarray) -> np.ndarray:
    """`−ln Σ exp z_c`."""
    return -logsumexp(z, axis=1)


def all_scores(z: np.ndarray, classes: list[str]) -> dict[str, np.ndarray]:
    return {"attack_vs_normal": attack_vs_normal(z, classes), "msp": msp(z), "energy": energy(z)}


class NormalCalibrator:
    """Объединение оценок по p-значениям нормы валидации.

    `fit` запоминает отсортированные оценки нормы; `ecdf` — доля нормы СТРОГО ниже значения (близко
    к 1 —
    значение необычно большое для нормы); `combined` — максимум по оценкам. Строго «ниже», а не «не
    выше»:
    у нормы много одинаковых потоков (одиночные пакеты) и верх распределения — плато из ничьих; при
    «не выше» плато и всё, что выше него, получили бы 1.0 и порог упёрся бы в 1.0, а `>` не
    пропустил
    бы уже ничего. При «строго ниже» атака выше плато получает 1.0, сама норма на плато — меньше.
    """

    def __init__(self) -> None:
        self._norm: dict[str, np.ndarray] = {}
        self._threshold: dict[float, float] = {}

    def fit(self, normal_scores: dict[str, np.ndarray]) -> NormalCalibrator:
        self._norm = {k: np.sort(np.asarray(v, dtype=float)) for k, v in normal_scores.items()}
        self._combined_norm = np.sort(self.combined(normal_scores))
        return self

    def ecdf(self, name: str, values: np.ndarray) -> np.ndarray:
        ref = self._norm[name]
        # значение выше всей нормы получает ровно 1, не выше самой малой — 0; ничьи считаются «не
        # ниже»
        return np.searchsorted(ref, np.asarray(values, dtype=float), side="left") / len(ref)

    def combined(self, scores: dict[str, np.ndarray]) -> np.ndarray:
        return np.max(np.vstack([self.ecdf(k, scores[k]) for k in self._norm]), axis=0)

    def threshold(self, alpha: float) -> float:
        """Порог объединения: тревога при `combined > порога`; на норме валидации доля тревог ≈ "
        "α."""
        return float(np.quantile(self._combined_norm, 1 - alpha))


def thresholds_for(
    normal_scores: dict[str, np.ndarray], fprs
) -> tuple[dict[str, dict[float, float]], NormalCalibrator]:
    """Порог каждого способа на каждой доле ложных срабатываний (квантиль 1−f нормы валидации) и "
    "калибратор."""
    cal = NormalCalibrator().fit(normal_scores)
    out = {
        name: {f: float(np.quantile(v, 1 - f)) for f in fprs} for name, v in normal_scores.items()
    }
    out["combined"] = {f: cal.threshold(f) for f in fprs}
    return out, cal


def recall_by_method(
    scores: dict[str, np.ndarray], cal: NormalCalibrator, thr: dict[str, dict[float, float]], fprs
) -> dict[str, dict[float, float]]:
    """Полнота на потоках `scores` для каждого способа и доли ложных срабатываний."""
    comb = cal.combined(scores)
    out: dict[str, dict[float, float]] = {}
    for name in METHODS:
        s = comb if name == "combined" else np.asarray(scores[name], dtype=float)
        out[name] = {f: float((s > thr[name][f]).mean()) if len(s) else float("nan") for f in fprs}
    return out
