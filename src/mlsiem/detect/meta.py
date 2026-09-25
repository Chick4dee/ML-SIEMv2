"""Мета-слой: как из ответов двух экспертов получить один вердикт (фича 004, research R3, R4).

Эксперты:
- `classifier` — классификатор 002: вероятности 10 классов, его скор атаки `1 − P(benign)`
  и его собственный порог (0.986 на реальных данных);
- `anomaly` — детектор аномалий: перцентиль нормы в [0, 1] и свой порог (0.5% нормы val).

Кандидаты мета-слоя — от простого к сложному (принцип IV: «а надо ли было учить?»):
- `any_fired` — без обучения: алерт, если сработал хотя бы один эксперт на своём пороге;
- `mean_score` — без обучения: скор атаки — среднее скоров двух экспертов, порог — по F1 на val;
- `stack_logreg` — стекинг: логистическая регрессия на ответах экспертов, выход — 10
  вероятностей классов. Вход — ТОЛЬКО ответы экспертов, признаков потока здесь нет вовсе.

Выход любого кандидата один и тот же — матрица вероятностей в порядке классов
классификатора. Поэтому macro PR-AUC ансамбля считается ровно как у классификатора 002, и
цифры можно сравнивать напрямую. У правил без обучения «вероятности» — это вероятности
классификатора, пересчитанные так, чтобы `1 − P(benign)` равнялось скору правила, а доли
атакующих классов между собой не менялись.

Где учится стекинг (R3): эксперты учились на train, и на train их уверенность завышена —
мета-слой, увидевший её, научился бы верить им слепо (классическая утечка стекинга). Поэтому
мета-слой учится на val, а честная оценка на той же val получается out-of-fold: val режется
на K последовательных по времени блоков, каждый блок предсказывается моделью, обученной на
остальных. Блоки, а не случайные фолды — потому что потоки одной атаки идут пачками по
времени, и случайные фолды разнесли бы одну сессию по обе стороны.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

import numpy as np

from mlsiem.detect.metrics import ANOMALY_CLASS, BENIGN

EPS = 1e-6
# Кандидаты без обучения: им не нужны ни фолды, ни meta.joblib
RULE_CANDIDATES = ("any_fired", "mean_score")
# Порог правила any_fired на общей шкале (см. `_to_common_scale`) — фиксирован, не подбирается
ANY_FIRED_THRESHOLD = 0.5

# Русские имена экспертов — для объяснений (консоль берёт свои подписи из ui/labels.py)
EXPERT_TITLES = {"classifier": "классификатор", "anomaly": "детектор аномалий"}


# ---------------------------------------------------------------- блоки времени и OOF


@dataclass(frozen=True)
class TimeBlocks:
    """K последовательных блоков val по времени начала потока + зазоры у границ."""

    block: np.ndarray  # номер блока каждого потока, 0…k−1
    boundaries: np.ndarray  # k−1 границ (мс): блок i — время в [b_{i−1}, b_i)
    first_seen_ms: np.ndarray
    gap_ms: int

    @property
    def k(self) -> int:
        return len(self.boundaries) + 1

    def folds(self) -> Iterator[tuple[np.ndarray, np.ndarray]]:
        """(индексы обучения, индексы предсказания) для каждого блока.

        Блок j предсказывается моделью, обученной на остальных блоках, КРОМЕ потоков ближе
        `gap_ms` к границам блока j: сессия, начавшаяся у самой границы, могла перетечь в
        соседний блок, и тогда модель видела бы «продолжение» предсказываемой атаки.
        """
        t = self.first_seen_ms
        for j in range(self.k):
            pred = np.flatnonzero(self.block == j)
            near = np.zeros(len(t), dtype=bool)
            for edge in (j - 1, j):  # левая и правая границы блока j
                if 0 <= edge < len(self.boundaries):
                    near |= np.abs(t - self.boundaries[edge]) < self.gap_ms
            train = np.flatnonzero((self.block != j) & ~near)
            yield train, pred


def time_blocks(first_seen_ms: np.ndarray, k: int, gap_ms: int) -> TimeBlocks:
    """Делит потоки на `k` последовательных блоков по квантилям времени начала (R3)."""
    if k < 2:
        raise ValueError(f"для out-of-fold нужно хотя бы 2 блока, а задано {k}")
    t = np.asarray(first_seen_ms, dtype=np.int64)
    if t.size < k:
        raise ValueError(f"потоков ({t.size}) меньше, чем блоков ({k}) — out-of-fold невозможен")
    order = np.sort(t)
    # Граница блока — время потока на i/k-й доле: так блоки примерно равны по числу потоков
    bounds = order[[int(round(i * t.size / k)) for i in range(1, k)]]
    block = np.searchsorted(bounds, t, side="right")
    sizes = np.bincount(block, minlength=k)
    if (sizes == 0).any():
        raise ValueError(
            f"пустой блок времени (размеры {sizes.tolist()}): у потоков слишком мало разных "
            "времён начала — уменьшите meta.folds"
        )
    return TimeBlocks(block=block, boundaries=bounds, first_seen_ms=t, gap_ms=int(gap_ms))


def oof_predict(
    fit_fn: Callable[[np.ndarray, np.ndarray], Callable[[np.ndarray], np.ndarray]],
    X: np.ndarray,
    y: np.ndarray,
    blocks: TimeBlocks,
) -> np.ndarray:
    """Out-of-fold предсказания: каждый блок — моделью, не видевшей его (и зазоров у него).

    `fit_fn(X_train, y_train)` возвращает функцию «X → вероятности». Результат — строки
    в исходном порядке X; каждая строка предсказана ровно один раз.
    """
    out: np.ndarray | None = None
    for train_idx, pred_idx in blocks.folds():
        predict = fit_fn(X[train_idx], np.asarray(y)[train_idx])
        p = predict(X[pred_idx])
        if out is None:
            out = np.zeros((len(X), p.shape[1]))
        out[pred_idx] = p
    assert out is not None
    return out


# ---------------------------------------------------------------- вход и кандидаты


def meta_input(P: np.ndarray, anomaly_pct: np.ndarray) -> np.ndarray:
    """Вход стекинга: log(p + ε) по 10 вероятностям классификатора и перцентиль аномальности.

    Логарифм — потому что у бустинга уверенности прижаты к 0 и 1, и разница «0.999 против
    0.9999» (в 10 раз меньше шансов на ошибку) в сырых вероятностях почти не видна.
    """
    return np.hstack([np.log(np.asarray(P) + EPS), np.asarray(anomaly_pct)[:, None]])


def _to_common_scale(score: np.ndarray, threshold: float) -> np.ndarray:
    """Монотонно переводит скор эксперта на шкалу [0, 1], где его порог — ровно 0.5.

    Зачем: у классификатора порог 0.986, у детектора аномалий — ~0.995; чтобы правило
    «сработал хоть один» было обычным «скор ≥ порога», как у всех вариантов, скоры
    приводятся к общей шкале, где у обоих порог одинаковый. Порядок потоков внутри
    эксперта не меняется, так что PR-AUC каждого эксперта от этого не меняется.
    """
    s = np.asarray(score, dtype=np.float64)
    t = float(threshold)
    if t <= 0:
        return 0.5 + 0.5 * s
    if t >= 1:
        return 0.5 * s / t
    return np.where(s < t, 0.5 * s / t, 0.5 + 0.5 * (s - t) / (1 - t))


def rescale_proba(P: np.ndarray, classes: list[str], score: np.ndarray) -> np.ndarray:
    """Вероятности классификатора, пересчитанные под новый скор атаки.

    P(benign) := 1 − score; доли атакующих классов между собой — как у классификатора.
    Если классификатор совсем уверен в норме (сумма атак 0) — атака делится поровну.
    """
    P = np.asarray(P, dtype=np.float64)
    b = classes.index(BENIGN)
    attack_idx = [i for i in range(len(classes)) if i != b]
    att = P[:, attack_idx]
    total = att.sum(axis=1, keepdims=True)
    share = np.where(total > 0, att / np.where(total > 0, total, 1), 1.0 / len(attack_idx))
    out = np.zeros_like(P)
    out[:, b] = 1.0 - score
    out[:, attack_idx] = share * np.asarray(score)[:, None]
    return out


def rule_scores(
    variant: str,
    P: np.ndarray,
    classes: list[str],
    anomaly_pct: np.ndarray,
    clf_threshold: float,
    anomaly_threshold: float,
) -> np.ndarray:
    """Скор атаки правила без обучения (`any_fired` или `mean_score`)."""
    s_c = 1.0 - np.asarray(P)[:, classes.index(BENIGN)]
    if variant == "any_fired":
        # Скор = максимум двух экспертов на общей шкале: он ≥ 0.5 ровно тогда, когда
        # хотя бы один эксперт сработал на СВОЁМ пороге (R4, FR-009)
        return np.maximum(
            _to_common_scale(s_c, clf_threshold), _to_common_scale(anomaly_pct, anomaly_threshold)
        )
    if variant == "mean_score":
        return (s_c + np.asarray(anomaly_pct)) / 2.0
    raise ValueError(f"{variant!r} — не правило без обучения ({RULE_CANDIDATES})")


class StackModel:
    """Стекинг: мультиклассовая логистическая регрессия на ответах экспертов (R4).

    `class_weight=balanced` — иначе на val с 43 `backdoor` и 250 тыс. нормы регрессия
    выучила бы «всегда норма». Классы, которых нет в обучающей части (фолд без `worms`),
    получают вероятность 0 — выход всегда в порядке классов классификатора.
    """

    def __init__(self, classes: list[str], seed: int) -> None:
        self.classes = list(classes)
        self.seed = seed
        self.pipeline = None
        self.fitted_classes: list[str] = []

    def fit(self, X_meta: np.ndarray, y: np.ndarray) -> StackModel:
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        self.pipeline = Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "model",
                    LogisticRegression(
                        class_weight="balanced", random_state=self.seed, max_iter=1000
                    ),
                ),
            ]
        )
        self.pipeline.fit(X_meta, np.asarray(y))
        self.fitted_classes = [str(c) for c in self.pipeline.classes_]
        return self

    def predict_proba(self, X_meta: np.ndarray) -> np.ndarray:
        p = self.pipeline.predict_proba(X_meta)
        out = np.zeros((len(X_meta), len(self.classes)))
        for j, cls in enumerate(self.fitted_classes):
            if cls in self.classes:
                out[:, self.classes.index(cls)] = p[:, j]
        return out

    def weights(self, input_names: list[str]) -> dict[str, dict[str, float]]:
        """Веса логрега по входам для каждого класса — «на что опирается мета-слой» (R6)."""
        coef = self.pipeline.named_steps["model"].coef_
        if coef.shape[0] == 1:  # бинарный случай — одна строка на «второй» класс
            return {
                self.fitted_classes[1]: dict(zip(input_names, map(float, coef[0]), strict=True))
            }
        return {
            cls: dict(zip(input_names, map(float, row), strict=True))
            for cls, row in zip(self.fitted_classes, coef, strict=True)
        }


def meta_proba(
    variant: str,
    P: np.ndarray,
    classes: list[str],
    anomaly_pct: np.ndarray,
    clf_threshold: float,
    anomaly_threshold: float,
    stack: StackModel | None = None,
) -> np.ndarray:
    """Единый выход любого кандидата: вероятности в порядке классов классификатора."""
    if variant in RULE_CANDIDATES:
        score = rule_scores(variant, P, classes, anomaly_pct, clf_threshold, anomaly_threshold)
        return rescale_proba(P, classes, score)
    if variant == "stack_logreg":
        if stack is None:
            raise ValueError("для stack_logreg нужна обученная мета-модель")
        return stack.predict_proba(meta_input(P, anomaly_pct))
    raise ValueError(f"неизвестный кандидат мета-слоя {variant!r}")


# ---------------------------------------------------------------- итоговый класс и объяснение


def top_attack(P: np.ndarray, classes: list[str]) -> np.ndarray:
    """Самый вероятный класс СРЕДИ АТАКУЮЩИХ — как класс алерта в 002."""
    attack_idx = [i for i, c in enumerate(classes) if c != BENIGN]
    names = np.array([classes[i] for i in attack_idx], dtype=object)
    if len(P) == 0:
        return np.array([], dtype=object)
    return names[np.argmax(np.asarray(P)[:, attack_idx], axis=1)]


def final_class(
    proba: np.ndarray,
    classes: list[str],
    is_alert: np.ndarray,
    clf_fired: np.ndarray,
    anomaly_fired: np.ndarray | None,
) -> np.ndarray:
    """Итоговый класс потока (FR-017, R4).

    - ниже порога ансамбля — `benign`;
    - алерт поднят, классификатор на своём пороге НЕ сработал, а детектор аномалий
      сработал — `anomaly`: тревога есть, а что это за атака, никто не знает, и честнее
      так и сказать, чем выдать самый вероятный класс, в котором классификатор не уверен;
    - иначе — самый вероятный класс атаки мета-выхода.
    """
    cls = np.where(np.asarray(is_alert), top_attack(proba, classes), BENIGN).astype(object)
    if anomaly_fired is not None:
        only_anomaly = np.asarray(is_alert) & ~np.asarray(clf_fired) & np.asarray(anomaly_fired)
        cls[only_anomaly] = ANOMALY_CLASS
    return cls.astype(str)


def _pct(x: float) -> str:
    """0.998 → «99.8» (перцентиль в процентах, одна цифра после точки)."""
    return f"{x * 100:.1f}"


def explain(
    *,
    clf_class: str,
    clf_score: float,
    clf_threshold: float,
    clf_fired: bool,
    anomaly_score: float | None = None,
    anomaly_threshold: float | None = None,
    anomaly_fired: bool | None = None,
    meta_score: float | None = None,
    meta_threshold: float | None = None,
) -> str:
    """Одна-две фразы по-русски: почему это алерт (data-model «Объяснение»).

    Детерминировано: одни и те же числа — один и тот же текст. Числа округлены так же,
    как их видит аналитик в таблице экспертов.
    """
    clf = f"классификатор ({clf_class}, {clf_score:.3f} ≥ {clf_threshold:.3f})"
    if anomaly_score is None:
        # Одиночный детектор 002 — эксперт один
        return f"сработал {clf}"
    an = f"детектор аномалий ({_pct(anomaly_score)}-й перцентиль нормы ≥ {_pct(anomaly_threshold)})"
    if clf_fired and anomaly_fired:
        return f"сработали {clf} и {an}"
    if clf_fired:
        return (
            f"сработал только {clf}; детектор аномалий — нет "
            f"({_pct(anomaly_score)}-й перцентиль < {_pct(anomaly_threshold)})"
        )
    if anomaly_fired:
        return f"сработал только {an} — класс атаки неизвестен"
    return (
        f"ни один эксперт не превысил свой порог, алерт поднял мета-слой "
        f"(скор {meta_score:.3f} ≥ {meta_threshold:.3f})"
    )
