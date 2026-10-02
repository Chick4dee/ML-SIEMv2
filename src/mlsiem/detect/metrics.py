"""Метрики детектора (research R3).

- Главная метрика — PR-AUC по каждому классу (one-vs-rest, `average_precision_score`) и macro —
  среднее по классам, у которых в оцениваемой части есть примеры. Класс без примеров PR-AUC
  не имеет (нечего искать), поэтому помечается `None` и в macro не входит.
- Скор атаки — `1 − P(benign)`: насколько модель уверена, что поток НЕ фоновый.
- Порог «алерт / не алерт» выбирается на val как максимум F1 бинарной задачи; при равенстве F1
  берётся больший порог — меньше ложных тревог при той же пользе.
- `prior` — «угадывание по доле классов»: каждому потоку одни и те же вероятности, равные
  долям классов в train. Это нижняя граница: детектор, не обгоняющий её, ничего не выучил.
"""

from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

BENIGN = "benign"


def attack_score(proba: np.ndarray, classes: list[str]) -> np.ndarray:
    """Скор атаки = 1 − P(benign). Если класса benign у модели нет — ошибка, а не нули."""
    if BENIGN not in classes:
        raise ValueError(f"у модели нет класса {BENIGN!r}: скор атаки не определён")
    return 1.0 - proba[:, classes.index(BENIGN)]


def per_class_pr_auc(
    y: np.ndarray, proba: np.ndarray, classes: list[str]
) -> dict[str, float | None]:
    """PR-AUC по каждому классу; `None` — в части нет ни одного примера этого класса."""
    y = np.asarray(y)
    result: dict[str, float | None] = {}
    for i, cls in enumerate(classes):
        positive = y == cls
        result[cls] = (
            float(average_precision_score(positive, proba[:, i])) if positive.any() else None
        )
    return result


def macro_pr_auc(per_class: dict[str, float | None]) -> float:
    """Среднее PR-AUC по классам, у которых есть примеры."""
    values = [v for v in per_class.values() if v is not None]
    return float(np.mean(values)) if values else float("nan")


def classes_without_examples(per_class: dict[str, float | None]) -> list[str]:
    return sorted(c for c, v in per_class.items() if v is None)


def choose_threshold(y_true_attack: np.ndarray, scores: np.ndarray) -> float:
    """Порог скора атаки с максимальным F1 на переданной части (val).

    Кандидаты — все уникальные значения скора: правило «атака, если скор ≥ порога».
    Считается векторно по отсортированным скорам, так что и на сотнях тысяч потоков быстро.
    При равенстве F1 выбирается больший порог. Много одинаковых скоров не мешают: порог —
    это само значение скора, и все равные ему потоки оказываются по одну сторону.
    """
    y = np.asarray(y_true_attack, dtype=bool)
    s = np.asarray(scores, dtype=np.float64)
    if y.sum() == 0:
        # Атак нет вовсе — порог выше любого скора: ни одного алерта
        return float(np.nextafter(s.max(), np.inf)) if s.size else 1.0
    uniq = np.unique(s)  # по возрастанию
    order = np.argsort(s, kind="stable")
    s_sorted, y_sorted = s[order], y[order]
    # Для порога u: tp = число атак со скором ≥ u, pred = число потоков со скором ≥ u
    idx = np.searchsorted(s_sorted, uniq, side="left")
    tp_suffix = np.concatenate([np.cumsum(y_sorted[::-1])[::-1], [0]])
    tp = tp_suffix[idx]
    pred = len(s) - idx
    f1 = 2 * tp / (pred + y.sum())
    best = np.flatnonzero(f1 == f1.max())[-1]  # последний максимум = больший порог
    return float(uniq[best])


def binary_report(y_true_attack: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    """Вспомогательные метрики бинарной задачи при выбранном пороге (FR-002)."""
    y = np.asarray(y_true_attack, dtype=bool)
    pred = np.asarray(scores) >= threshold
    both = y.any() and (~y).any()
    return {
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, scores)) if both else None,
        "n_alerts": int(pred.sum()),
        "n_attacks": int(y.sum()),
    }


def prior_proba(y_train: np.ndarray, classes: list[str], n: int) -> np.ndarray:
    """Вероятности «по доле классов в train» для n потоков."""
    y_train = np.asarray(y_train)
    shares = np.array([(y_train == c).mean() for c in classes])
    return np.tile(shares, (n, 1))


def prior_baseline(y_train: np.ndarray, y_eval: np.ndarray, classes: list[str]) -> dict:
    """PR-AUC базовой линии prior на оцениваемой части.

    Все скоры одинаковы, поэтому PR-AUC каждого класса равен доле этого класса в части.
    """
    per_class = per_class_pr_auc(y_eval, prior_proba(y_train, classes, len(y_eval)), classes)
    return {"macro_pr_auc": macro_pr_auc(per_class), "per_class": per_class}


# ---------------------------------------------------------------- фича 004: эксперты и ансамбль

# Итоговый класс «сработал только детектор аномалий — что за атака, неизвестно» (FR-017).
# Одна константа на всех: её пишет мета-слой (detect/meta.py), а плейбуки (soc/playbooks.py)
# по ней включают страховку «только ручной разбор». Строка в двух местах разошлась бы молча
ANOMALY_CLASS = "anomaly"


def binary_pr_auc(y_attack: np.ndarray, score: np.ndarray) -> float | None:
    """PR-AUC задачи «атака / не атака» (FR-006).

    У детектора аномалий нет классов, поэтому с классификатором и ансамблем его сравнивают
    именно так. Если в части нет атак или нет нормы, метрика не определена — `None`, а не 0:
    «нечего искать» и «искали плохо» — разные вещи.
    """
    y = np.asarray(y_attack, dtype=bool)
    if not y.any() or y.all():
        return None
    return float(average_precision_score(y, np.asarray(score, dtype=np.float64)))


def catch_rate(y: np.ndarray, alerts: np.ndarray, cls: str) -> float | None:
    """«Поимка» класса: доля его потоков, ставших алертами (FR-011, эксперимент «скрытый класс»).

    Для неизвестного модели класса PR-AUC по нему не посчитать — у модели нет такого выхода.
    Зато можно спросить главное: сколько таких потоков вообще подняли тревогу. `None` —
    примеров класса в части нет.
    """
    mask = np.asarray(y) == cls
    if not mask.any():
        return None
    return float(np.asarray(alerts, dtype=bool)[mask].mean())


def fpr_on_benign(y: np.ndarray, alerts: np.ndarray) -> float | None:
    """Доля нормальных потоков, ставших алертами (SC-002, порог эксперта аномалий)."""
    mask = np.asarray(y) == BENIGN
    if not mask.any():
        return None
    return float(np.asarray(alerts, dtype=bool)[mask].mean())


def unreliable_classes(y: np.ndarray, classes: list[str], below: int = 50) -> list[str]:
    """Классы, у которых в части меньше `below` примеров (но хотя бы один).

    PR-AUC по 14 `worms` скачет от одного потока — такие цифры помечаются в отчёте
    «ненадёжен», чтобы по ним не делали выводов. Классы без примеров сюда не входят:
    для них PR-AUC и так не считается (`None`).
    """
    y = np.asarray(y)
    out = []
    for cls in classes:
        n = int((y == cls).sum())
        if 0 < n < below:
            out.append(cls)
    return sorted(out)


# ---------------------------------------------------------------- фича 007: окна


def reliable_classes(y: np.ndarray, classes: list[str], min_windows: int) -> list[str]:
    """Классы, у которых в части (val) не меньше `min_windows` примеров (research R8).

    На уровне окон большинство классов атак представлены единицами (analysis — 5 окон на val,
    dos — 1): их PR-AUC 0 или 1 почти случайно. В метрику выбора идут только «надёжные»
    классы; benign — по тому же правилу, без исключений. Порог записан в конфиг до запуска.
    """
    y = np.asarray(y)
    return [c for c in classes if int((y == c).sum()) >= min_windows]


def macro_pr_auc_reliable(per_class: dict[str, float | None], reliable: list[str]) -> float:
    """Macro PR-AUC только по надёжным классам (метрика выбора фичи 007).

    Если надёжны все классы с примерами, результат совпадает с `macro_pr_auc`.
    """
    values = [per_class[c] for c in reliable if per_class.get(c) is not None]
    return float(np.mean(values)) if values else float("nan")
