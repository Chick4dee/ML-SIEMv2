"""Вердикты детектора по каждому потоку и алерты из них (FR-010, FR-011).

Вердикт потока:
- `attack_score` = 1 − P(benign) — насколько поток «не фоновый»;
- `is_alert` = attack_score ≥ порога детектора (порог выбран на val в эксперименте);
- `predicted_class` — для алерта самый вероятный класс СРЕДИ АТАКУЮЩИХ (аналитику нужен ответ
  «какая это атака», а не «скорее всего benign, но скор выше порога»); для потока ниже
  порога — `benign`;
- вероятности по всем классам (`p_<класс>`) — для разбора и отладки;
- `true_label` — только при проигрывании размеченного разбиения и только для сводки
  «сколько алертов верные». В детектор метка не подаётся: `Detector.predict_proba` берёт
  исключительно признаки из карточки.

Вход сортируется по `flow_uid`, поэтому результат не зависит от порядка строк во входе.
"""

from __future__ import annotations

import numpy as np
import polars as pl

from mlsiem.detect.artifact import Detector
from mlsiem.detect.metrics import BENIGN, attack_score

# Контекст алерта: какие поля потока 001 берутся и как называются в алерте
ALERT_CONTEXT = {
    "flow_uid": "flow_uid",
    "capture_id": "capture_id",
    "src_ip": "src_ip",
    "src_port": "src_port",
    "dst_ip": "dst_ip",
    "dst_port": "dst_port",
    "protocol": "protocol",
    "bidirectional_first_seen_ms": "first_seen_ms",
    "bidirectional_last_seen_ms": "last_seen_ms",
}


def compute_verdicts(detector: Detector, flows: pl.DataFrame) -> pl.DataFrame:
    """Вердикт для каждого потока. Колонки: flow_uid, predicted_class, attack_score, is_alert,
    p_<класс>…, и true_label, если во входе есть колонка `label`."""
    flows = flows.sort("flow_uid")
    classes = detector.classes
    proba = np.zeros((0, len(classes))) if flows.height == 0 else detector.predict_proba(flows)
    score = attack_score(proba, classes)
    is_alert = score >= detector.threshold

    attack_idx = [i for i, c in enumerate(classes) if c != BENIGN]
    attack_names = np.array([classes[i] for i in attack_idx], dtype=object)
    if proba.shape[0]:
        top_attack = attack_names[np.argmax(proba[:, attack_idx], axis=1)]
    else:
        top_attack = np.array([], dtype=object)
    predicted = np.where(is_alert, top_attack, BENIGN)

    cols = [
        flows["flow_uid"],
        pl.Series("predicted_class", predicted.astype(str), dtype=pl.String),
        pl.Series("attack_score", score, dtype=pl.Float64),
        pl.Series("is_alert", is_alert, dtype=pl.Boolean),
    ]
    cols += [pl.Series(f"p_{c}", proba[:, i], dtype=pl.Float64) for i, c in enumerate(classes)]
    if "label" in flows.columns:
        cols.append(flows["label"].alias("true_label"))
    return pl.DataFrame(cols)


def alerts_from_verdicts(verdicts: pl.DataFrame, flows: pl.DataFrame) -> pl.DataFrame:
    """Алерты = потоки с is_alert, с контекстом для аналитика (адреса, порты, время).

    Поля identity/time здесь — только контекст для человека и ключ группировки; в детектор
    они не попадали (FR-011).
    """
    context = flows.select([pl.col(src).alias(dst) for src, dst in ALERT_CONTEXT.items()])
    keep = ["flow_uid", "predicted_class", "attack_score"]
    if "true_label" in verdicts.columns:
        keep.append("true_label")
    return (
        verdicts.filter(pl.col("is_alert"))
        .select(keep)
        .join(context, on="flow_uid", how="left")
        .select([*ALERT_CONTEXT.values(), *keep[1:]])
        .sort("flow_uid")
    )
