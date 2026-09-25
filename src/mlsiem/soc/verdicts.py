"""Вердикты модели по каждому потоку и алерты из них (FR-010, FR-011; фича 004 — FR-016, R8, R11).

Вердикт потока считает модель прогона через общий интерфейс `LoadedModel.verdict_frame`
(детектор 002 или ансамбль — цепочке всё равно):
- `attack_score` — скор атаки итогового вердикта, `is_alert` — скор ≥ порога модели;
- `predicted_class` — для алерта самый вероятный класс СРЕДИ АТАКУЮЩИХ, либо `anomaly`, если
  тревогу поднял только детектор аномалий; ниже порога — `benign`;
- `p_<класс>` — вероятности итогового вердикта; `e_<эксперт>_score/_fired` — ответы экспертов;
- `reversed` — правило направления признало поток ответным (фича 004);
- `true_label` — только при проигрывании размеченного разбиения и только для сводки.
  В модель метка не подаётся: эксперты берут исключительно признаки из своих карточек.

Алерт получает контекст для аналитика (адреса, порты, время), атакующую сторону и ответы
экспертов с объяснением — всё это пишется в SQLite, чтобы консоль и API не зависели от
parquet-файла прогона.

Вход сортируется по `flow_uid`, поэтому результат не зависит от порядка строк во входе.
"""

from __future__ import annotations

import json

import polars as pl

from mlsiem.detect.artifact import Detector
from mlsiem.soc.direction import DIRECTION_COLUMNS, RULE_TITLES, sides

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
# Поля потока, нужные цепочке помимо признаков модели: контекст алерта и правило направления
CONTEXT_COLUMNS = list(dict.fromkeys([*ALERT_CONTEXT, *DIRECTION_COLUMNS]))
# Колонка объяснения нужна только алертам (пишется в SQLite), в verdicts.parquet её нет
EXPLANATION = "explanation"


def _as_model(model):
    """Детектор 002 (как его передают старые вызовы) → общий интерфейс `LoadedModel`."""
    if isinstance(model, Detector):
        from mlsiem.detect.ensemble import LoadedModel

        return LoadedModel(kind="detector", version=model.version, selected=None, classifier=model)
    return model


def expert_names(verdicts: pl.DataFrame) -> list[str]:
    """Эксперты, чьи ответы есть в кадре вердиктов (по колонкам `e_<имя>_score`)."""
    return sorted(
        c[2 : -len("_score")]
        for c in verdicts.columns
        if c.startswith("e_") and c.endswith("_score")
    )


def compute_verdicts(model, flows: pl.DataFrame, *, direction: str = "auto") -> pl.DataFrame:
    """Вердикт для каждого потока.

    Колонки: flow_uid, predicted_class, attack_score, is_alert, p_<класс>…, e_<эксперт>_score,
    e_<эксперт>_fired, reversed, explanation (только у алертов), true_label (если во входе
    есть `label`). `model` — `LoadedModel` или детектор 002.
    """
    v = _as_model(model).verdict_frame(flows)
    side = sides(flows.sort("flow_uid"), direction).select("flow_uid", "reversed")
    v = v.join(side, on="flow_uid", how="left", maintain_order="left")
    # reversed ставим перед explanation/true_label — порядок колонок как в data-model
    tail = [c for c in (EXPLANATION, "true_label") if c in v.columns]
    return v.select([c for c in v.columns if c not in tail] + tail)


def _experts_json(row: dict, names: list[str], meta: dict[str, dict]) -> str | None:
    if not names:
        return None
    out = {
        n: {
            "score": row[f"e_{n}_score"],
            "threshold": (meta.get(n) or {}).get("threshold"),
            "fired": bool(row[f"e_{n}_fired"]),
        }
        for n in names
    }
    return json.dumps(out, ensure_ascii=False, sort_keys=True)


def alerts_from_verdicts(
    verdicts: pl.DataFrame,
    flows: pl.DataFrame,
    *,
    experts_meta: dict[str, dict] | None = None,
    direction: str = "auto",
) -> pl.DataFrame:
    """Алерты = потоки с is_alert, с контекстом, атакующей стороной и ответами экспертов.

    Поля identity/time здесь — только контекст для человека и ключ группировки; в модель
    они не попадали (FR-011). Исходные src_*/dst_* потока не меняются: для ответного потока
    меняется лишь то, кто считается атакующим (`attacker_ip`), и это видно в `reversed`.
    """
    context = flows.select([pl.col(src).alias(dst) for src, dst in ALERT_CONTEXT.items()])
    keep = ["flow_uid", "predicted_class", "attack_score"]
    if "true_label" in verdicts.columns:
        keep.append("true_label")
    names = expert_names(verdicts)
    extra = [c for c in verdicts.columns if c.startswith("e_")]
    if EXPLANATION in verdicts.columns:
        extra.append(EXPLANATION)
    alerts = verdicts.filter(pl.col("is_alert")).select([*keep, *extra])
    side = sides(flows.filter(pl.col("flow_uid").is_in(alerts["flow_uid"].implode())), direction)
    alerts = (
        alerts.join(context, on="flow_uid", how="left")
        .join(side, on="flow_uid", how="left")
        .sort("flow_uid")
    )

    meta = experts_meta or {}
    experts_col, fired_col, expl_col = [], [], []
    for row in alerts.iter_rows(named=True):
        experts_col.append(_experts_json(row, names, meta))
        fired = sorted(n for n in names if row[f"e_{n}_fired"])
        fired_col.append(",".join(fired) if names else None)
        text = row.get(EXPLANATION)
        if row["reversed"]:
            addition = (
                f"поток ответный: атакующая сторона — {row['attacker_ip']} "
                f"(правило: {RULE_TITLES[row['direction_rule']]})"
            )
            text = f"{text}; {addition}" if text else addition
        expl_col.append(text)

    return alerts.with_columns(
        pl.Series("experts", experts_col, dtype=pl.String),
        pl.Series("fired_experts", fired_col, dtype=pl.String),
        pl.Series(EXPLANATION, expl_col, dtype=pl.String),
        pl.col("reversed").cast(pl.Int64),
    ).select(
        [
            *ALERT_CONTEXT.values(),
            *keep[1:],
            "attacker_ip",
            "victim_ip",
            "reversed",
            "direction_rule",
            "fired_experts",
            "experts",
            EXPLANATION,
        ]
    )
