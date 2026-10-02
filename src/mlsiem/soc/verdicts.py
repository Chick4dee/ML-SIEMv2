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


# ---------------------------------------------------------------- фича 007: алерты окон

WINDOW_EXPERT = "windows"
# Поля потока для таблицы «самые подозрительные потоки окна» в описании алерта окна
TOP_FLOW_COLUMNS = ("flow_uid", "victim_ip", "victim_port", "protocol", "flow_score")


def window_flow_context(flows: pl.DataFrame, side: pl.DataFrame, flow_verdicts: pl.DataFrame):
    """Контекст потоков для описания окна: цель и порт цели (сторона-жертва по правилу
    направления), протокол и скор модели потоков. Общий для пакета и потребителя."""
    df = flows.select("flow_uid", "src_port", "dst_port", "protocol").join(
        side.select("flow_uid", "reversed", "victim_ip"), on="flow_uid", how="left"
    )
    df = df.with_columns(
        pl.when(pl.col("reversed"))
        .then(pl.col("src_port"))
        .otherwise(pl.col("dst_port"))
        .alias("victim_port")
    )
    scores = flow_verdicts.select("flow_uid", pl.col("attack_score").alias("flow_score"))
    return df.join(scores, on="flow_uid", how="left").select(TOP_FLOW_COLUMNS)


def _window_explanation(row: dict, info: dict, kind: str, threshold: float) -> str:
    """Одна-две фразы: почему окно — атака (FR-017). Детерминированно, как у потоков."""
    targets = info["targets"]
    head = (
        f"окно {info['n_flows']} потоков за {(info['end_ms'] - info['start_ms']) // 1000} с "
        f"к {len(targets)} целям ({info['n_dst_ports']} портов): эксперт окон {kind}, скор "
        f"{row['attack_score']:.3f} ≥ {threshold:.3f}"
    )
    if info["top_features"]:
        names = ", ".join(f["name"] for f in info["top_features"][:3])
        head += f"; главные признаки окна: {names}"
    elif info["top_flows"]:
        flows = ", ".join(
            f"{f['flow_uid']} ({f['flow_score']:.3f})"
            for f in info["top_flows"][:3]
            if f["flow_score"] is not None
        )
        if flows:
            head += f"; самые подозрительные потоки: {flows}"
    if info["truncated"]:
        head += f"; нейросеть видела первые {info['seq_max']} потоков из {info['n_flows']}"
    return head


def alerts_from_window_verdicts(result, flow_context: pl.DataFrame, expert) -> pl.DataFrame:
    """Атакующие окна → строки алертов той же таблицы `alerts` (research R12, data-model).

    `flow_uid = window_id` (уникальность (прогон, flow_uid) сразу даёт идемпотентность),
    `src_ip = attacker_ip`, `dst_ip = victim_ip` — самая частая цель, порты и протокол — NULL,
    границы — старт первого и конец последнего потока окна. Описание окна — `window_info`
    (JSON): интервал, цели, число портов, до 20 самых подозрительных потоков и до 5 самых
    влиятельных признаков. Группировка в инциденты — та же, что у потоков.
    """
    v = result.verdicts.filter(pl.col("is_alert"))
    if v.height == 0:
        return pl.DataFrame()
    w = result.windows.join(v.select("window_id"), on="window_id", how="semi")
    per_flow = (
        w.select("window_id", pl.col("flow_uids").alias("flow_uid"))
        .explode("flow_uid", empty_as_null=True)
        .join(flow_context, on="flow_uid", how="left")
        .sort(
            ["window_id", "flow_score", "flow_uid"],
            descending=[False, True, False],
            nulls_last=True,
        )
    )
    top_flows: dict[str, list[dict]] = {}
    for wid, group in per_flow.group_by("window_id", maintain_order=True):
        top_flows[wid[0]] = [
            {
                "flow_uid": r["flow_uid"],
                "dst_ip": r["victim_ip"],
                "dst_port": r["victim_port"],
                "protocol": r["protocol"],
                "flow_score": None if r["flow_score"] is None else round(r["flow_score"], 6),
            }
            for r in group.head(20).iter_rows(named=True)
        ]
    by_id = {r["window_id"]: r for r in w.iter_rows(named=True)}
    rows = []
    for row in v.iter_rows(named=True):
        win = by_id[row["window_id"]]
        targets = [{"ip": t["ip"], "n": int(t["n"])} for t in win["targets"]]
        info = {
            "window_id": row["window_id"],
            "start_ms": int(win["window_start_ms"]),
            "end_ms": int(win["window_end_ms"]),
            "n_flows": int(win["n_flows"]),
            "truncated": bool(win["truncated"]),
            "seq_max": expert.seq_max,
            "targets": targets,
            "n_dst_ports": int(win["n_dst_ports"]),
            "top_flows": top_flows.get(row["window_id"], []),
            "top_features": result.top_features.get(row["window_id"], []),
            "expert_version": expert.version,
            "kind": expert.kind,
        }
        score = float(row["attack_score"])
        rows.append(
            {
                "flow_uid": row["window_id"],
                "capture_id": win["capture_id"],
                "src_ip": win["attacker_ip"],
                "src_port": None,
                "dst_ip": targets[0]["ip"] if targets else None,
                "dst_port": None,
                "protocol": None,
                "first_seen_ms": int(win["first_seen_ms"]),
                "last_seen_ms": int(win["last_seen_ms"]),
                "predicted_class": row["predicted_class"],
                "attack_score": score,
                "true_label": row.get("true_label"),
                "attacker_ip": win["attacker_ip"],
                "victim_ip": targets[0]["ip"] if targets else None,
                "reversed": 0,
                "direction_rule": "window",
                "fired_experts": WINDOW_EXPERT,
                "experts": json.dumps(
                    {WINDOW_EXPERT: {"score": score, "threshold": expert.threshold, "fired": True}},
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                EXPLANATION: _window_explanation(row, info, expert.kind, expert.threshold),
                "alert_kind": "window",
                "window_info": json.dumps(info, ensure_ascii=False, sort_keys=True),
            }
        )
    out = pl.DataFrame(
        rows,
        schema={
            "flow_uid": pl.String,
            "capture_id": pl.String,
            "src_ip": pl.String,
            "src_port": pl.Int64,
            "dst_ip": pl.String,
            "dst_port": pl.Int64,
            "protocol": pl.Int64,
            "first_seen_ms": pl.Int64,
            "last_seen_ms": pl.Int64,
            "predicted_class": pl.String,
            "attack_score": pl.Float64,
            "true_label": pl.String,
            "attacker_ip": pl.String,
            "victim_ip": pl.String,
            "reversed": pl.Int64,
            "direction_rule": pl.String,
            "fired_experts": pl.String,
            "experts": pl.String,
            EXPLANATION: pl.String,
            "alert_kind": pl.String,
            "window_info": pl.String,
        },
    )
    if "true_label" not in result.verdicts.columns:
        out = out.drop("true_label")
    return out.sort("flow_uid")


def with_flow_kind(alerts: pl.DataFrame) -> pl.DataFrame:
    """Алертам потоков — вид `flow` и пустое описание окна (колонки схемы 5)."""
    if "alert_kind" in alerts.columns:
        return alerts
    return alerts.with_columns(
        pl.lit("flow", dtype=pl.String).alias("alert_kind"),
        pl.lit(None, dtype=pl.String).alias("window_info"),
    )
