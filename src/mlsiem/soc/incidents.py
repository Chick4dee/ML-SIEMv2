"""Группировка алертов в инциденты и серьёзность (FR-012, FR-013, research R9, R10).

Группировка: ключ — (атакующая сторона, класс атаки). С фичи 004 атакующая сторона —
`attacker_ip` алерта: для ответного потока «сервер → клиент» это клиент, а не src_ip
(правило направления — soc/direction.py, research R8). Цели инцидента — `victim_ip`.
Если у алертов нет этих полей (вызовы 002 и их тесты), атакующий = src_ip, как было.
Алерты ключа идут по времени начала потока
(при равенстве — по flow_uid); если до предыдущего алерта того же ключа прошло больше
`window_ms`, открывается новый инцидент. Граница включительная: ровно `window_ms` — ещё
тот же инцидент. Делается векторно в polars: diff внутри ключа → признак разрыва →
накопленная сумма = номер инцидента внутри ключа.

Серьёзность: базовый уровень класса из конфига и +1 ступень, если алертов ≥ bump_at;
выше critical не поднимается. Уверенность детектора в серьёзность намеренно не входит —
серьёзность должна объясняться словами «что за атака и насколько массовая».
"""

from __future__ import annotations

import json

import polars as pl

from mlsiem.soc.config import SEVERITY_LEVELS
from mlsiem.soc.store import input_digest

KEY = ["attacker_ip", "predicted_class"]


def severity(
    attack_class: str, n_alerts: int, base: dict[str, str], bump_at: int
) -> tuple[str, str]:
    """(уровень, объяснение по-русски)."""
    if attack_class not in base:
        raise ValueError(
            f"для класса {attack_class!r} не задан базовый уровень серьёзности "
            "(configs/soc.yaml, severity.base)"
        )
    level = base[attack_class]
    reason = f"базовый уровень класса {attack_class} = {level}"
    if n_alerts >= bump_at:
        i = SEVERITY_LEVELS.index(level)
        if i + 1 < len(SEVERITY_LEVELS):
            level = SEVERITY_LEVELS[i + 1]
            reason += f"; +1 за {n_alerts} ≥ {bump_at} алертов → {level}"
        else:
            reason += f"; {n_alerts} ≥ {bump_at} алертов, но выше {level} уровня нет"
    return level, reason


# Поля инцидента из его алертов — ОДНИ выражения для пакетной группировки (group_by … agg) и
# для потоковой (фича 005: дописывание в инцидент пересчитывает поля по всем его алертам).
# Так два режима не могут разойтись в том, что значит «последний алерт» или «цели».
# last_alert_start_ms — максимум времени НАЧАЛА потоков алертов: правая граница окна
# присоединения (research R8); last_seen_ms — время конца последнего потока, для аналитика.
FIELD_AGGS = (
    pl.col("first_seen_ms").min().alias("first_seen_ms"),
    pl.col("last_seen_ms").max().alias("last_seen_ms"),
    pl.col("first_seen_ms").max().alias("last_alert_start_ms"),
    pl.len().cast(pl.Int64).alias("n_alerts"),
    pl.col("attack_score").max().alias("max_score"),
    pl.col("attack_score").mean().alias("mean_score"),
    pl.col("victim_ip").drop_nulls().unique().sort().alias("_targets"),
)


def _finish_fields(
    agg: dict, attack_class: str, severity_base: dict[str, str], bump_at: int
) -> dict:
    level, reason = severity(attack_class, agg["n_alerts"], severity_base, bump_at)
    return {
        "targets": json.dumps(list(agg["_targets"]), ensure_ascii=False),
        "first_seen_ms": agg["first_seen_ms"],
        "last_seen_ms": agg["last_seen_ms"],
        "last_alert_start_ms": agg["last_alert_start_ms"],
        "n_alerts": agg["n_alerts"],
        "max_score": agg["max_score"],
        "mean_score": agg["mean_score"],
        "severity": level,
        "severity_reason": reason,
    }


def incident_fields(
    alerts_of_incident: pl.DataFrame,
    attack_class: str,
    severity_base: dict[str, str],
    bump_at: int,
) -> dict:
    """Поля инцидента по ВСЕМ его алертам: границы, число, скоры, цели (`victim_ip`),
    серьёзность с пояснением. Нужны колонки first_seen_ms, last_seen_ms, attack_score,
    victim_ip. Алерты сортируются как в пакетной группировке — чтобы и средний скор
    складывался в том же порядке."""
    ordered = alerts_of_incident.sort(["first_seen_ms", "flow_uid"])
    # Через group_by по одной «группе», а не select: в agg список целей собирается списком
    # ровно так же, как в пакетной группировке (в select он был бы колонкой)
    agg = (
        ordered.with_columns(pl.lit(0).alias("_one"))
        .group_by("_one", maintain_order=True)
        .agg(FIELD_AGGS)
        .row(0, named=True)
    )
    return _finish_fields(agg, attack_class, severity_base, bump_at)


def incident_id(run_id: str, src_ip: str, attack_class: str, first_seen_ms: int) -> str:
    """`inc-<хеш12>` от прогона, ключа и времени первого алерта — детерминирован, не счётчик."""
    return "inc-" + input_digest(run_id, str(src_ip), attack_class, str(first_seen_ms))[:12]


def group_alerts(
    alerts: pl.DataFrame,
    *,
    window_ms: int,
    run_id: str,
    severity_base: dict[str, str],
    bump_at: int,
) -> tuple[pl.DataFrame, pl.DataFrame]:
    """Возвращает (алерты с колонкой incident_id, таблица инцидентов).

    Каждый алерт попадает ровно в один инцидент (номер инцидента внутри ключа — функция
    строки). Порядок инцидентов на выходе — по (first_seen_ms, incident_id).
    """
    if alerts.height == 0:
        empty_incidents = pl.DataFrame(
            schema={
                "incident_id": pl.String,
                "src_ip": pl.String,
                "attack_class": pl.String,
                "targets": pl.String,
                "first_seen_ms": pl.Int64,
                "last_seen_ms": pl.Int64,
                "last_alert_start_ms": pl.Int64,
                "n_alerts": pl.Int64,
                "max_score": pl.Float64,
                "mean_score": pl.Float64,
                "severity": pl.String,
                "severity_reason": pl.String,
            }
        )
        return alerts.with_columns(pl.lit(None, pl.String).alias("incident_id")), empty_incidents

    if "attacker_ip" not in alerts.columns:
        alerts = alerts.with_columns(
            pl.col("src_ip").alias("attacker_ip"), pl.col("dst_ip").alias("victim_ip")
        )
    ordered = alerts.sort([*KEY, "first_seen_ms", "flow_uid"])
    ordered = ordered.with_columns(
        (pl.col("first_seen_ms").diff().over(KEY).fill_null(0) > window_ms)
        .cast(pl.Int64)
        .cum_sum()
        .over(KEY)
        .alias("_seq")
    )
    groups = ordered.group_by([*KEY, "_seq"], maintain_order=True).agg(FIELD_AGGS)

    rows = []
    for g in groups.iter_rows(named=True):
        rows.append(
            {
                # src_ip инцидента — атакующая сторона ключа (имя колонки — как в 002)
                "incident_id": incident_id(
                    run_id, g["attacker_ip"], g["predicted_class"], g["first_seen_ms"]
                ),
                "src_ip": g["attacker_ip"],
                "attack_class": g["predicted_class"],
                "_seq": g["_seq"],
                **_finish_fields(g, g["predicted_class"], severity_base, bump_at),
            }
        )
    incidents = pl.DataFrame(rows, schema_overrides={"src_ip": pl.String})
    mapping = incidents.select(
        pl.col("src_ip").alias("attacker_ip"),
        pl.col("attack_class").alias("predicted_class"),
        "_seq",
        "incident_id",
    )
    with_incident = (
        ordered.join(mapping, on=[*KEY, "_seq"], how="left").drop("_seq").sort("flow_uid")
    )
    incidents = incidents.drop("_seq").sort(["first_seen_ms", "incident_id"])
    return with_incident, incidents
