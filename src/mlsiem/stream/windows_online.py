"""Окна в онлайн-потребителе 005: сборка, закрытие по водяному знаку, перезапуск без потерь
(фича 007, research R13, data-model «Незакрытые окна сеанса»).

Главное обещание — онлайн-окна совпадают с пакетными (FR-016). Для этого:

1. **Сетка та же.** Поток попадает в окно `assign_windows` — той же функцией, что в пакете и
   при обучении; вердикт окну выносит тот же `WindowExpert.verdicts`.
2. **Окно закрывается только тогда, когда в него уже не может прийти не опоздавший поток.**
   Водяной знак — `max_first_seen_ms` сеанса (уже есть в 005). Окно `[s, s + L)` закрывается,
   когда `s + L ≤ watermark − allowed_lateness`: любой поток такого окна начался бы раньше
   `watermark − allowed_lateness` и был бы помечен опоздавшим (`mark_late` 005). Значит, поток
   в пределах допустимого опоздания никогда не приходит в уже закрытое окно. Закрытие по
   часам (wall-clock) сломало бы эквивалентность: при проигрывании 2015 года время трафика и
   часы живут отдельно.
3. **Открытые окна живут в SQLite**, в таблице `window_pending`, и пишутся в ТОЙ ЖЕ транзакции,
   что алерты, инциденты и позиция чтения (гарантия 005 R7). Упал потребитель — открытые окна
   на месте, позиция не сдвинута, перечитанные сообщения отсеются `stream_seen`.
4. **Опоздавший сильнее допустимого поток, чьё окно уже закрыто,** в окно не добавляется: он
   считается в `n_window_late_dropped` и пишется в `stream_divergences` с причиной
   `window_late_dropped` — отчёт сравнения объясняет им расхождение с пакетом.
5. Отметка `end` и команда `stream close` закрывают все открытые окна источника. Остановка без
   `end` ничего не закрывает: окна продолжатся после перезапуска.

Модуль только ПЛАНИРУЕТ (`WindowPlan`): читает состояние сеанса и считает, что записать.
Записывает план `apply_window_plan` внутри транзакции `store.append_batch`.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

import orjson
import polars as pl

from mlsiem.data.captures import atomic_path
from mlsiem.data.schema import SCHEMA
from mlsiem.detect import windows as W
from mlsiem.soc.direction import sides
from mlsiem.soc.verdicts import alerts_from_window_verdicts, window_flow_context

log = logging.getLogger("mlsiem")

# Что кладётся в payload потока открытого окна: поля окон и обеих моделей окон, стороны по
# правилу направления, скор модели потоков (для таблицы подозрительных потоков) и метка
# (только при проигрывании размеченного разбиения — для отчёта, не для модели)
SIDE_EXTRA = ("attacker_ip", "victim_ip", "reversed")
DIVERGENCE_KIND = "window_late_dropped"


def payload_columns(has_label: bool) -> list[str]:
    cols = [*W.flow_columns(), *SIDE_EXTRA, "flow_score"]
    return [*cols, "label"] if has_label else cols


def _schema(has_label: bool) -> dict[str, pl.DataType]:
    dtypes = SCHEMA.dtypes()
    out = {}
    for c in payload_columns(has_label):
        if c in dtypes:
            out[c] = dtypes[c]
        elif c == "reversed":
            out[c] = pl.Boolean
        elif c == "flow_score":
            out[c] = pl.Float64
        else:
            out[c] = pl.String
    return out


def encode_payload(values: tuple | list) -> bytes:
    """Поток открытого окна → payload: JSON-МАССИВ значений в порядке `payload_columns`.

    Сначала payload был словарём {поле: значение}, и в каждом потоке заново писались 88 имён
    полей — половина из ~2 КБ. За часть test это 560 МБ, которые пишутся в window_pending и
    тут же удаляются, и хвост потребителя из-за этого вырос с 28 до 88 с (T058). Массив —
    тот же orjson, так что float64 по-прежнему возвращается тем же до бита."""
    return orjson.dumps(list(values))


def frame_from_payloads(payloads: list[bytes]) -> pl.DataFrame:
    """Потоки окна из `window_pending` обратно в кадр — с типами схемы 001, как в пакете.

    orjson пишет числа кратчайшим точным представлением, так что float64 возвращается тем же
    до последнего бита — признаки окна в онлайне и в пакете совпадают побитно. Понимает оба
    вида payload: массив (`encode_payload`) и прежний словарь — открытые окна сеанса,
    начатого старой версией, не теряются."""
    rows = [orjson.loads(p) for p in payloads]
    if not rows:
        return pl.DataFrame(schema=_schema(False))
    if isinstance(rows[0], dict):
        has_label = "label" in rows[0]
        return pl.DataFrame(rows, schema=_schema(has_label))
    # Метка есть только при проигрывании размеченного разбиения — её видно по длине массива
    has_label = len(rows[0]) == len(payload_columns(True))
    return pl.DataFrame(rows, schema=_schema(has_label), orient="row")


@dataclass
class WindowPlan:
    """Что сделать с окнами сеанса в этой пачке (всё — в транзакции пачки)."""

    run_id: str
    pending_rows: list[tuple] = field(default_factory=list)  # новые строки window_pending
    close_ids: list[str] = field(default_factory=list)  # закрываемые окна
    closed_rows: list[tuple] = field(default_factory=list)  # строки window_closed
    dropped: list[dict] = field(default_factory=list)  # опоздавшие в закрытое окно
    verdicts: pl.DataFrame = field(default_factory=pl.DataFrame)  # вердикты закрытых окон
    alerts: pl.DataFrame = field(default_factory=pl.DataFrame)  # алерты закрытых окон
    open_delta: int = 0

    def counters(self) -> dict[str, int]:
        return {
            "n_windows": len(self.close_ids),
            "n_window_alerts": self.alerts.height,
            "n_window_late_dropped": len(self.dropped),
            "n_open_windows": self.open_delta,
        }


def _chunks(values: list, size: int = 500):
    for i in range(0, len(values), size):
        yield values[i : i + size]


def closed_among(conn: sqlite3.Connection, run_id: str, window_ids: list[str]) -> set[str]:
    out: set[str] = set()
    for chunk in _chunks(window_ids):
        marks = ", ".join("?" for _ in chunk)
        out |= {
            r[0]
            for r in conn.execute(
                f"SELECT window_id FROM window_closed WHERE run_id = ? AND window_id IN ({marks})",
                [run_id, *chunk],
            )
        }
    return out


def open_windows(conn: sqlite3.Connection, run_id: str) -> dict[str, int]:
    """window_id → начало для всех открытых окон сеанса."""
    return {
        r[0]: r[1]
        for r in conn.execute(
            "SELECT DISTINCT window_id, window_start_ms FROM window_pending WHERE run_id = ?",
            (run_id,),
        )
    }


def pending_payloads(conn: sqlite3.Connection, run_id: str, window_ids: list[str]) -> list[bytes]:
    out: list[bytes] = []
    for chunk in _chunks(window_ids):
        marks = ", ".join("?" for _ in chunk)
        out += [
            r[0]
            for r in conn.execute(
                f"SELECT payload FROM window_pending WHERE run_id = ? AND window_id IN ({marks}) "
                "ORDER BY flow_uid",
                [run_id, *chunk],
            )
        ]
    return out


def due(
    starts: dict[str, int], watermark: int | None, length_ms: int, lateness_ms: int
) -> list[str]:
    """Окна, которые можно закрыть: `start + L ≤ watermark − lateness` (R13)."""
    if watermark is None:
        return []
    edge = watermark - lateness_ms
    return sorted(w for w, s in starts.items() if s + length_ms <= edge)


class WindowAssembler:
    """Сборщик окон одного потребителя: эксперт окон, режим направления, опоздание."""

    def __init__(self, expert, direction: str, lateness_ms: int) -> None:
        self.expert = expert
        self.direction = direction
        self.lateness_ms = int(lateness_ms)

    def plan(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        flows: pl.DataFrame,
        flow_verdicts: pl.DataFrame,
        *,
        watermark: int | None,
        close_all: bool,
    ) -> WindowPlan:
        """Новые (не повторные) потоки пачки → окна; закрыть созревшие; при `close_all`
        (отметка end) — все открытые. Чтение состояния — здесь, запись — `apply_window_plan`."""
        plan = WindowPlan(run_id)
        L = self.expert.length_ms
        before = open_windows(conn, run_id)
        batch_starts: dict[str, int] = {}
        data = None
        if flows.height:
            side = sides(flows, self.direction).select(W.SIDE_COLUMNS)
            asg = W.assign_windows(flows, side, length_ms=L)
            already = closed_among(conn, run_id, asg["window_id"].unique().to_list())
            has_label = "label" in flows.columns
            cols = payload_columns(has_label)
            data = (
                flows.join(side.select("flow_uid", *SIDE_EXTRA), on="flow_uid", how="left")
                .join(
                    flow_verdicts.select("flow_uid", pl.col("attack_score").alias("flow_score")),
                    on="flow_uid",
                    how="left",
                )
                .join(asg.select("flow_uid", "window_id", "window_start_ms"), on="flow_uid")
                .sort("flow_uid")
            )
            if already:
                late = data.filter(pl.col("window_id").is_in(list(already)))
                plan.dropped = late.select(
                    "flow_uid", "window_id", pl.col(W.FIRST).alias("first_seen_ms")
                ).to_dicts()
                data = data.filter(~pl.col("window_id").is_in(list(already)))
            batch_starts = dict(
                data.group_by("window_id").agg(pl.col("window_start_ms").first()).iter_rows()
            )
        starts = {**before, **batch_starts}
        closing = sorted(starts) if close_all else due(starts, watermark, L, self.lateness_ms)
        closing_set = set(closing)
        after_open = set(starts) - closing_set
        plan.open_delta = len(after_open) - len(before)

        if data is not None:
            in_closing = pl.col("window_id").is_in(list(closing_set))
            # В window_pending — только потоки окон, которые остаются открытыми. Окно,
            # открытое и закрытое в этой же пачке, туда не пишем: его строки удалились бы той
            # же транзакцией, а на --speed max таких окон большинство — сотни мегабайт вставки
            # и удаления (T058). Перезапуск это не задевает: план пишется атомарно, вместе с
            # позицией чтения. Кортежи, а не словари: первые два поля — окно, дальше ровно
            # колонки payload
            i_uid, i_att = cols.index("flow_uid"), cols.index("attacker_ip")
            for wid, start, *values in (
                data.filter(~in_closing).select("window_id", "window_start_ms", *cols).iter_rows()
            ):
                plan.pending_rows.append(
                    (run_id, values[i_uid], wid, start, values[i_att], encode_payload(values))
                )
        if not closing:
            return plan
        stored = [w for w in closing if w in before]
        parts = [frame_from_payloads(pending_payloads(conn, run_id, stored))] if stored else []
        if data is not None:
            # Потоки закрываемых окон этой пачки — прямо из кадра, без круга через JSON. Типы
            # те же, что у прочитанных из базы (`_schema`), порядок строк неважен: окна
            # строятся в каноническом порядке (`windows._ordered`)
            fresh = data.filter(in_closing).select(
                [pl.col(c).cast(t) for c, t in _schema(has_label).items()]
            )
            parts.append(fresh)
        parts = [p for p in parts if p.height] or parts[:1]
        frame = pl.concat(parts, how="diagonal_relaxed") if len(parts) > 1 else parts[0]
        result = self.expert.verdicts(frame, frame.select(W.SIDE_COLUMNS))
        ctx = window_flow_context(
            frame,
            frame.select(W.SIDE_COLUMNS),
            frame.select("flow_uid", pl.col("flow_score").alias("attack_score")),
        )
        alerts = alerts_from_window_verdicts(result, ctx, self.expert)
        if alerts.height:
            alerts = alerts.with_columns(pl.lit(0, dtype=pl.Int64).alias("late"))
        n_by = dict(zip(result.windows["window_id"], result.windows["n_flows"], strict=True))
        plan.close_ids = closing
        plan.closed_rows = [(run_id, w, int(n_by.get(w, 0))) for w in closing]
        plan.verdicts = result.verdicts
        plan.alerts = alerts
        return plan


def apply_window_plan(conn: sqlite3.Connection, plan: WindowPlan, at: str) -> None:
    """План окон — внутри уже открытой транзакции пачки (`store.append_batch(extra=…)`)."""
    conn.executemany(
        "INSERT OR IGNORE INTO window_pending (run_id, flow_uid, window_id, window_start_ms, "
        "attacker_ip, payload) VALUES (?, ?, ?, ?, ?, ?)",
        plan.pending_rows,
    )
    for chunk in _chunks(plan.close_ids):
        marks = ", ".join("?" for _ in chunk)
        conn.execute(
            f"DELETE FROM window_pending WHERE run_id = ? AND window_id IN ({marks})",
            [plan.run_id, *chunk],
        )
    conn.executemany(
        "INSERT OR IGNORE INTO window_closed (run_id, window_id, closed_at, n_flows) "
        "VALUES (?, ?, ?, ?)",
        [(r, w, at, n) for r, w, n in plan.closed_rows],
    )
    conn.executemany(
        "INSERT INTO stream_divergences (run_id, kind, incident_id, other_incident_id, flow_uid, "
        "at, details) VALUES (?, ?, NULL, NULL, ?, ?, ?)",
        [
            (
                plan.run_id,
                DIVERGENCE_KIND,
                d["flow_uid"],
                at,
                orjson.dumps(
                    {
                        "window_id": d["window_id"],
                        "first_seen_ms": d["first_seen_ms"],
                        "text": (
                            f"поток {d['flow_uid']} пришёл в уже закрытое окно {d['window_id']} "
                            "(опоздал сильнее допустимого) — в окно не добавлен"
                        ),
                    }
                ).decode(),
            )
            for d in plan.dropped
        ],
    )


def write_window_part(runs_dir: Path, run_id: str, plan: WindowPlan, tag: str) -> None:
    """Вердикты закрытых окон пачки — файлом `windows/part-*.parquet` (до транзакции, как
    вердикты потоков: при повторе пачки файл перепишется тем же содержимым)."""
    if plan.verdicts.height == 0:
        return
    path = Path(runs_dir) / run_id / "windows" / f"part-{tag}.parquet"
    with atomic_path(path) as tmp:
        plan.verdicts.write_parquet(tmp)


def close_session_windows(conn: sqlite3.Connection, soc_cfg, run_id: str) -> dict[str, int]:
    """Закрыть все открытые окна сеанса без потребителя — для `stream close` (contracts/cli.md).

    Эксперт окон — тот, с которым начат сеанс (путь и версия — в сводке сеанса): судить окна
    другой моделью значило бы смешать в одном сеансе вердикты двух моделей. Вердикты, алерты
    окон и их инциденты пишутся одной транзакцией, как пачка потребителя.
    """
    from mlsiem.detect.windows_expert import load_window_expert
    from mlsiem.soc import store
    from mlsiem.soc.run import alerts_by_expert
    from mlsiem.stream.incremental import plan_batch

    run = store.get_run(conn, run_id)
    section = (run.get("summary") or {}).get("windows") or {}
    if not section.get("enabled") or not open_windows(conn, run_id):
        return {"n_windows": 0, "n_window_alerts": 0}
    expert = load_window_expert(Path(section["model_path"]), force=True)
    if expert.version != section.get("expert_version"):
        raise ValueError(
            f"сеанс {run_id} начат с экспертом окон {section.get('expert_version')}, а в "
            f"{section['model_path']} теперь {expert.version} — закрыть окна той же моделью нельзя"
        )
    plan = WindowAssembler(expert, soc_cfg.direction, 0).plan(
        conn, run_id, pl.DataFrame(), pl.DataFrame(), watermark=None, close_all=True
    )
    write_window_part(soc_cfg.runs_dir, run_id, plan, f"close-{store.now_iso().replace(':', '')}")
    plans = [plan_batch(conn, run_id, plan.alerts, soc_cfg)] if plan.alerts.height else []
    summary: dict = {"windows": plan.counters()}
    if plan.alerts.height:
        summary["alerts_by_expert"] = alerts_by_expert(plan.alerts)

    def write(c, at):
        apply_window_plan(c, plan, at)

    store.append_batch(
        conn, plans, offsets={}, sessions={run_id: {"summary": summary}}, extra=[write]
    )
    return {"n_windows": len(plan.close_ids), "n_window_alerts": plan.alerts.height}
