"""Онлайн-цепочка — `mlsiem stream consume` (FR-011, FR-012, FR-015, FR-016, FR-019, research R7).

Цикл одной пачки:

1. `poll_batch` — до `batch_max_messages` сообщений или `batch_max_wait_ms` ожидания;
2. разбор и проверка (`decode_flows`); отвергнутые сразу уходят в топик отвергнутых с
   причиной, и их доставка подтверждается ДО записи пачки — иначе при сбое они бы пропали;
3. по источникам: сеанс найден или создан; потоки, уже обработанные в сеансе
   (`stream_seen`), отбрасываются — так повторная доставка не даёт дублей (FR-015);
4. вердикты той же функцией, что пакетный режим (`compute_verdicts`), алерты
   (`alerts_from_verdicts` — правило направления), инкрементальная группировка
   (`plan_batch`), плейбуки (`propose_action` внутри плана);
5. вердикты пачки — в `var/runs/<сеанс>/verdicts/part-*.parquet` (файл до транзакции: если
   транзакция не удастся, пачка прочитается снова и файл перепишется тем же содержимым);
6. ОДНА транзакция SQLite (`store.append_batch`): алерты, инциденты, действия, аудит,
   обработанные потоки, позиция чтения, показатели;
7. только после COMMIT — подтверждение позиции брокеру.

При старте позиция берётся из SQLite, а не из брокера (research R7): если процесс упал между
6 и 7, перечитанные сообщения отсеются на шаге 3; если до 6 — прочитаются заново. Так при
доставке «хотя бы один раз» результат получается «ровно один раз».

Модель загружается и проверяется ДО первого чтения (US3 п. 7): битый эксперт — отказ, топик
не тронут, позиции не сдвинуты. Модель сеанса неизменна: если сеанс начат другой версией,
потребитель останавливается с объяснением, ничего не подтверждая (data-model «Сеанс»).

Единственность — аренда в SQLite (FR-019): второй потребитель при живой аренде не стартует;
аренда продлевается каждые `lease_ttl_s / 6` с, а потерявший её потребитель останавливается,
не записав больше ни одной пачки.

Фича 007 (research R13): если включён эксперт окон, новые потоки пачки раскладываются по
окнам (`WindowAssembler`), открытые окна копятся в `window_pending`, созревшие по водяному
знаку закрываются, их алерты идут в тот же `plan_batch`, что алерты потоков, — и всё это
пишется в ту же транзакцию, что позиция. Сеанс запоминает эксперт окон, с которым начат:
перезапуск с другим — `ModelMismatch`, как для модели потоков.
"""

from __future__ import annotations

import logging
import os
import socket
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import polars as pl

from mlsiem.data.captures import atomic_path
from mlsiem.detect.ensemble import LoadedModel, load_model
from mlsiem.soc import store
from mlsiem.soc.config import SocConfig, check_model_classes
from mlsiem.soc.run import alerts_by_expert
from mlsiem.soc.verdicts import (
    EXPLANATION,
    alerts_from_verdicts,
    compute_verdicts,
    with_flow_kind,
)
from mlsiem.stream.broker import Broker, BrokerUnavailable, Message
from mlsiem.stream.incremental import mark_late, plan_batch
from mlsiem.stream.messages import EndMark, decode_flows, rejected_payload
from mlsiem.stream.stats import StatsWindow, lag_messages

log = logging.getLogger("mlsiem")
# Сколько раз пересчитать план пачки, если аналитик успевает что-то решить между планом и
# записью (оптимистичная блокировка, FR-020)
MAX_REPLANS = 5
FLUSH_TIMEOUT_S = 30
# --once: сколько пустых опросов подряд терпеть, если топик ещё не дочитан (≈ 1 мин при
# ожидании пачки 500 мс) — чтобы не зависнуть навсегда на недоступном брокере
ONCE_MAX_EMPTY_POLLS = 120


class ConsumerStopped(RuntimeError):
    """Потребитель остановлен по причине, которую надо показать владельцу (код 1)."""


class LeaseLost(ConsumerStopped):
    pass


class StoreUnavailable(ConsumerStopped):
    pass


class ModelMismatch(ConsumerStopped):
    pass


@dataclass
class SessionState:
    run_id: str
    source_id: str
    stats: StatsWindow
    processed: int = 0
    alerts: int = 0
    rejected: int = 0


@dataclass
class ConsumeSummary:
    batches: int = 0
    messages: int = 0
    processed: int = 0
    rejected: int = 0
    duplicates: int = 0
    sessions: dict[str, SessionState] = field(default_factory=dict)
    stop_reason: str | None = None


def default_holder() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def windows_section(choice) -> dict:
    """Раздел `windows` сводки сеанса (фича 007): эксперт окон, с которым начат сеанс, и
    счётчики окон. Путь к модели нужен `stream close` — закрыть окна без потребителя."""
    if choice is None:
        return {"mode": "off", "enabled": False, "reason": "выключен"}
    out = choice.summary()
    if choice.expert is not None:
        out.update(
            n_windows=0,
            n_window_alerts=0,
            n_window_late_dropped=0,
            n_open_windows=0,
            model_path=Path(choice.expert.path).as_posix() if choice.expert.path else None,
        )
    return out


def session_summary(model: LoadedModel, cfg: SocConfig, windows_choice=None) -> dict:
    """Сводка нового сеанса — те же поля модели, что у пакетного прогона 004 (консоль
    показывает порог, классы, экспертов и режим направления)."""
    from mlsiem.data.schema import SCHEMA

    return {
        "windows": windows_section(windows_choice),
        "schema_version": SCHEMA.version,
        "threshold": float(model.threshold),
        "classes": list(model.classes),
        "model": model.summary(),
        "experts": {n: m["version"] for n, m in model.experts_meta.items()},
        "experts_meta": model.experts_meta,
        "alerts_by_expert": {},
        "n_reversed": 0,
        "direction_mode": cfg.direction,
    }


class Consumer:
    """Потребитель онлайн-цепочки. Внешние зависимости — параметрами: брокер, часы, сон."""

    def __init__(
        self,
        stream_cfg,
        soc_cfg: SocConfig,
        *,
        broker: Broker,
        model_dir: Path,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        holder: str | None = None,
        on_report: Callable[[str], None] | None = None,
        windows_mode: str | None = None,
        windows_model: Path | None = None,
    ) -> None:
        self.cfg = stream_cfg
        self.windows_mode = windows_mode
        self.windows_model = windows_model
        self.windows = None  # WindowsChoice фичи 007
        self.assembler = None
        self.soc = soc_cfg
        self.broker = broker
        self.model_dir = Path(model_dir)
        self.clock = clock
        self.sleep = sleep
        self.holder = holder or default_holder()
        self.on_report = on_report
        self.model: LoadedModel | None = None
        self.conn: sqlite3.Connection | None = None
        self.summary = ConsumeSummary()
        self._positions: dict[tuple[str, int], int] = {}
        self._last_renew = 0.0
        self._last_stats = 0.0
        self._last_report = 0.0
        self._started = False

    # ------------------------------------------------ старт и стоп

    def start(self) -> None:
        """Модель и её проверки → база → аренда → позиции → подписка. До первого чтения."""
        from mlsiem.detect.windows_expert import resolve_window_expert
        from mlsiem.stream.windows_online import WindowAssembler

        self.model = load_model(self.model_dir)
        check_model_classes(self.soc, self.model.output_classes)
        # Эксперт окон и его проверки — тоже до первого чтения (FR-013)
        self.windows = resolve_window_expert(self.soc, self.windows_mode, self.windows_model)
        if self.windows.expert is not None:
            self.assembler = WindowAssembler(
                self.windows.expert, self.soc.direction, self.cfg.consumer.allowed_lateness_ms
            )
        self.conn = store.connect(self.soc.db)
        store.init_db(self.conn)
        store.acquire_lease(self.conn, self.holder, self.cfg.consumer.lease_ttl_s, now=self.clock())
        self._last_renew = self.clock()
        self._started = True
        self._positions = store.load_offsets(self.conn)
        for (topic, partition), offset in self._positions.items():
            if topic == self.cfg.topics.flows:
                self.broker.seek(topic, partition, offset)
        self.broker.subscribe([self.cfg.topics.flows])

    def stop(self, reason: str = "потребитель остановлен") -> None:
        """Сеансы, которые этот потребитель вёл и не завершил, — `stopped`; аренда отдаётся."""
        if self.conn is None:
            return
        if self._started:
            for st in self.summary.sessions.values():
                try:
                    run = store.get_run(self.conn, st.run_id)
                    if run["status"] == "running":
                        store.set_session_status(self.conn, st.run_id, "stopped", reason)
                except (store.StoreError, sqlite3.Error) as exc:
                    log.warning("Не удалось отметить сеанс %s остановленным: %s", st.run_id, exc)
            try:
                store.release_lease(self.conn, self.holder)
            except sqlite3.Error as exc:
                log.warning("Не удалось отдать аренду потребителя: %s", exc)
        self.conn.close()
        self.conn = None

    # ------------------------------------------------ цикл

    def run(self, *, once: bool = False, stop: Callable[[], bool] | None = None) -> ConsumeSummary:
        """Обрабатывать пачки, пока `stop()` не скажет «хватит»; `once` — пока не дочитан
        конец топика, каким он был к моменту пустого опроса."""
        c = self.cfg.consumer
        empty = 0
        while not (stop and stop()):
            self._renew_lease()
            msgs = self.broker.poll_batch(c.batch_max_messages, c.batch_max_wait_ms)
            if not msgs:
                self._maybe_report()
                if once:
                    empty += 1
                    if self._caught_up() or empty >= ONCE_MAX_EMPTY_POLLS:
                        if empty >= ONCE_MAX_EMPTY_POLLS and not self._caught_up():
                            log.warning(
                                "--once: брокер %d раз подряд не отдал сообщений, хотя топик "
                                "дочитан не до конца — выхожу; следующий запуск продолжит",
                                empty,
                            )
                        break
                continue
            empty = 0
            self.process(msgs)
            self._maybe_report()
        return self.summary

    def _caught_up(self) -> bool:
        """Позиция чтения дошла до конца каждой партиции топика потоков.

        Пустой опрос сам по себе ничего не значит: у настоящей Kafka первые опросы после
        подключения пусты, пока клиент устанавливает соединение и получает партиции.
        """
        topic = self.cfg.topics.flows
        try:
            ends = self.broker.end_offsets(topic)
        except BrokerUnavailable:
            return False
        return all(self._positions.get((topic, p), 0) >= end for p, end in ends.items())

    def _renew_lease(self) -> None:
        now = self.clock()
        if now - self._last_renew < self.cfg.consumer.lease_ttl_s / 6:
            return
        try:
            renewed = store.renew_lease(self.conn, self.holder, now=now)
        except sqlite3.OperationalError as exc:
            # База занята — продлим в следующий раз; если за это время аренду заберут,
            # следующее продление это обнаружит
            log.warning("Не удалось продлить аренду (%s) — повторю", exc)
            return
        if not renewed:
            self._started = False  # аренда чужая — отдавать и трогать сеансы нельзя
            raise LeaseLost(
                "аренду потребителя забрал другой процесс (эта истекла) — останавливаюсь, "
                "ничего больше не записывая"
            )
        self._last_renew = now

    def _maybe_report(self) -> None:
        now = self.clock()
        if self.on_report is None or now - self._last_report < self.cfg.consumer.report_interval_s:
            return
        self._last_report = now
        for st in self.summary.sessions.values():
            snap = st.stats.snapshot()
            p50, p95 = snap["latency_p50_ms"], snap["latency_p95_ms"]
            self.on_report(
                f"{st.run_id}: обработано {st.processed}, {snap['rate_per_s']:.0f} потоков/с, "
                f"задержка p50 {_ms(p50)} / p95 {_ms(p95)}, отвергнуто {st.rejected}, "
                f"опоздавших {snap['late']}" + self._windows_report(st.run_id)
            )

    def _windows_report(self, run_id: str) -> str:
        """«окна: открыто N, закрыто M, алертов K, опоздавших-вне-окна L» (contracts/cli.md)."""
        if self.assembler is None or self.conn is None:
            return ""
        try:
            w = (store.get_run(self.conn, run_id).get("summary") or {}).get("windows") or {}
        except store.StoreError:
            return ""
        return (
            f"; окна: открыто {w.get('n_open_windows', 0)}, закрыто {w.get('n_windows', 0)}, "
            f"алертов {w.get('n_window_alerts', 0)}, опоздавших-вне-окна "
            f"{w.get('n_window_late_dropped', 0)}"
        )

    # ------------------------------------------------ пачка

    def process(self, msgs: list[Message]) -> None:
        """Одна пачка с повтором, если SQLite занята или недоступна (US4 п. 3).

        Повтор всей пачки безопасен: сеанс создаётся идемпотентно, файл вердиктов
        перезаписывается тем же содержимым, а запись в базу — одна транзакция, которой ещё не
        было. Пока пачка не записана, брокеру ничего не подтверждается; через `db_retry_s`
        потребитель останавливается — следующий запуск продолжит с того же места.
        """
        c = self.cfg.consumer
        pause, waited = 0.5, 0.0
        while True:
            try:
                self._batch_rejected = 0
                self._process_once(msgs)
                break
            except sqlite3.OperationalError as exc:
                if waited >= c.db_retry_s:
                    raise StoreUnavailable(
                        f"хранилище {self.soc.db} недоступно {waited:.0f} с ({exc}) — пачка не "
                        "записана и не подтверждена брокеру; запустите потребителя снова, когда "
                        "база освободится: он продолжит с того же места"
                    ) from exc
                log.warning("Хранилище занято (%s) — повтор через %.1f с", exc, pause)
                self.sleep(pause)
                waited += pause
                pause = min(pause * 2, 8.0)
        self.summary.batches += 1
        self.summary.messages += len(msgs)
        self.summary.rejected += self._batch_rejected

    def _process_once(self, msgs: list[Message]) -> None:
        """Одна пачка: от разбора до подтверждения брокеру."""
        assert self.model is not None and self.conn is not None
        s = self.summary
        frame, rejected, ends = decode_flows(msgs, model_schema=self.model.schema_version)

        # Отвергнутые — в свой топик и подтвердить доставку ДО записи пачки
        if rejected:
            for r in rejected:
                key, value, headers = rejected_payload(r)
                self.broker.produce(self.cfg.topics.rejected, key, value, headers)
            left = self.broker.flush(FLUSH_TIMEOUT_S)
            if left:
                raise BrokerUnavailable(
                    f"брокер не подтвердил {left} отвергнутых сообщений — пачка не записана, "
                    "позиция не подтверждена"
                )
            self._batch_rejected = len(rejected)

        offsets: dict[tuple[str, int], int] = {}
        for m in msgs:
            tp = (m.topic, m.partition)
            offsets[tp] = max(offsets.get(tp, 0), m.offset + 1)

        rejected_by_source: dict[str, int] = {}
        for r in rejected:
            src = r.message.headers.get("mlsiem-source") or r.message.key
            if src:
                rejected_by_source[src] = rejected_by_source.get(src, 0) + 1

        sources = list(dict.fromkeys(frame["source_id"].to_list())) if frame.height else []
        for end in ends:
            if end.source_id not in sources:
                sources.append(end.source_id)
        for src in rejected_by_source:
            if src not in sources and store.session_by_source(self.conn, src) is not None:
                sources.append(src)

        prepared = []
        for src in sources:
            part = frame.filter(pl.col("source_id") == src) if frame.height else frame
            item = self._prepare(src, part, [e for e in ends if e.source_id == src], offsets)
            if item is not None:
                item["session"]["stream"]["n_rejected"] = rejected_by_source.get(src, 0)
                prepared.append(item)

        stats_rows = self._stats_rows(prepared, offsets)
        self._write(prepared, offsets, stats_rows)
        # Только теперь, после COMMIT, — подтверждение брокеру (FR-016)
        self.broker.commit(offsets)
        self._positions.update(offsets)
        for item in prepared:
            st = self.summary.sessions[item["run_id"]]
            st.processed += item["session"]["n_flows"]
            st.alerts += item["alerts"].height
            st.rejected += item["session"]["stream"]["n_rejected"]
            s.processed += item["session"]["n_flows"]

    def _session(self, src: str) -> dict | None:
        run = store.session_by_source(self.conn, src)
        if run is None:
            run = store.create_session(
                self.conn,
                src,
                model_version=self.model.version,
                summary=session_summary(self.model, self.soc, self.windows),
            )
            log.info("Новый сеанс %s для источника %s", run["run_id"], src)
        if run["status"] == "completed":
            return None
        if run["model_version"] != self.model.version:
            store.set_session_status(
                self.conn,
                run["run_id"],
                "stopped",
                f"загружена модель {self.model.version}, а сеанс начат моделью "
                f"{run['model_version']}",
            )
            raise ModelMismatch(
                f"сеанс {run['run_id']} ({src}) начат моделью {run['model_version']}, а "
                f"загружена {self.model.version} — сообщения источника не обрабатываю. Верните "
                f"модель (--model) или закройте сеанс: mlsiem stream close --session "
                f"{run['run_id']}"
            )
        mine = (run.get("summary") or {}).get("windows") or {"enabled": False}
        want = windows_section(self.windows)
        if bool(mine.get("enabled")) != bool(want.get("enabled")) or (
            want.get("enabled") and mine.get("expert_version") != want.get("expert_version")
        ):
            have = mine.get("expert_version") if mine.get("enabled") else "без эксперта окон"
            now = want.get("expert_version") if want.get("enabled") else "без эксперта окон"
            store.set_session_status(
                self.conn,
                run["run_id"],
                "stopped",
                f"эксперт окон сеанса: {have}, а потребитель запущен: {now}",
            )
            raise ModelMismatch(
                f"сеанс {run['run_id']} ({src}) начат с экспертом окон: {have}, а сейчас: {now} — "
                "сообщения источника не обрабатываю. Верните прежний режим (--windows, "
                "--windows-model) или закройте сеанс: mlsiem stream close --session "
                f"{run['run_id']}"
            )
        if run["run_id"] not in self.summary.sessions:
            self.summary.sessions[run["run_id"]] = SessionState(
                run["run_id"], src, StatsWindow(clock=self.clock)
            )
        return run

    def _prepare(self, src: str, part: pl.DataFrame, ends: list[EndMark], offsets) -> dict | None:
        """Всё, что не зависит от состояния инцидентов: сеанс, отсев повторов, вердикты,
        алерты, флаги опоздания. План инцидентов строится позже — его, в отличие от этого,
        может понадобиться пересчитать при конфликте с решением аналитика."""
        run = self._session(src)
        if run is None:
            if part.height:
                log.warning(
                    "Источник %s: сеанс уже завершён — %d сообщений пропущено", src, part.height
                )
            return None
        run_id = run["run_id"]
        stream = (run.get("summary") or {}).get("stream") or {}

        # Повторы: внутри пачки (первое вхождение) и уже обработанные в сеансе
        n_before = part.height
        part = part.unique(subset="flow_uid", keep="first", maintain_order=True)
        seen = (
            store.seen_flows(self.conn, run_id, part["flow_uid"].to_list())
            if part.height
            else set()
        )
        if seen:
            part = part.filter(~pl.col("flow_uid").is_in(list(seen)))
        self.summary.duplicates += n_before - part.height

        # Опоздание — по всем потокам в порядке прихода (не только по алертам)
        flags, max_seen = mark_late(
            part["bidirectional_first_seen_ms"].to_list(),
            stream.get("max_first_seen_ms"),
            self.cfg.consumer.allowed_lateness_ms,
        )
        late_by_uid = dict(zip(part["flow_uid"].to_list(), flags, strict=True))

        alerts = pl.DataFrame()
        flows = verdicts = pl.DataFrame()
        if part.height:
            flows = part.drop(["source_id", "seq", "sent_at_ms"])
            if flows["label"].null_count() == flows.height:
                flows = flows.drop("label")
            verdicts = compute_verdicts(self.model, flows, direction=self.soc.direction)
            self._write_verdicts(run_id, part, verdicts, offsets)
            alerts = alerts_from_verdicts(
                verdicts,
                flows.sort("flow_uid"),
                experts_meta=self.model.experts_meta,
                direction=self.soc.direction,
            )
            alerts = alerts.with_columns(
                pl.col("flow_uid")
                .replace_strict(late_by_uid, return_dtype=pl.Int64, default=0)
                .alias("late")
            )

        seqs = list(zip(part["flow_uid"].to_list(), part["seq"].to_list(), strict=True))
        stream_set: dict = {}
        if max_seen is not None:
            stream_set["max_first_seen_ms"] = max_seen
        prev_last = stream.get("last_seq")
        if part.height:
            top = int(part["seq"].max())
            stream_set["last_seq_seen"] = max(stream.get("last_seq_seen") or -1, top)
        status, reason = None, ""
        end_last = prev_last if stream.get("end_received") else None
        if ends:
            end_last = max(e.last_seq for e in ends)
            stream_set["end_received"] = True
            stream_set["last_seq"] = end_last
        if end_last is not None:
            done = store.seen_count(self.conn, run_id, end_last) + sum(
                1 for _, q in seqs if q <= end_last
            )
            if done >= end_last + 1:
                status, reason = "completed", f"получен end, обработаны все {end_last + 1} потоков"
        if status is None and run["status"] == "stopped":
            status, reason = "running", "потребитель снова обрабатывает сообщения источника"

        n_reversed = int(alerts["reversed"].sum()) if alerts.height else 0
        sent_by_uid = dict(
            zip(part["flow_uid"].to_list(), part["sent_at_ms"].to_list(), strict=True)
        )
        # Задержка «поток → алерт» — только у алертов потоков: алерт окна по определению ждёт
        # закрытия окна (L + допустимое опоздание, SC-006), его задержка — отдельная мера
        alert_sent_at = (
            [sent_by_uid[u] for u in alerts["flow_uid"].to_list()] if alerts.height else []
        )
        summary_delta: dict = {
            "alerts_by_expert": alerts_by_expert(alerts) if alerts.height else {},
            "n_reversed": n_reversed,
        }
        window_plan = None
        if self.assembler is not None:
            window_plan = self.assembler.plan(
                self.conn,
                run_id,
                flows,
                verdicts,
                watermark=max_seen,
                close_all=status == "completed",
            )
            from mlsiem.stream.windows_online import write_window_part

            first = min(offsets.values()) if offsets else 0
            write_window_part(
                self.soc.runs_dir, run_id, window_plan, f"{first:012d}-{part.height:05d}"
            )
            walerts = window_plan.alerts
            if walerts.height:
                alerts = pl.concat([with_flow_kind(alerts), walerts], how="diagonal_relaxed")
                summary_delta["alerts_by_expert"] = alerts_by_expert(alerts)
            summary_delta["windows"] = window_plan.counters()
        return {
            "run_id": run_id,
            "alerts": alerts,
            "window_plan": window_plan,
            "alert_sent_at": alert_sent_at,
            "max_seen": stream.get("max_first_seen_ms"),
            "seen": seqs,
            "late_flows": sum(flags),
            "sent_at_last": int(part["sent_at_ms"].max()) if part.height else None,
            "session": {
                "n_flows": part.height,
                "stream": {"n_late": int(sum(flags)), "parts": 1 if part.height else 0},
                "stream_set": stream_set,
                "summary": summary_delta,
                "status": status,
                "reason": reason,
            },
        }

    def _write_verdicts(self, run_id, part, verdicts, offsets) -> None:
        """Вердикты пачки — отдельным файлом каталога `verdicts/` (консоль читает их glob)."""
        first = min(o for o in offsets.values()) if offsets else 0
        tp = min(offsets) if offsets else ("t", 0)
        path = (
            Path(self.soc.runs_dir)
            / run_id
            / "verdicts"
            / f"part-{tp[1]:03d}-{first:012d}-{part.height:05d}.parquet"
        )
        with atomic_path(path) as tmp:
            verdicts.drop(EXPLANATION, strict=False).write_parquet(tmp)

    def _stats_rows(self, prepared: list[dict], offsets) -> list[dict] | None:
        now = self.clock()
        at_ms = now * 1000
        for item in prepared:
            st = self.summary.sessions[item["run_id"]]
            sent = []
            if item["alerts"].height:
                # sent_at_ms алерта — из сообщения его потока; задержка — до записи (сейчас)
                sent = [at_ms - x for x in item.get("alert_sent_at", [])]
            st.stats.add(
                processed=item["session"]["n_flows"],
                latencies_ms=sent,
                rejected=item["session"]["stream"]["n_rejected"],
                late=item["late_flows"],
                last_sent_at_ms=item["sent_at_last"],
            )
        # Завершение сеанса записываем сразу, не дожидаясь интервала: иначе последними
        # остались бы показатели середины потока (с «хвостом» отставания)
        completing = any(item["session"]["status"] == "completed" for item in prepared)
        if not prepared or (
            now - self._last_stats < self.cfg.consumer.stats_interval_s and not completing
        ):
            return None
        self._last_stats = now
        lag = None
        try:
            ends = self.broker.end_offsets(self.cfg.topics.flows)
            positions = {
                # позиции — уже с этой пачкой: она пишется в той же транзакции, что и показатели
                p: o
                for (t, p), o in {**self._positions, **offsets}.items()
                if t == self.cfg.topics.flows
            }
            lag = lag_messages(ends, positions)
        except BrokerUnavailable:
            lag = None
        return [
            {"run_id": item["run_id"], **self.summary.sessions[item["run_id"]].stats.snapshot(lag)}
            for item in prepared
        ]

    def _write(self, prepared: list[dict], offsets, stats_rows) -> None:
        """План инцидентов + одна транзакция; конфликт с аналитиком → пересчёт плана
        (занятую базу повторяет `process` целиком)."""
        c = self.cfg.consumer
        replans = 0
        while True:
            self._renew_lease()
            plans = [
                plan_batch(
                    self.conn,
                    item["run_id"],
                    item["alerts"],
                    self.soc,
                    lateness_ms=c.allowed_lateness_ms,
                    max_seen_ms=item["max_seen"],
                )
                for item in prepared
            ]
            try:
                store.append_batch(
                    self.conn,
                    plans,
                    offsets=offsets,
                    seen={item["run_id"]: item["seen"] for item in prepared},
                    sessions={item["run_id"]: item["session"] for item in prepared},
                    stats=stats_rows,
                    extra=[_window_writer(item["window_plan"]) for item in prepared],
                )
                return
            except store.Conflict as exc:
                replans += 1
                if replans > MAX_REPLANS:
                    raise StoreUnavailable(
                        f"пачка не записана: {MAX_REPLANS} раз подряд конфликт с решениями "
                        f"аналитиков ({exc.message}) — позиция не подтверждена"
                    ) from exc
                log.info("Конфликт с решением аналитика — пересчитываю план пачки: %s", exc.message)


def _window_writer(plan):
    """Запись плана окон сеанса внутри транзакции пачки (или ничего, если окон нет)."""
    from mlsiem.stream.windows_online import apply_window_plan

    def write(conn, at):
        if plan is not None:
            apply_window_plan(conn, plan, at)

    return write


def _ms(x: float | None) -> str:
    return "—" if x is None else f"{x:.0f} мс"


def consume(
    stream_cfg,
    soc_cfg: SocConfig,
    *,
    broker: Broker,
    model_dir: Path,
    once: bool = False,
    stop: Callable[[], bool] | None = None,
    clock: Callable[[], float] = time.time,
    holder: str | None = None,
    on_report: Callable[[str], None] | None = None,
    windows_mode: str | None = None,
    windows_model: Path | None = None,
) -> ConsumeSummary:
    """Запустить потребителя: проверки → цикл → остановка (сеансы `stopped`, аренда отдана)."""
    c = Consumer(
        stream_cfg,
        soc_cfg,
        broker=broker,
        model_dir=model_dir,
        clock=clock,
        holder=holder,
        on_report=on_report,
        windows_mode=windows_mode,
        windows_model=windows_model,
    )
    try:
        c.start()
        summary = c.run(once=once, stop=stop)
    except BaseException as exc:
        c.summary.stop_reason = str(exc) or type(exc).__name__
        c.stop(f"потребитель остановлен: {c.summary.stop_reason}")
        raise
    c.stop("потребитель остановлен" + (" (--once: сообщений больше нет)" if once else ""))
    return summary
