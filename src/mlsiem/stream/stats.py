"""Показатели потока (FR-022, research R11): скорость, отставание, задержка, отвергнутые.

Считаются в потребителе после каждой пачки и пишутся в SQLite (`stream_stats`) не чаще
`consumer.stats_interval_s` — там их читают `mlsiem stream status`, API и панель консоли.
Отдельного стека мониторинга нет: показатели живут там же, где их показывают.

- задержка поток → алерт = время записи алерта − `sent_at_ms` сообщения (часы производителя).
  В 005 производитель и потребитель на одном хосте, часы общие; для сенсора 006 — NTP;
- p50/p95 — по алертам скользящего окна 60 с (по часам потребителя);
- отставание в сообщениях = конец партиции − позиция чтения; в секундах = сейчас −
  `sent_at` последнего обработанного сообщения (сколько потребитель «позади» производителя);
- скорость = обработанных потоков за окно / длительность окна.
"""

from __future__ import annotations

import math
import sqlite3
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

WINDOW_S = 60.0


def percentile(values: list[float], q: float) -> float | None:
    """Перцентиль «ближайшего ранга» — без интерполяции, значение всегда из выборки."""
    if not values:
        return None
    ordered = sorted(values)
    k = max(0, math.ceil(q / 100 * len(ordered)) - 1)
    return float(ordered[k])


@dataclass
class StatsWindow:
    """Скользящее окно показателей одного сеанса."""

    clock: Callable[[], float] = time.time
    window_s: float = WINDOW_S
    _latencies: deque = field(default_factory=deque)  # (когда, задержка мс)
    _processed: deque = field(default_factory=deque)  # (когда, сколько потоков)
    rejected: int = 0
    late: int = 0
    last_sent_at_ms: int | None = None

    def add(
        self,
        *,
        processed: int,
        latencies_ms: list[float] = (),
        rejected: int = 0,
        late: int = 0,
        last_sent_at_ms: int | None = None,
    ) -> None:
        now = self.clock()
        self._processed.append((now, processed))
        for x in latencies_ms:
            self._latencies.append((now, float(x)))
        self.rejected += rejected
        self.late += late
        if last_sent_at_ms is not None:
            self.last_sent_at_ms = max(self.last_sent_at_ms or 0, last_sent_at_ms)
        self._trim(now)

    def _trim(self, now: float) -> None:
        edge = now - self.window_s
        while self._latencies and self._latencies[0][0] < edge:
            self._latencies.popleft()
        while self._processed and self._processed[0][0] < edge:
            self._processed.popleft()

    def snapshot(self, lag_messages: int | None = None) -> dict:
        now = self.clock()
        self._trim(now)
        lat = [x for _, x in self._latencies]
        n = sum(k for _, k in self._processed)
        span = (now - self._processed[0][0]) if self._processed else 0.0
        # Окно короче секунды (самое начало) — делим на секунду, а не на ноль
        rate = n / max(span, 1.0) if self._processed else 0.0
        lag_s = None
        if self.last_sent_at_ms is not None:
            lag_s = max(0.0, now - self.last_sent_at_ms / 1000)
        return {
            "processed": n,
            "rate_per_s": rate,
            "latency_p50_ms": percentile(lat, 50),
            "latency_p95_ms": percentile(lat, 95),
            "lag_messages": lag_messages,
            "lag_seconds": lag_s,
            "rejected": self.rejected,
            "late": self.late,
        }


def lag_messages(ends: dict[int, int], positions: dict[int, int]) -> int:
    """Сколько сообщений ещё не прочитано: Σ (конец партиции − позиция чтения)."""
    return sum(max(0, end - positions.get(p, 0)) for p, end in ends.items())


@dataclass
class SensorStatsWindow:
    """Скользящее окно показателей живого сенсора (фича 006, research R17).

    Считает пакеты/с и потоки/с за окно, отдаёт потери (накопленные), занятость буфера и
    живость (был ли пакет не позже `liveness_s` назад). Пишется в `stream_stats` рядом с
    показателями 005; для источников-проигрывателей эти поля остаются NULL.
    """

    liveness_s: float = 30.0
    clock: Callable[[], float] = time.time
    window_s: float = WINDOW_S
    _packets: deque = field(default_factory=deque)  # (когда, пакетов)
    _flows: deque = field(default_factory=deque)  # (когда, потоков)

    def add(self, *, packets: int, flows: int) -> None:
        now = self.clock()
        self._packets.append((now, packets))
        self._flows.append((now, flows))
        self._trim(now)

    def _trim(self, now: float) -> None:
        edge = now - self.window_s
        for dq in (self._packets, self._flows):
            while dq and dq[0][0] < edge:
                dq.popleft()

    def _rate(self, dq: deque) -> float:
        now = self.clock()
        n = sum(k for _, k in dq)
        span = (now - dq[0][0]) if dq else 0.0
        return n / max(span, 1.0) if dq else 0.0

    def snapshot(self, counters, *, buffer_fill: float) -> dict:
        """Показатели сенсора для строки `stream_stats` (packets_per_s, flows_per_s, drops,
        buffer_fill, liveness). `counters` — `stream.sensor.SensorCounters`."""
        now = self.clock()
        self._trim(now)
        last = counters.last_packet_at
        alive = last is not None and (now - last) <= self.liveness_s
        return {
            "packets_per_s": self._rate(self._packets),
            "flows_per_s": self._rate(self._flows),
            # Потери за сеанс (пакеты, не успетые захватом, + потоки, не влезшие в буфер)
            "drops": counters.packets_dropped + counters.flows_dropped,
            "buffer_fill": buffer_fill,
            "liveness": 1 if alive else 0,
        }


def check_broker_state(stream_cfg, broker_factory: Callable[[], object] | None) -> dict:
    """Жив ли брокер и где концы партиций топика потоков. Без фабрики — «не проверялся»."""
    from mlsiem.soc import store
    from mlsiem.stream.broker import BrokerUnavailable

    broker: dict = {"reachable": None, "checked_at": None, "error": None, "end_offsets": None}
    if broker_factory is None:
        return broker
    broker["checked_at"] = store.now_iso()
    try:
        b = broker_factory()
        try:
            b.ping()
            broker["reachable"] = True
            broker["end_offsets"] = b.end_offsets(stream_cfg.topics.flows)
        finally:
            b.close()
    except BrokerUnavailable as exc:
        broker["reachable"] = False
        broker["error"] = str(exc)
    return broker


def status_report(
    conn: sqlite3.Connection,
    stream_cfg,
    broker_factory: Callable[[], object] | None = None,
    *,
    broker_state: dict | None = None,
    now: float | None = None,
) -> dict:
    """Состояние потока для `stream status` и `GET /stream/status` (contracts/api-ui-additions).

    Брокер проверяется, только если передана фабрика (или готовое `broker_state`): API
    проверяет его с коротким тайм-аутом и кеширует, чтобы страница не висела на выключенной
    машине.
    """
    from mlsiem.soc import store

    now = time.time() if now is None else now
    broker = broker_state or check_broker_state(stream_cfg, broker_factory)
    lease = store.lease_info(conn, stream_cfg.consumer.lease_ttl_s, now=now)
    offsets = store.load_offsets(conn)
    positions = {p: o for (t, p), o in offsets.items() if t == stream_cfg.topics.flows}
    total_lag = (
        lag_messages(broker["end_offsets"], positions)
        if broker["end_offsets"] is not None
        else None
    )
    sessions = []
    for run in store.list_sessions(conn):
        stats = store.latest_stats(conn, run["run_id"]) or {}
        # Фича 006: показатели живого сенсора пишутся отдельными строками — берём последнюю,
        # где они есть; флаг «с потерями» — из строки runs
        sensor = store.latest_sensor_stats(conn, run["run_id"])
        stream = (run.get("summary") or {}).get("stream") or {}
        # Фича 007: окна сеанса (только у сеанса с экспертом окон, иначе None)
        win = (run.get("summary") or {}).get("windows") or {}
        on = bool(win.get("enabled"))
        sessions.append(
            {
                "run_id": run["run_id"],
                "status": run["status"],
                "source_id": run["source_id"],
                "processed": run["n_flows"],
                "n_alerts": run["n_alerts"],
                "n_incidents": run["n_incidents"],
                # Отставание в сообщениях общее для топика: сеансы делят партицию
                "lag_messages": total_lag if total_lag is not None else stats.get("lag_messages"),
                "lag_seconds": stats.get("lag_seconds"),
                "latency_p50_ms": stats.get("latency_p50_ms"),
                "latency_p95_ms": stats.get("latency_p95_ms"),
                "rejected": stream.get("n_rejected", 0),
                "late": stream.get("n_late", 0),
                "rate_per_s": stats.get("rate_per_s"),
                "last_activity_at": run["last_activity_at"],
                "end_received": bool(stream.get("end_received")),
                "windows_enabled": on,
                "n_open_windows": win.get("n_open_windows", 0) if on else None,
                "n_windows_closed": win.get("n_windows", 0) if on else None,
                "n_window_alerts": win.get("n_window_alerts", 0) if on else None,
                "n_window_late_dropped": win.get("n_window_late_dropped", 0) if on else None,
                # Фича 006: показатели живого сенсора (None у источников-проигрывателей 005)
                "is_sensor": bool(sensor),
                "lossy": bool(run.get("lossy")),
                "packets_per_s": (sensor or {}).get("packets_per_s"),
                "flows_per_s": (sensor or {}).get("flows_per_s"),
                "drops": (sensor or {}).get("drops"),
                "buffer_fill": (sensor or {}).get("buffer_fill"),
                "liveness": (sensor or {}).get("liveness"),
            }
        )
    return {
        "broker": {k: broker[k] for k in ("reachable", "checked_at", "error")},
        "consumer": {
            "alive": lease["alive"],
            "holder": lease["holder"],
            "renewed_at": lease["renewed_at"],
        },
        "lag_messages": total_lag,
        "sessions": sessions,
    }
