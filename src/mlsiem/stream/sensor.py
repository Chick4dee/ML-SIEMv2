"""Живой сенсор: трафик сети стенда → потоки тем же экстрактором 001 → брокер (фича 006).

Сенсор — ещё один производитель потоков для цепочки 005 (research R7/R8). Он слушает
интерфейс-приёмник зеркала портов в гостевой ОС, тем же `NFStreamer` и `SCHEMA.extractor`,
что и офлайн-экстрактор 001 (train = serve, конституция II), превращает завершённые потоки в
сообщения `flow` и отправляет их в брокер как источник `sensor:live`. Дальше работает готовая
онлайн-цепочка 005 (модель → алерт → инцидент → консоль).

Разделение для тестов без ВМ и без прав админа (research R18):
- `iter_live_flows` — живой захват nfstream на интерфейсе (на машине, `# pragma: no cover`);
- `flows_from_pcap` — те же потоки из записанного pcap тем же экстрактором: вход для быстрого
  теста train = serve и для разметки набора;
- `SensorSink` — буфер отправки, учёт потерь и показатели: сюда подаются готовые потоки
  любым источником, и именно эта логика проверяется в тестах (брокер — MemoryBroker 005).

idle/active-таймауты экстрактора в живом режиме НЕ трогаются (R8): иначе признаки разойдутся
с обучением. Поэтому поток уходит в брокер не раньше, чем через idle_timeout (120 с) после
последнего пакета — это учтено в целях (SC-005 считает задержку сверх таймаута).
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mlsiem.data.schema import SCHEMA
from mlsiem.stream.broker import Broker, BrokerUnavailable
from mlsiem.stream.messages import encode_end, encode_flow

DEFAULT_SOURCE_ID = "sensor:live"
# Колонки, которые выдаёт nfstream (как в extract.py): без наших key-колонок, но с его id
NFSTREAM_COLUMNS = ["id"] + [
    c
    for c in SCHEMA.names()
    if c not in SCHEMA.columns_of("key") and c not in SCHEMA.columns_of("label")
]
FIRST = "bidirectional_first_seen_ms"


class SensorError(RuntimeError):
    """Сенсор не смог начать работу (нет интерфейса, несовместимая схема); текст по-русски."""


def _cast_row(flow_values: list[Any]) -> dict[str, Any]:
    """Значения потока nfstream → типизированная строка по схеме (как чтение CSV в extract.py).

    Пустые и NaN превращаются в None (в JSON их нет — так же, как при офлайн-разборе), числа —
    в int/float по типу схемы, строки — как есть. id nfstream отбрасывается: он зависит от
    того, какой «метр» первым отдал поток, и в признаки не входит.
    """
    dtypes = SCHEMA.dtypes()
    row: dict[str, Any] = {}
    for name, value in zip(NFSTREAM_COLUMNS, flow_values, strict=True):
        if name == "id":
            continue
        row[name] = _coerce(value, dtypes[name])
    return row


def _coerce(value: Any, dtype) -> Any:
    import math

    import polars as pl

    if value is None or value == "":
        return None
    if dtype == pl.String():
        return str(value)
    try:
        if dtype == pl.Int64():
            return int(value)
        f = float(value)
        return None if math.isnan(f) else f
    except (TypeError, ValueError):
        return None


def iter_live_flows(iface: str) -> Iterator[dict[str, Any]]:  # pragma: no cover - нужна машина
    """Живой захват на интерфейсе: завершённые потоки строками по схеме 001 (R8).

    Тот же `NFStreamer` и `SCHEMA.extractor`, что офлайн, только `source=<iface>`. Набор
    колонок сверяется со схемой — расхождение значит новую версию nfstream, а не повод молча
    слать неверные потоки.
    """
    from nfstream import NFStreamer

    settings = {k: v for k, v in SCHEMA.extractor.items() if k != "library"}
    streamer = NFStreamer(source=iface, **settings)
    first = True
    for flow in streamer:
        if first:
            keys = list(flow.keys())
            if keys != NFSTREAM_COLUMNS:
                raise SensorError(
                    f"набор колонок nfstream не совпадает со схемой {SCHEMA.version}: "
                    f"лишние {sorted(set(keys) - set(NFSTREAM_COLUMNS))}, "
                    f"нет {sorted(set(NFSTREAM_COLUMNS) - set(keys))}"
                )
            first = False
        yield _cast_row(list(flow.values()))


def flows_from_pcap(pcap: Path, *, workdir: Path | None = None) -> Iterator[dict[str, Any]]:
    """Потоки из записанного pcap тем же экстрактором, в порядке завершения (по времени конца).

    Используется быстрыми тестами (train = serve) и разметкой набора вместо живого захвата.
    Порядок — по времени последнего пакета: так же завершал бы потоки живой nfstream. Временный
    CSV экстрактора кладётся в отдельный каталог (по умолчанию — свой во временной папке ОС),
    чтобы не засорять каталог с pcap.
    """
    import shutil
    import tempfile

    from mlsiem.data.extract import extract_flows

    own = workdir is None
    workdir = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="mlsiem-sensor-"))
    try:
        result = extract_flows(Path(pcap), "sensor", workdir=workdir)
    finally:
        if own:
            shutil.rmtree(workdir, ignore_errors=True)
    df = result.df.sort(["bidirectional_last_seen_ms", FIRST])
    for row in df.iter_rows(named=True):
        yield {k: row[k] for k in row if k not in ("flow_uid", "capture_id")}


# ---------------------------------------------------------------- приёмник потоков


@dataclass
class SensorCounters:
    """Счётчики сеанса сенсора (research R10/R17). Потери только растут и не «заживают»."""

    flows_seen: int = 0
    flows_sent: int = 0
    flows_dropped: int = 0  # не влезли в буфер при недоступном брокере
    packets_seen: int = 0
    packets_dropped: int = 0  # libpcap/nfstream не успел (перегрузка захвата)
    last_packet_at: float | None = None

    @property
    def lossy(self) -> bool:
        return self.flows_dropped > 0 or self.packets_dropped > 0


@dataclass
class SensorSink:
    """Отправка потоков сенсора в брокер с буфером и учётом потерь (R10).

    Поведение при недоступном брокере: завершённые потоки копятся в ограниченной очереди
    (`buffer_flows`) и досылаются, когда брокер вернётся. Переполнение очереди — честная
    потеря: счётчик растёт, сеанс помечается «с потерями» (флаг `lossy`), старые потоки из
    очереди не вытесняются (теряем новые, а не уже принятые — порядок для цепочки важнее).
    """

    broker: Broker
    topic: str
    source_id: str = DEFAULT_SOURCE_ID
    buffer_flows: int = 3000
    clock: Callable[[], float] = time.time
    counters: SensorCounters = field(default_factory=SensorCounters)
    _buffer: deque = field(default_factory=deque)
    _seq: int = 0
    _ended: bool = False

    def _send_pending(self) -> bool:
        """Пытается отправить всё из буфера. True — брокер принял (буфер пуст), False — молчит."""
        while self._buffer:
            key, value, headers = self._buffer[0]
            try:
                self.broker.produce(self.topic, key, value, headers)
            except BrokerUnavailable:
                return False
            self._buffer.popleft()
        return True

    def feed(self, row: dict[str, Any], *, packets: int | None = None) -> None:
        """Принять завершённый поток: закодировать и отправить (или отложить в буфер)."""
        self.counters.flows_seen += 1
        pkts = packets if packets is not None else row.get("bidirectional_packets") or 0
        self.counters.packets_seen += int(pkts)
        self.counters.last_packet_at = self.clock()
        # В живом режиме нет глобальной сортировки, поэтому flow_uid/capture_id сенсор задаёт
        # сам: источник и порядковый номер потока. Признаки (FEATURE_FIELDS) при этом те же
        row = {**row, "flow_uid": f"{self.source_id}/{self._seq}", "capture_id": self.source_id}
        key, value, headers = encode_flow(
            row,
            self.source_id,
            self._seq,
            int(self.clock() * 1000),
            row.get("label"),
            schema_version=SCHEMA.version,
        )
        self._seq += 1
        # Сначала пробуем освободить буфер (брокер мог вернуться), потом — новый поток
        if self._send_pending():
            try:
                self.broker.produce(self.topic, key, value, headers)
                self.counters.flows_sent += 1
                return
            except BrokerUnavailable:
                pass
        # Брокер молчит — в буфер; переполнение считаем как потерю нового потока
        if len(self._buffer) < self.buffer_flows:
            self._buffer.append((key, value, headers))
        else:
            self.counters.flows_dropped += 1

    def record_packet_drops(self, n: int) -> None:
        """Учесть потерянные при захвате пакеты (nfstream/libpcap `drop`) — перегрузка (R10)."""
        if n > 0:
            self.counters.packets_dropped += n

    def flush(self, timeout_s: float = 30.0) -> int:
        """Досылает буфер и ждёт подтверждения доставки; возвращает число неотправленного."""
        if not self._send_pending():
            return len(self._buffer)
        # Подтверждённые брокером потоки переводим в flows_sent (буфер мог содержать их)
        left = self.broker.flush(timeout_s)
        self.counters.flows_sent = self.broker.delivered
        return left + len(self._buffer)

    def end(self, timeout_s: float = 30.0) -> int:
        """Отправляет отметку `end` сеанса (как проигрыватель 005) и досылает всё."""
        remaining = self.flush(timeout_s)
        if remaining == 0 and not self._ended:
            key, value, headers = encode_end(
                self.source_id, self.counters.flows_sent, int(self.clock() * 1000)
            )
            self.broker.produce(self.topic, key, value, headers)
            self.broker.flush(timeout_s)
            self._ended = True
        return remaining

    @property
    def buffer_fill(self) -> float:
        """Занятость буфера отправки, доля [0, 1] — показатель R17."""
        return min(1.0, len(self._buffer) / self.buffer_flows) if self.buffer_flows else 0.0


@dataclass
class SensorSummary:
    run_id: str
    source_id: str
    counters: SensorCounters
    remaining: int  # не отправленных на момент завершения (0 — всё ушло)

    @property
    def lossy(self) -> bool:
        return self.counters.lossy


def run_sensor(
    cfg,
    conn,
    broker: Broker,
    flows: Iterator[dict[str, Any]],
    *,
    stop: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.time,
    send_end: bool = True,
    on_report: Callable[[str], None] | None = None,
) -> SensorSummary:
    """Главный цикл сенсора: потоки → брокер, показатели → хранилище (research R8/R10/R17).

    Источник `flows` — живой `iter_live_flows(iface)` или `flows_from_pcap(...)` в тестах.
    Потоки не из сети стенда отбрасываются (FR-006). Раз в `sensor.report_interval_s`
    пишется строка показателей сенсора; сеанс с потерями помечается `lossy`. Сеанс (строку
    `runs`) создаёт потребитель — сенсор только производитель; показатели ключуются по
    `session_run_id(source_id)` и всплывают в `stream status`, как только потребитель заведёт
    сеанс. `stop()` прерывает цикл (команда остановки), `send_end` шлёт отметку конца.
    """
    from mlsiem.soc import store

    lab = cfg.lab
    source_id = lab.sensor.source_id if lab else DEFAULT_SOURCE_ID
    subnet = lab.subnet if lab else None
    run_id = store.session_run_id(source_id)
    sink = SensorSink(
        broker,
        cfg.topics.flows,
        source_id=source_id,
        buffer_flows=lab.sensor.buffer_flows if lab else 3000,
        clock=clock,
    )
    from mlsiem.stream.stats import SensorStatsWindow

    window = SensorStatsWindow(liveness_s=lab.sensor.liveness_s if lab else 30.0, clock=clock)
    interval = lab.sensor.report_interval_s if lab else 5.0
    last_report = clock()
    lossy_written = False

    def write_report() -> None:
        nonlocal lossy_written
        snap = window.snapshot(sink.counters, buffer_fill=sink.buffer_fill)
        store.write_stats(conn, [{"run_id": run_id, "processed": sink.counters.flows_sent, **snap}])
        if sink.counters.lossy and not lossy_written:
            store.mark_lossy(conn, run_id)
            lossy_written = True
        if on_report is not None:
            on_report(
                f"сенсор: {snap['packets_per_s']:.0f} пак/с, {snap['flows_per_s']:.1f} пот/с, "
                f"потери {snap['drops']}, буфер {snap['buffer_fill'] * 100:.0f}%, "
                f"живость {'да' if snap['liveness'] else 'нет'}"
            )

    for row in flows:
        if stop():
            break
        if subnet is not None and not in_scope(row, subnet):
            continue
        pkts = int(row.get("bidirectional_packets") or 0)
        sink.feed(row)
        window.add(packets=pkts, flows=1)
        now = clock()
        if now - last_report >= interval:
            write_report()
            last_report = now
    remaining = sink.end() if send_end else sink.flush()
    write_report()
    return SensorSummary(run_id, source_id, sink.counters, remaining)


def in_scope(row: dict[str, Any], subnet) -> bool:
    """Поток относится к сети стенда? Хотя бы один адрес в `subnet` (FR-006).

    Зеркало `mlsiem-lab` несёт только трафик стенда, но на случай служебных кадров сенсор ещё
    раз отбрасывает потоки, у которых ни один конец не в сети стенда (служебная сеть — другой
    коммутатор и в зеркало не попадает, но страховка дешёвая).
    """
    import ipaddress

    for key in ("src_ip", "dst_ip"):
        ip = row.get(key)
        if ip is None:
            continue
        try:
            if ipaddress.ip_address(ip) in subnet:
                return True
        except ValueError:
            continue
    return False
