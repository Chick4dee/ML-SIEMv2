"""Проигрыватели: часть разбиения 001 или PCAP → сообщения в брокер (FR-008, FR-009, research R6).

Порядок — по времени начала потока `(bidirectional_first_seen_ms, flow_uid)`: так же
упорядочивает пакетная группировка, и так же (без опозданий) отдавал бы потоки сенсор.
`seq` — номер потока в источнике с 0 без пропусков; по нему потребитель понимает, что всё до
отметки `end` обработано, а `--resume` — с какого потока продолжать.

Темп. `speed = N` — «реальное время × N»: поток с временем трафика t уходит в момент
`старт + (t − t₀) / N` по часам. Считается от старта, а не от предыдущего потока — поэтому
накопившееся отставание (медленная отправка, пауза ОС) само компенсируется: следующие
потоки уйдут без пауз, пока график не догонят. Паузы короче 1 мс не делаются — это шум
планировщика, а не темп трафика. `speed = None` («max») — без пауз вовсе.

Часы (`clock`) и сон (`sleep`) передаются параметрами: тесты подменяют их и проверяют темп
без реального ожидания.

Проигрыватель не пишет ничего, кроме сообщений в брокер: `source_id` новый при каждом запуске
(время запуска в имени), так что повторное проигрывание того же входа — новый источник и
новый сеанс (FR-018), а не дубли в старом.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import orjson
import polars as pl

from mlsiem.data.extract import read_parquet_metadata
from mlsiem.data.schema import SCHEMA
from mlsiem.stream.broker import Broker, BrokerUnavailable
from mlsiem.stream.messages import (
    FEATURE_FIELDS,
    H_KIND,
    KIND_END,
    KIND_FLOW,
    check_schema_major,
    encode_end,
    encode_flow,
)

FIRST = "bidirectional_first_seen_ms"
ORDER = [FIRST, "flow_uid"]
# Сколько строк за раз превращать в словари: память ровная и на 282 тыс. потоков
SLICE_ROWS = 50_000
# Сколько ждать подтверждения доставки всего в конце, секунд
FLUSH_TIMEOUT_S = 60
MIN_SLEEP_S = 0.001


class ReplayError(RuntimeError):
    """Проигрывание не удалось; текст — по-русски, с тем, сколько отправлено и что делать."""


@dataclass
class ReplaySource:
    """Что проигрывается: подпись входа (для source_id), сами потоки и версия схемы."""

    label: str
    flows: pl.DataFrame
    schema_version: str | None
    warnings: list[str]

    @property
    def total(self) -> int:
        return self.flows.height


@dataclass
class ReplaySummary:
    source_id: str
    total: int
    sent: int
    first_seq: int
    seconds: float
    behind_s: float

    @property
    def rate(self) -> float:
        return self.sent / self.seconds if self.seconds > 0 else float(self.sent)


def new_source_id(label: str, now: datetime | None = None) -> str:
    """`replay:<вход>:<UTC YYYYMMDDTHHMMSS>` — новый при каждом запуске проигрывателя."""
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%S")
    return f"replay:{label}:{stamp}"


def _check_version(version: str | None, what: str) -> None:
    if version is None:
        raise ReplayError(
            f"у {what} нет версии схемы признаков в метаданных — проигрывание не начато: "
            "без версии потребитель не сможет проверить совместимость с моделью (FR-005)"
        )
    if not check_schema_major(version):
        raise ReplayError(
            f"у {what} схема {version}, а код работает со схемой {SCHEMA.version} (мажорные "
            "версии различаются) — проигрывание не начато; пересчитайте потоки "
            "(`mlsiem data flows`)"
        )


def load_split_source(
    split: str, part: str, *, data_dir: Path = Path("data"), limit: int | None = None
) -> ReplaySource:
    """Все колонки схемы + метка части разбиения, по времени начала. Версия схемы —
    из метаданных parquet потоков 001 и обязана быть одной и совместимой."""
    from mlsiem.detect.dataset import flow_files, scan_part

    files = flow_files(split, data_dir)
    versions = {read_parquet_metadata(f).get("mlsiem.schema_version") for f in files}
    if len(versions) != 1:
        raise ReplayError(
            f"потоки разбиения {split} записаны разными версиями схемы: "
            f"{sorted(map(str, versions))} — проигрывание не начато"
        )
    version = versions.pop()
    _check_version(version, f"потоков разбиения {split}")
    lazy = scan_part(split, part, data_dir=data_dir, columns=[*FEATURE_FIELDS, "label"]).sort(ORDER)
    if limit is not None:
        lazy = lazy.head(limit)
    return ReplaySource(f"{split}/{part}", lazy.collect(), version, [])


def load_pcap_source(pcap: Path, workdir: Path) -> ReplaySource:
    """PCAP → потоки тем же экстрактором 001, что `soc run --pcap` (FR-008)."""
    from mlsiem.data.extract import extract_flows
    from mlsiem.soc.run import _check_pcap_path

    pcap = Path(pcap)
    _check_pcap_path(pcap)
    capture_id = "adhoc_" + pcap.stem.replace(":", "_")
    result = extract_flows(pcap, capture_id, workdir=workdir)
    flows = result.df.sort(ORDER)
    return ReplaySource(pcap.name, flows, SCHEMA.version, list(result.warnings))


def iter_rows(flows: pl.DataFrame, skip: int = 0) -> Iterator[dict]:
    """Строки потоков словарями, кусками по SLICE_ROWS (без копии всей таблицы в словари)."""
    for chunk in flows.slice(skip).iter_slices(SLICE_ROWS):
        yield from chunk.iter_rows(named=True)


def find_resume(broker: Broker, topic: str, source_id: str) -> tuple[int, bool]:
    """(следующий seq, уже отправлен ли end) по сообщениям источника в топике.

    Идём по всему топику: сообщения источника лежат в одной партиции по ключу, и этого
    хватает — проигрыватель запускают руками после сбоя, а не в цикле.
    """
    next_seq, ended = 0, False
    for msg in broker.scan(topic):
        if msg.key != source_id:
            continue
        kind = msg.headers.get(H_KIND)
        if kind == KIND_END:
            ended = True
            continue
        if kind == KIND_FLOW:
            try:
                seq = orjson.loads(msg.value)["seq"]
            except (orjson.JSONDecodeError, KeyError, TypeError):
                continue
            next_seq = max(next_seq, int(seq) + 1)
    return next_seq, ended


def replay(
    source: ReplaySource,
    broker: Broker,
    topic: str,
    *,
    source_id: str,
    speed: float | None,
    first_seq: int = 0,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    on_progress: Callable[[int, int, float, float], None] | None = None,
    progress_interval_s: float = 1.0,
) -> ReplaySummary:
    """Отправить потоки (начиная с `first_seq`) и отметку `end`; вернуть сводку.

    `on_progress(отправлено, всего, потоков/с, отставание от графика, с)` — не чаще раза в
    `progress_interval_s`. При недоступном брокере — `ReplayError` «отправлено N из M».
    """
    total = source.total
    started = clock()
    t0_traffic = None
    behind = 0.0
    last_report = started
    sent_before = broker.delivered
    seq = first_seq

    def sent_now() -> int:
        return first_seq + broker.delivered - sent_before

    try:
        for row in iter_rows(source.flows, first_seq):
            if speed is not None:
                t = row[FIRST]
                if t0_traffic is None:
                    t0_traffic = t
                target = started + (t - t0_traffic) / 1000.0 / speed
                delay = target - clock()
                if delay >= MIN_SLEEP_S:
                    sleep(delay)
                else:
                    behind = max(behind, -delay)
            key, value, headers = encode_flow(
                row,
                source_id,
                seq,
                int(clock() * 1000),
                row.get("label"),
                schema_version=source.schema_version or SCHEMA.version,
            )
            broker.produce(topic, key, value, headers)
            seq += 1
            now = clock()
            if on_progress is not None and now - last_report >= progress_interval_s:
                elapsed = now - started
                on_progress(seq, total, (seq - first_seq) / elapsed if elapsed else 0.0, behind)
                last_report = now
        key, value, headers = encode_end(
            source_id,
            total,
            int(clock() * 1000),
            schema_version=source.schema_version or SCHEMA.version,
        )
        broker.produce(topic, key, value, headers)
        left = broker.flush(FLUSH_TIMEOUT_S)
    except BrokerUnavailable as exc:
        raise ReplayError(
            f"{exc}. Отправлено {max(sent_now(), first_seq)} из {total} — продолжить: "
            f"--resume {source_id}"
        ) from exc
    if left:
        raise ReplayError(
            f"брокер не подтвердил доставку {left} сообщений за {FLUSH_TIMEOUT_S} с. "
            f"Отправлено {sent_now()} из {total} — продолжить: --resume {source_id}"
        )
    return ReplaySummary(
        source_id=source_id,
        total=total,
        sent=seq - first_seq,
        first_seq=first_seq,
        seconds=clock() - started,
        behind_s=behind,
    )
