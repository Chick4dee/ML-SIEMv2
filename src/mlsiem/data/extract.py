"""Экстрактор потоков: PCAP → nfstream → временный CSV → отсортированная таблица → parquet.

Один и тот же код работает и для размеченных датасетов (`mlsiem data flows`), и для нового
неразмеченного PCAP (`mlsiem data extract`) — в этом весь смысл train = serve. Настройки
NFStreamer берутся только из схемы (`SCHEMA.extractor`), здесь их нет.

Почему через CSV, а не `to_pandas()` как в v1: nfstream отдаёт потоки по одному, и мы
сразу пишем их на диск. В памяти одновременно не висят объекты nfstream, pandas-таблица
и её polars-копия — пик памяти заметно ниже (research R2).

Подвох nfstream: его итератор сам перехватывает Ctrl+C, тихо останавливается и отдаёт
неполный набор потоков как будто всё в порядке. Для нас это катастрофа — прерванный захват
записался бы как готовый. Поэтому на время разбора ставим свой обработчик SIGINT, который
запоминает факт прерывания, а после разбора поднимаем KeyboardInterrupt сами.

Windows: nfstream запускает дочерние процессы (spawn), поэтому вызывающий скрипт должен
работать под `if __name__ == "__main__":` — CLI `mlsiem` это обеспечивает.
"""

from __future__ import annotations

import csv
import hashlib
import signal
import struct
import threading
from dataclasses import dataclass, field
from pathlib import Path

import polars as pl
import pyarrow.parquet as pq

from mlsiem.data.captures import atomic_path
from mlsiem.data.schema import SCHEMA

# Ключ сортировки (research R3). nfstream раскидывает потоки по нескольким процессам-«метрам»,
# поэтому порядок строк от запуска к запуску разный — без сортировки flow_uid не воспроизводится
SORT_KEY = [
    "bidirectional_first_seen_ms",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "bidirectional_last_seen_ms",
    "bidirectional_packets",
]

# Колонки, которые выдаёт экстрактор: всё, кроме разметки
FLOW_COLUMNS = [c for c in SCHEMA.names() if c not in SCHEMA.columns_of("label")]
# Колонки, которые пишет nfstream: без наших key-колонок, но с его собственным id
NFSTREAM_COLUMNS = ["id"] + [c for c in FLOW_COLUMNS if c not in SCHEMA.columns_of("key")]


# Проверка целостности: до какого размера файл проходится целиком и как проверяется хвост
FULL_WALK_LIMIT = 4 * 1024**3
TAIL_WINDOW = 4 * 1024**2
TAIL_SYNC_SPAN = 300_000  # запись не длиннее ~256 КБ, так что начало найдётся раньше
TAIL_MIN_CHAIN = 8


class ExtractError(RuntimeError):
    """Захват не удалось прочитать совсем (ни одного потока)."""


@dataclass
class ExtractResult:
    df: pl.DataFrame
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- проверка целостности PCAP


def check_pcap_integrity(path: Path) -> list[str]:
    """Проходит по заголовкам записей PCAP/PCAPNG и ищет обрыв файла.

    nfstream на обрезанном файле молча читает, сколько может, — и мы хотим хотя бы знать об
    этом (предупреждение попадёт в манифест и отчёт). Читаем только заголовки записей
    (16 байт на пакет), поэтому 2-гигабайтный файл проходится за секунды.

    Но в CTU-13 есть PCAP на 70 ГБ — сотни миллионов пакетов, и полный проход по ним на
    Python занял бы больше, чем сам разбор nfstream. Для таких файлов проверяем только хвост
    (`_check_pcap_tail`): обрыв бывает именно в конце файла.
    """
    path = Path(path)
    size = path.stat().st_size
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            return [f"{path.name}: файл короче заголовка PCAP ({size} байт)"]
        magic = head[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        elif magic == b"\x0a\x0d\x0d\x0a":
            return _check_pcapng(f, size, path.name)
        else:
            return [f"{path.name}: формат не распознан, целостность не проверена"]

        if size > FULL_WALK_LIMIT:
            snaplen = struct.unpack(endian + "I", head[16:20])[0]
            return _check_pcap_tail(f, size, endian, snaplen, path.name)

        pos, n = 24, 0
        while pos < size:
            if pos + 16 > size:
                return [
                    f"{path.name}: файл обрывается в заголовке пакета №{n + 1} "
                    f"(смещение {pos}); прочитаны пакеты до обрыва"
                ]
            f.seek(pos + 8)
            incl_len = struct.unpack(endian + "I", f.read(4))[0]
            if pos + 16 + incl_len > size:
                return [
                    f"{path.name}: файл обрывается внутри пакета №{n + 1} "
                    f"(смещение {pos}); прочитаны пакеты до обрыва"
                ]
            pos += 16 + incl_len
            n += 1
    return []


def _check_pcap_tail(f, size: int, endian: str, snaplen: int, name: str) -> list[str]:
    """Проверка только последних TAIL_WINDOW байт большого PCAP.

    Где в хвосте начинается запись, заранее неизвестно, поэтому ищем смещение, с которого
    выстраивается цепочка правдоподобных заголовков (длина пакета не больше snaplen и
    исходной длины, время близко ко времени первого пакета файла). Случайный мусор такую
    цепочку из нескольких записей подряд не образует. Если цепочка доходит ровно до конца
    файла — всё в порядке; если последняя запись обрывается — файл обрезан.
    """
    f.seek(24)
    first = f.read(16)
    if len(first) < 16:
        return []
    first_ts = struct.unpack(endian + "I", first[:4])[0]
    start = max(24, size - TAIL_WINDOW)
    f.seek(start)
    buf = f.read()
    end = len(buf)
    header = struct.Struct(endian + "IIII")
    ten_years = 10 * 365 * 24 * 3600

    for i in range(min(end, TAIL_SYNC_SPAN)):
        pos, n = i, 0
        while pos + 16 <= end:
            ts, frac, incl, orig = header.unpack_from(buf, pos)
            plausible = (
                incl <= snaplen
                and incl <= orig
                and frac < 1_000_000_000
                and abs(ts - first_ts) < ten_years
            )
            if not plausible:
                break
            if pos + 16 + incl > end:
                if n >= TAIL_MIN_CHAIN:
                    return [
                        f"{name}: файл обрывается внутри последнего пакета "
                        f"(смещение {start + pos}); прочитаны пакеты до обрыва"
                    ]
                break
            pos += 16 + incl
            n += 1
        else:
            if n >= TAIL_MIN_CHAIN:
                if pos == end:
                    return []
                return [
                    f"{name}: файл обрывается в заголовке последнего пакета "
                    f"(смещение {start + pos}); прочитаны пакеты до обрыва"
                ]
    return [f"{name}: хвост файла не разобран, целостность не проверена"]


def _check_pcapng(f, size: int, name: str) -> list[str]:
    f.seek(8)
    bom = f.read(4)
    endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
    pos, n = 0, 0
    while pos < size:
        if pos + 8 > size:
            return [f"{name}: pcapng обрывается в заголовке блока №{n + 1}"]
        f.seek(pos + 4)
        block_len = struct.unpack(endian + "I", f.read(4))[0]
        if block_len < 12 or pos + block_len > size:
            return [f"{name}: pcapng обрывается внутри блока №{n + 1} (смещение {pos})"]
        pos += block_len
        n += 1
    return []


# ---------------------------------------------------------------- nfstream → CSV


class _InterruptGuard:
    """Запоминает Ctrl+C, который nfstream иначе проглотил бы (см. docstring модуля)."""

    def __init__(self) -> None:
        self.interrupted = False
        self._previous = None

    def _handler(self, signum, frame):
        self.interrupted = True
        raise KeyboardInterrupt  # nfstream на это корректно гасит своих «метров»

    def __enter__(self):
        # Обработчики сигналов можно ставить только из главного потока
        if threading.current_thread() is threading.main_thread():
            self._previous = signal.signal(signal.SIGINT, self._handler)
        return self

    def __exit__(self, *exc):
        if self._previous is not None:
            signal.signal(signal.SIGINT, self._previous)
        return False


def pcap_to_csv(pcap: Path, csv_path: Path) -> int:
    """Прогоняет PCAP через nfstream и пишет потоки в CSV. Возвращает число потоков."""
    from nfstream import NFStreamer  # тяжёлый импорт — только когда реально нужен

    settings = {k: v for k, v in SCHEMA.extractor.items() if k != "library"}
    streamer = NFStreamer(source=str(pcap), **settings)
    n = 0
    with open(csv_path, "w", newline="", encoding="utf-8") as f, _InterruptGuard() as guard:
        writer = csv.writer(f)
        writer.writerow(NFSTREAM_COLUMNS)
        for flow in streamer:
            if n == 0:
                keys = list(flow.keys())
                if keys != NFSTREAM_COLUMNS:
                    # Версия nfstream выдала другой набор колонок — это новая схема,
                    # а не повод молча записать неправильную таблицу
                    raise ExtractError(
                        "набор колонок nfstream не совпадает со схемой "
                        f"{SCHEMA.version}: лишние {sorted(set(keys) - set(NFSTREAM_COLUMNS))}, "
                        f"нет {sorted(set(NFSTREAM_COLUMNS) - set(keys))}"
                    )
            writer.writerow(flow.values())
            n += 1
    if guard.interrupted:
        raise KeyboardInterrupt
    return n


def read_flows_csv(csv_path: Path) -> pl.DataFrame:
    """Читает CSV nfstream с типами из схемы и выбрасывает id.

    id — внутренний номер nfstream, зависящий от того, какой «метр» первым отдал поток;
    с ним таблица между запусками не совпадала бы никогда.
    """
    dtypes = SCHEMA.dtypes()
    schema = {"id": pl.Int64(), **{c: dtypes[c] for c in NFSTREAM_COLUMNS[1:]}}
    return pl.scan_csv(csv_path, schema=schema).drop("id").collect()


# ---------------------------------------------------------------- сортировка и ключи


def sort_flows(df: pl.DataFrame) -> pl.DataFrame:
    """Полная детерминированная сортировка: ключ R3, потом все остальные колонки по порядку.

    Только 8 полей ключа мало: два потока могут совпасть по ним целиком (например, повторы
    одного и того же запроса), и тогда их взаимный порядок снова случаен.
    """
    rest = [c for c in df.columns if c not in SORT_KEY and c not in ("flow_uid", "capture_id")]
    by = [c for c in SORT_KEY if c in df.columns] + rest
    return df.sort(by, nulls_last=True, maintain_order=True)


def add_keys(df: pl.DataFrame, capture_id: str) -> pl.DataFrame:
    """Добавляет flow_uid = `<capture_id>/<номер после сортировки>` и capture_id в начало."""
    return df.select(
        pl.concat_str(
            pl.lit(f"{capture_id}/"), pl.int_range(pl.len(), dtype=pl.Int64).cast(pl.String)
        ).alias("flow_uid"),
        pl.lit(capture_id, dtype=pl.String).alias("capture_id"),
        pl.all(),
    )


def extract_flows(pcap: Path, capture_id: str, *, workdir: Path) -> ExtractResult:
    """PCAP → отсортированная таблица потоков по схеме (без колонок разметки)."""
    pcap = Path(pcap)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    warnings = check_pcap_integrity(pcap)
    csv_path = workdir / f".{capture_id}.nfstream.csv"
    try:
        try:
            pcap_to_csv(pcap, csv_path)
        except ValueError as exc:
            # nfstream сообщает об ошибках чтения файла через ValueError. Если что-то
            # успели прочитать до ошибки — сохраняем это с предупреждением, иначе падаем
            if not csv_path.exists() or read_flows_csv(csv_path).height == 0:
                raise ExtractError(f"nfstream не смог прочитать {pcap.name}: {exc}") from exc
            warnings.append(f"{pcap.name}: nfstream прервал чтение: {exc}")
        df = read_flows_csv(csv_path)
    finally:
        # Временный CSV может весить гигабайты — не оставляем его ни при каком исходе
        csv_path.unlink(missing_ok=True)
    df = add_keys(sort_flows(df), capture_id)
    return ExtractResult(df=df.select(FLOW_COLUMNS), warnings=warnings)


# ---------------------------------------------------------------- хеш и запись


def content_hash(df: pl.DataFrame) -> str:
    """SHA-256 по содержимому таблицы: имена, типы и значения колонок по порядку.

    Хешировать байты parquet нельзя: они меняются с версией pyarrow и настройками сжатия,
    а данные при этом те же. Здесь хешируется ровно то, что прочитает потребитель.
    """
    h = hashlib.sha256()
    h.update(str(df.height).encode())
    for name in df.columns:
        s = df[name]
        h.update(f"\x1e{name}:{s.dtype}".encode())
        h.update(s.is_null().to_numpy().tobytes())
        if s.dtype == pl.String:
            h.update("\x1f".join(s.fill_null("").to_list()).encode("utf-8"))
        else:
            h.update(s.fill_null(0).to_numpy().tobytes())
    return h.hexdigest()


def write_flows_parquet(df: pl.DataFrame, path: Path, metadata: dict[str, str]) -> None:
    """Пишет parquet атомарно; в метаданные файла кладётся версия схемы и переданные поля."""
    table = df.to_arrow()
    meta = dict(table.schema.metadata or {})
    meta.update({b"mlsiem.schema_version": SCHEMA.version.encode()})
    meta.update({k.encode(): str(v).encode() for k, v in metadata.items()})
    table = table.replace_schema_metadata(meta)
    with atomic_path(Path(path)) as tmp:
        pq.write_table(table, tmp, compression="zstd")


def read_parquet_metadata(path: Path) -> dict[str, str]:
    meta = pq.read_schema(path).metadata or {}
    return {k.decode(): v.decode() for k, v in meta.items() if k.decode().startswith("mlsiem.")}
