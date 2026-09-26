"""Граница с брокером: интерфейс `Broker` и две реализации (research R4).

Зачем интерфейс, а не прямые вызовы confluent-kafka. Гарантии фичи — «ни потерь, ни дублей
при любом сбое» (FR-015, FR-016) — надо проверять детерминированно: сбой ровно между записью
в SQLite и подтверждением брокеру, повторная доставка, недоступный брокер. На настоящей Kafka
такие тесты медленные и требуют машины стенда. Поэтому всё, что цепочке нужно от брокера,
сведено к десятку методов, и у них две реализации:

- `KafkaBroker` — настоящий клиент (confluent-kafka поверх librdkafka): идемпотентный
  продюсер, ручное подтверждение позиций, администрирование топиков;
- `MemoryBroker` — брокер в памяти процесса с партициями, позициями группы, повторной
  доставкой после «сбоя» и выключением «машины». На нём идут все быстрые тесты.

Позиции потребителя. Истина — в SQLite (`stream_offsets`, R7), поэтому потребитель при старте
сам говорит брокеру, откуда читать (`seek`), а подтверждение в Kafka (`commit`) — лишь копия
для внешних инструментов. Потребитель у нас один (аренда, FR-019), так что партиции
назначаются ему явно (`assign`), без перебалансировок группы.
"""

from __future__ import annotations

import contextlib
import itertools
import os
import socket
import time
import zlib
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

# Ключ позиции: (топик, партиция) → следующая позиция для чтения
Offsets = dict[tuple[str, int], int]


class BrokerUnavailable(RuntimeError):
    """Брокер не отвечает. Сообщение — готовый текст по-русски с подсказкой, что делать."""


@dataclass(frozen=True)
class Message:
    topic: str
    partition: int
    offset: int
    key: str | None
    value: bytes
    headers: dict[str, str]
    timestamp_ms: int


@dataclass(frozen=True)
class TopicSpec:
    name: str
    partitions: int
    retention_ms: int


def unavailable_text(bootstrap: str, timeout_s: float, vm_name: str | None = None) -> str:
    hint = f" — машина выключена? Start-VM {vm_name}" if vm_name else ""
    return f"брокер {bootstrap} недоступен за {timeout_s:g} с{hint}"


class Broker(ABC):
    """Всё, что цепочке нужно от брокера. Методы бросают `BrokerUnavailable`, если брокер
    не отвечает, — вызывающий решает, повторять или останавливаться."""

    @abstractmethod
    def ping(self) -> None:
        """Проверить, что брокер отвечает (за `connect_timeout_s`), иначе `BrokerUnavailable`."""

    @abstractmethod
    def produce(self, topic: str, key: str | None, value: bytes, headers: dict[str, str]) -> None:
        """Поставить сообщение в отправку (асинхронно). Доставку подтверждает `flush`."""

    @abstractmethod
    def flush(self, timeout: float) -> int:
        """Дождаться доставки; вернуть число сообщений, так и не доставленных."""

    @property
    @abstractmethod
    def delivered(self) -> int:
        """Сколько сообщений брокер подтвердил с момента создания клиента."""

    @abstractmethod
    def subscribe(self, topics: list[str]) -> None:
        """Назначить себе все партиции топиков. Старт — с позиций `seek`, иначе с
        подтверждённых группой, иначе с начала топика."""

    @abstractmethod
    def poll_batch(self, max_messages: int, timeout_ms: int) -> list[Message]:
        """До `max_messages` сообщений; ждать не дольше `timeout_ms`, если сообщений нет."""

    @abstractmethod
    def seek(self, topic: str, partition: int, offset: int) -> None:
        """Следующее чтение партиции — с этой позиции (до или после `subscribe`)."""

    @abstractmethod
    def commit(self, offsets: Offsets) -> None:
        """Подтвердить брокеру позиции (следующие для чтения) — синхронно."""

    @abstractmethod
    def committed(self, topic: str) -> Offsets:
        """Подтверждённые группой позиции партиций топика."""

    @abstractmethod
    def end_offsets(self, topic: str) -> dict[int, int]:
        """Конец каждой партиции (позиция, которую получит следующее сообщение)."""

    @abstractmethod
    def list_topics(self) -> dict[str, dict[str, Any]]:
        """Топики брокера: имя → {partitions, retention_ms}."""

    @abstractmethod
    def ensure_topics(self, specs: list[TopicSpec]) -> list[str]:
        """Создать недостающие топики (идемпотентно); вернуть имена созданных."""

    @abstractmethod
    def scan(self, topic: str) -> Iterator[Message]:
        """Все сообщения топика от начала до текущего конца — отдельным читателем, без
        подтверждений и без влияния на позиции группы (нужно проигрывателю для `--resume`)."""

    @abstractmethod
    def close(self) -> None: ...

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ---------------------------------------------------------------- заглушка в памяти


@dataclass
class MemoryCluster:
    """Общее состояние «брокера в памяти»: журналы партиций и подтверждённые позиции групп.

    Клиентов (`MemoryBroker`) у одного кластера может быть сколько угодно — как у настоящего
    брокера: проигрыватель пишет одним, потребитель читает другим, «перезапущенный»
    потребитель — третьим.
    """

    partitions: dict[str, int] = field(default_factory=dict)
    retention_ms: dict[str, int] = field(default_factory=dict)
    logs: dict[tuple[str, int], list[Message]] = field(default_factory=dict)
    group_offsets: dict[str, Offsets] = field(default_factory=dict)
    # «Машина выключена»: любой вызов клиента → BrokerUnavailable
    down: bool = False
    # Для тестов «брокер пропал посреди проигрывания»: после стольких produce — недоступен
    fail_after_produce: int | None = None
    produced: int = 0
    clock: Any = time.time

    def add_topic(self, name: str, partitions: int = 1, retention_ms: int = 0) -> None:
        if name not in self.partitions:
            self.partitions[name] = partitions
            self.retention_ms[name] = retention_ms
            for p in range(partitions):
                self.logs[(name, p)] = []


class MemoryBroker(Broker):
    """Брокер в памяти с поведением Kafka, важным для гарантий доставки.

    - сообщения с одним ключом идут в одну партицию и читаются в порядке отправки;
    - позиция группы меняется только `commit`; новый клиент той же группы начинает с неё;
    - `crash()` — «потребитель упал»: всё прочитанное, но не подтверждённое, следующий
      клиент получит снова (повторная доставка, at-least-once);
    - `cluster.down = True` — «машина брокера выключена».
    """

    def __init__(
        self,
        cluster: MemoryCluster | None = None,
        *,
        group: str = "mlsiem-chain",
        bootstrap: str = "memory:9092",
        vm_name: str | None = None,
    ) -> None:
        self.cluster = cluster or MemoryCluster()
        self.group = group
        self.bootstrap = bootstrap
        self.vm_name = vm_name
        self._delivered = 0
        self._pending = 0
        self._topics: list[str] = []
        self._positions: Offsets = {}
        self._seeks: Offsets = {}
        self._closed = False

    def client(self, **kw) -> MemoryBroker:
        """Ещё один клиент того же кластера (например, «перезапущенный» потребитель)."""
        return MemoryBroker(self.cluster, group=kw.get("group", self.group), vm_name=self.vm_name)

    def _check(self) -> None:
        if self._closed:
            raise RuntimeError("клиент брокера уже закрыт (или «упал» в тесте)")
        if self.cluster.down:
            raise BrokerUnavailable(unavailable_text(self.bootstrap, 0, self.vm_name))

    def ping(self) -> None:
        self._check()

    @staticmethod
    def partition_of(key: str | None, n: int) -> int:
        return 0 if key is None or n == 1 else zlib.crc32(key.encode("utf-8")) % n

    def produce(self, topic, key, value, headers) -> None:
        self._check()
        c = self.cluster
        if c.fail_after_produce is not None and c.produced >= c.fail_after_produce:
            c.down = True
            raise BrokerUnavailable(unavailable_text(self.bootstrap, 0, self.vm_name))
        if topic not in c.partitions:
            # auto.create.topics.enable=false у настоящего брокера — и здесь так же
            raise ValueError(f"топика {topic} нет на брокере — создайте его (ensure_topics)")
        p = self.partition_of(key, c.partitions[topic])
        log = c.logs[(topic, p)]
        log.append(
            Message(
                topic=topic,
                partition=p,
                offset=len(log),
                key=key,
                value=bytes(value),
                headers=dict(headers),
                timestamp_ms=int(c.clock() * 1000),
            )
        )
        c.produced += 1
        self._delivered += 1

    def flush(self, timeout: float) -> int:
        self._check()
        return self._pending

    @property
    def delivered(self) -> int:
        return self._delivered

    def subscribe(self, topics: list[str]) -> None:
        self._check()
        self._topics = list(topics)
        committed = self.cluster.group_offsets.setdefault(self.group, {})
        for t in topics:
            for p in range(self.cluster.partitions.get(t, 0)):
                tp = (t, p)
                self._positions[tp] = self._seeks.get(tp, committed.get(tp, 0))

    def poll_batch(self, max_messages: int, timeout_ms: int) -> list[Message]:
        self._check()
        out: list[Message] = []
        for tp in sorted(self._positions):
            log = self.cluster.logs.get(tp, [])
            pos = self._positions[tp]
            take = log[pos : pos + max_messages - len(out)]
            out += take
            self._positions[tp] = pos + len(take)
            if len(out) >= max_messages:
                break
        return out

    def seek(self, topic: str, partition: int, offset: int) -> None:
        self._seeks[(topic, partition)] = offset
        if (topic, partition) in self._positions:
            self._positions[(topic, partition)] = offset

    def commit(self, offsets: Offsets) -> None:
        self._check()
        self.cluster.group_offsets.setdefault(self.group, {}).update(offsets)

    def committed(self, topic: str) -> Offsets:
        self._check()
        got = self.cluster.group_offsets.get(self.group, {})
        return {tp: o for tp, o in got.items() if tp[0] == topic}

    def end_offsets(self, topic: str) -> dict[int, int]:
        self._check()
        n = self.cluster.partitions.get(topic, 0)
        return {p: len(self.cluster.logs[(topic, p)]) for p in range(n)}

    def list_topics(self) -> dict[str, dict[str, Any]]:
        self._check()
        return {
            t: {"partitions": n, "retention_ms": self.cluster.retention_ms.get(t)}
            for t, n in sorted(self.cluster.partitions.items())
        }

    def ensure_topics(self, specs: list[TopicSpec]) -> list[str]:
        self._check()
        created = [s.name for s in specs if s.name not in self.cluster.partitions]
        for s in specs:
            self.cluster.add_topic(s.name, s.partitions, s.retention_ms)
        return created

    def scan(self, topic: str) -> Iterator[Message]:
        self._check()
        for p in range(self.cluster.partitions.get(topic, 0)):
            yield from list(self.cluster.logs[(topic, p)])

    def crash(self) -> None:
        """«Процесс упал»: ничего не подтверждает и больше не работает."""
        self._closed = True

    def close(self) -> None:
        self._closed = True

    # Удобства для тестов
    def messages(self, topic: str) -> list[Message]:
        return list(
            itertools.chain.from_iterable(
                self.cluster.logs[(topic, p)] for p in range(self.cluster.partitions.get(topic, 0))
            )
        )


# ---------------------------------------------------------------- настоящий Kafka


class KafkaBroker(Broker):
    """Клиент Kafka на confluent-kafka (librdkafka).

    Продюсер идемпотентный (`enable.idempotence=true`, `acks=all`): повтор отправки после
    сетевой ошибки не создаёт дублей в журнале брокера. Потребитель без автоподтверждения
    (`enable.auto.commit=false`) — позицию подтверждаем сами и только после записи в SQLite.
    """

    def __init__(
        self,
        bootstrap: str,
        *,
        group: str,
        connect_timeout_s: float,
        vm_name: str | None = None,
        client_id: str = "mlsiem",
    ) -> None:
        self.bootstrap = bootstrap
        self.group = group
        self.timeout = float(connect_timeout_s)
        self.vm_name = vm_name
        self.client_id = client_id
        self._producer = None
        self._consumer = None
        self._admin = None
        self._delivered = 0
        self._errors: list[str] = []
        self._assigned: Offsets = {}
        self._seeks: Offsets = {}

    # ------------------------------------------------ служебное

    def _unavailable(self, exc: BaseException | None = None) -> BrokerUnavailable:
        text = unavailable_text(self.bootstrap, self.timeout, self.vm_name)
        if exc is not None:
            text += f" ({exc})"
        return BrokerUnavailable(text)

    def _base(self) -> dict[str, Any]:
        # socket.connection.setup.timeout.ms — чтобы «машина выключена» было ошибкой за
        # connect_timeout_s, а не бесконечными попытками переподключения в фоне.
        # log_level 0: librdkafka пишет в stderr каждую неудачную попытку соединения —
        # десятки строк, пока машина выключена; недоступность мы и так сообщаем одной
        # понятной строкой
        return {
            "bootstrap.servers": self.bootstrap,
            "client.id": f"{self.client_id}-{socket.gethostname()}-{os.getpid()}",
            "socket.connection.setup.timeout.ms": int(self.timeout * 1000),
            "log_level": 0,
        }

    def _admin_client(self):
        if self._admin is None:
            from confluent_kafka.admin import AdminClient

            self._admin = AdminClient(self._base())
        return self._admin

    def _metadata(self):
        from confluent_kafka import KafkaException

        try:
            return self._admin_client().list_topics(timeout=self.timeout)
        except KafkaException as exc:
            raise self._unavailable(exc) from exc

    def ping(self) -> None:
        self._metadata()

    def cluster_info(self) -> dict[str, Any]:
        """Сведения о кластере для `stand check`: id, узлы, контроллер."""
        md = self._metadata()
        return {
            "cluster_id": md.cluster_id,
            "brokers": [f"{b.host}:{b.port}" for b in md.brokers.values()],
            "controller_id": md.controller_id,
        }

    # ------------------------------------------------ продюсер

    def _producer_client(self):
        if self._producer is None:
            from confluent_kafka import Producer

            self._producer = Producer(
                {
                    **self._base(),
                    "enable.idempotence": True,
                    "acks": "all",
                    "linger.ms": 5,
                    "compression.type": "lz4",
                    # Сколько ждать доставку одного сообщения, прежде чем признать ошибку
                    "delivery.timeout.ms": max(int(self.timeout * 3000), 30000),
                }
            )
        return self._producer

    def _on_delivery(self, err, msg) -> None:
        if err is None:
            self._delivered += 1
        else:
            self._errors.append(str(err))

    def produce(self, topic, key, value, headers) -> None:
        p = self._producer_client()
        if self._errors:
            raise self._unavailable(RuntimeError(self._errors[-1]))
        hdrs = [(k, v.encode("utf-8")) for k, v in headers.items()]
        for _ in range(2):
            try:
                p.produce(topic, value=value, key=key, headers=hdrs, on_delivery=self._on_delivery)
                break
            except BufferError:
                # Очередь librdkafka полна: даём ей отправить накопленное и пробуем ещё раз
                p.poll(self.timeout)
        else:
            raise self._unavailable(RuntimeError("очередь отправки переполнена"))
        p.poll(0)

    def flush(self, timeout: float) -> int:
        if self._producer is None:
            return 0
        left = self._producer.flush(timeout)
        if self._errors and left == 0:
            return len(self._errors)
        return left

    @property
    def delivered(self) -> int:
        return self._delivered

    # ------------------------------------------------ потребитель

    def _consumer_client(self):
        if self._consumer is None:
            from confluent_kafka import Consumer

            self._consumer = Consumer(
                {
                    **self._base(),
                    "group.id": self.group,
                    "enable.auto.commit": False,
                    "enable.auto.offset.store": False,
                    "auto.offset.reset": "earliest",
                }
            )
        return self._consumer

    def _reassign(self) -> None:
        from confluent_kafka import TopicPartition

        self._consumer_client().assign(
            [TopicPartition(t, p, o) for (t, p), o in sorted(self._assigned.items())]
        )

    def subscribe(self, topics: list[str]) -> None:
        from confluent_kafka import OFFSET_BEGINNING

        md = self._metadata()
        start: Offsets = {}
        for t in topics:
            if t not in md.topics:
                raise ValueError(
                    f"топика {t} нет на брокере {self.bootstrap} — `mlsiem stand check`"
                )
            for p in md.topics[t].partitions:
                start[(t, p)] = OFFSET_BEGINNING
            for tp, o in self.committed(t).items():
                if o >= 0:
                    start[tp] = o
        start.update({tp: o for tp, o in self._seeks.items() if tp in start})
        self._assigned = start
        self._reassign()

    def poll_batch(self, max_messages: int, timeout_ms: int) -> list[Message]:
        from confluent_kafka import KafkaError, KafkaException

        try:
            raw = self._consumer_client().consume(max_messages, timeout_ms / 1000)
        except KafkaException as exc:
            raise self._unavailable(exc) from exc
        out = []
        for m in raw:
            err = m.error()
            if err is not None:
                if err.code() == KafkaError._PARTITION_EOF:
                    continue
                if err.code() in (KafkaError._TRANSPORT, KafkaError._ALL_BROKERS_DOWN):
                    raise self._unavailable(KafkaException(err))
                raise KafkaException(err)
            key = m.key()
            out.append(
                Message(
                    topic=m.topic(),
                    partition=m.partition(),
                    offset=m.offset(),
                    key=key.decode("utf-8") if isinstance(key, bytes) else key,
                    value=m.value() or b"",
                    headers={k: (v or b"").decode("utf-8") for k, v in (m.headers() or [])},
                    timestamp_ms=m.timestamp()[1],
                )
            )
        return out

    def seek(self, topic: str, partition: int, offset: int) -> None:
        self._seeks[(topic, partition)] = offset
        if (topic, partition) in self._assigned:
            self._assigned[(topic, partition)] = offset
            self._reassign()

    def commit(self, offsets: Offsets) -> None:
        from confluent_kafka import KafkaException, TopicPartition

        if not offsets:
            return
        try:
            self._consumer_client().commit(
                offsets=[TopicPartition(t, p, o) for (t, p), o in offsets.items()],
                asynchronous=False,
            )
        except KafkaException as exc:
            raise self._unavailable(exc) from exc

    def committed(self, topic: str) -> Offsets:
        from confluent_kafka import KafkaException, TopicPartition

        md = self._metadata()
        if topic not in md.topics:
            return {}
        tps = [TopicPartition(topic, p) for p in md.topics[topic].partitions]
        try:
            got = self._consumer_client().committed(tps, timeout=self.timeout)
        except KafkaException as exc:
            raise self._unavailable(exc) from exc
        return {(tp.topic, tp.partition): tp.offset for tp in got if tp.offset >= 0}

    def end_offsets(self, topic: str) -> dict[int, int]:
        from confluent_kafka import KafkaException, TopicPartition

        md = self._metadata()
        if topic not in md.topics:
            return {}
        out = {}
        for p in md.topics[topic].partitions:
            try:
                _, high = self._consumer_client().get_watermark_offsets(
                    TopicPartition(topic, p), timeout=self.timeout, cached=False
                )
            except KafkaException as exc:
                raise self._unavailable(exc) from exc
            out[p] = high
        return out

    # ------------------------------------------------ топики

    def list_topics(self) -> dict[str, dict[str, Any]]:
        from confluent_kafka.admin import ConfigResource, ResourceType

        md = self._metadata()
        names = sorted(t for t in md.topics if not t.startswith("__"))
        out: dict[str, dict[str, Any]] = {
            t: {"partitions": len(md.topics[t].partitions), "retention_ms": None} for t in names
        }
        if names:
            futures = self._admin_client().describe_configs(
                [ConfigResource(ResourceType.TOPIC, t) for t in names],
                request_timeout=self.timeout,
            )
            for res, fut in futures.items():
                with contextlib.suppress(Exception):
                    entry = fut.result(timeout=self.timeout).get("retention.ms")
                    if entry is not None and entry.value is not None:
                        out[res.name]["retention_ms"] = int(entry.value)
        return out

    def ensure_topics(self, specs: list[TopicSpec]) -> list[str]:
        from confluent_kafka.admin import NewTopic

        existing = set(self._metadata().topics)
        missing = [s for s in specs if s.name not in existing]
        if not missing:
            return []
        futures = self._admin_client().create_topics(
            [
                NewTopic(
                    s.name,
                    num_partitions=s.partitions,
                    replication_factor=1,
                    config={"retention.ms": str(s.retention_ms)},
                )
                for s in missing
            ],
            request_timeout=self.timeout,
        )
        for fut in futures.values():
            fut.result(timeout=self.timeout)
        return [s.name for s in missing]

    def scan(self, topic: str) -> Iterator[Message]:
        from confluent_kafka import Consumer, TopicPartition

        ends = self.end_offsets(topic)
        reader = Consumer(
            {
                **self._base(),
                # Отдельная одноразовая группа: чтение не трогает позиции потребителя цепочки
                "group.id": f"{self.group}-scan-{os.getpid()}-{time.time_ns()}",
                "enable.auto.commit": False,
                "auto.offset.reset": "earliest",
            }
        )
        try:
            reader.assign([TopicPartition(topic, p, 0) for p, end in ends.items() if end > 0])
            left = {p: end for p, end in ends.items() if end > 0}
            while left:
                batch = reader.consume(1000, self.timeout)
                if not batch:
                    raise self._unavailable(RuntimeError("чтение топика прервалось"))
                for m in batch:
                    if m.error() is not None:
                        continue
                    key = m.key()
                    yield Message(
                        topic=m.topic(),
                        partition=m.partition(),
                        offset=m.offset(),
                        key=key.decode("utf-8") if isinstance(key, bytes) else key,
                        value=m.value() or b"",
                        headers={k: (v or b"").decode("utf-8") for k, v in (m.headers() or [])},
                        timestamp_ms=m.timestamp()[1],
                    )
                    if m.offset() + 1 >= left.get(m.partition(), 0):
                        left.pop(m.partition(), None)
        finally:
            reader.close()

    def close(self) -> None:
        if self._producer is not None:
            self._producer.flush(self.timeout)
            self._producer = None
        if self._consumer is not None:
            with contextlib.suppress(Exception):
                self._consumer.close()
            self._consumer = None


def make_broker(cfg, role: str = "client") -> Broker:
    """Клиент брокера по конфигу потока. Тесты подменяют эту функцию на `MemoryBroker`
    (monkeypatch `mlsiem.stream.broker.make_broker`), поэтому CLI зовёт её через модуль."""
    return KafkaBroker(
        cfg.broker.bootstrap,
        group=cfg.consumer.group,
        connect_timeout_s=cfg.broker.connect_timeout_s,
        vm_name=cfg.stand.vm_name,
        client_id=f"mlsiem-{role}",
    )


def topic_specs(cfg) -> list[TopicSpec]:
    """Топики фичи по конфигу: потоки и отвергнутые (отвергнутых всегда одна партиция)."""
    return [
        TopicSpec(cfg.topics.flows, cfg.topics.partitions, cfg.topics.retention_ms),
        TopicSpec(cfg.topics.rejected, 1, cfg.topics.retention_ms),
    ]
