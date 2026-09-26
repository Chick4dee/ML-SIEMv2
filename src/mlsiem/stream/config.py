"""Чтение и проверка configs/stream.yaml (фича 005, data-model «Конфигурация»).

Как конфиги 001–004, проверяется целиком при запуске и с полным именем ключа в ошибке:
потребитель работает часами, и узнать об опечатке в адресе брокера нужно сразу, а не после
первого тайм-аута. Проверки ключей и типов — общие с 001 (`_get`), поэтому сообщения
выглядят одинаково во всех командах.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from mlsiem.data.config import ConfigError, _get

DEFAULT_STREAM_CONFIG = Path("configs/stream.yaml")


@dataclass(frozen=True)
class BrokerConfig:
    bootstrap: str
    connect_timeout_s: int


@dataclass(frozen=True)
class TopicsConfig:
    flows: str
    rejected: str
    partitions: int
    retention_hours: int

    @property
    def retention_ms(self) -> int:
        return self.retention_hours * 3600 * 1000


@dataclass(frozen=True)
class ConsumerConfig:
    group: str
    batch_max_messages: int
    batch_max_wait_ms: int
    allowed_lateness_ms: int
    lease_ttl_s: int
    stats_interval_s: int
    db_retry_s: int
    report_interval_s: int


@dataclass(frozen=True)
class ReplayConfig:
    default_speed: float | None  # None — «max», без пауз
    progress_interval_s: float


@dataclass(frozen=True)
class StandConfig:
    vm_name: str
    mgmt_switch: str
    lab_switch: str
    host_ip: str
    broker_ip: str
    prefix: int
    memory_mb: int
    cpus: int
    disk_gb: int
    kafka_heap_mb: int
    kafka_version: str
    kafka_sha512: str
    cluster_id: str
    admin_user: str
    mgmt_mac: str
    install_mac: str

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(f"{self.host_ip}/{self.prefix}", strict=False)


@dataclass(frozen=True)
class StreamConfig:
    broker: BrokerConfig
    topics: TopicsConfig
    consumer: ConsumerConfig
    replay: ReplayConfig
    stand: StandConfig
    # Сырой словарь — для журнала и для PowerShell-скриптов (Read-StreamConfig.ps1)
    raw: dict[str, Any]


def _positive(raw: dict, key: str, minimum: int = 1) -> int:
    value = _get(raw, key, int)
    if value < minimum:
        raise ConfigError(f"ключ {key}: нужно целое ≥ {minimum}, а записано {value}")
    return value


def _name(raw: dict, key: str) -> str:
    value = _get(raw, key, str).strip()
    if not value:
        raise ConfigError(f"ключ {key}: нужна непустая строка")
    return value


def parse_speed(value: Any, key: str = "replay.default_speed") -> float | None:
    """Темп проигрывания: число > 0 («реальное время × N») или `max` (без пауз → None)."""
    if isinstance(value, str) and value.strip().lower() == "max":
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        try:
            value = float(str(value))
        except ValueError:
            raise ConfigError(
                f"ключ {key}: ожидалось число > 0 или max, а записано {value!r}"
            ) from None
    if value <= 0:
        raise ConfigError(f"ключ {key}: ускорение должно быть > 0 (или max), а записано {value}")
    return float(value)


def _bootstrap(raw: dict) -> str:
    """`хост:порт[,хост:порт…]` — без порта librdkafka молча подставил бы 9092, а это
    как раз тот случай, когда явное лучше догадки."""
    value = _name(raw, "broker.bootstrap")
    for part in value.split(","):
        host, sep, port = part.strip().rpartition(":")
        if not sep or not host or not port.isdigit() or not 0 < int(port) < 65536:
            raise ConfigError(
                f"ключ broker.bootstrap: {part.strip()!r} — нужен адрес вида хост:порт, "
                "например 10.77.0.10:9092"
            )
    return value


def _ip(raw: dict, key: str) -> str:
    value = _name(raw, key)
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        raise ConfigError(f"ключ {key}: {value!r} — не IPv4-адрес") from None
    return value


def _mac(raw: dict, key: str) -> str:
    """MAC-адрес → `00:15:5d:4d:00:10` (строчные, через двоеточие) — так его ждёт netplan."""
    value = _name(raw, key)
    digits = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(digits) != 12:
        raise ConfigError(f"ключ {key}: {value!r} — не MAC-адрес (нужно 12 шестнадцатеричных цифр)")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2)).lower()


def _parse_stand(raw: dict) -> StandConfig:
    prefix = _get(raw, "stand.prefix", int)
    if not 8 <= prefix <= 30:
        raise ConfigError(f"ключ stand.prefix: длина префикса сети 8–30, а записано {prefix}")
    host_ip, broker_ip = _ip(raw, "stand.host_ip"), _ip(raw, "stand.broker_ip")
    net = ipaddress.ip_network(f"{host_ip}/{prefix}", strict=False)
    if ipaddress.IPv4Address(broker_ip) not in net:
        raise ConfigError(
            f"ключи stand.host_ip и stand.broker_ip: {host_ip} и {broker_ip} не в одной сети "
            f"/{prefix} — хост не увидит брокера в служебной сети"
        )
    if host_ip == broker_ip:
        raise ConfigError("ключи stand.host_ip и stand.broker_ip: адреса хоста и брокера совпадают")
    memory_mb = _positive(raw, "stand.memory_mb")
    if memory_mb < 1024:
        raise ConfigError(
            f"ключ stand.memory_mb: брокерной машине нужно ≥ 1024 МБ (ОС + JVM), а записано "
            f"{memory_mb}"
        )
    heap = _positive(raw, "stand.kafka_heap_mb")
    if heap >= memory_mb:
        raise ConfigError(
            f"ключ stand.kafka_heap_mb: куча Kafka ({heap} МБ) должна быть меньше памяти машины "
            f"stand.memory_mb ({memory_mb} МБ) — иначе ОС нечем жить"
        )
    version = str(_get(raw, "stand.kafka_version", (str, int, float))).strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ConfigError(f"ключ stand.kafka_version: ожидалась версия вида 4.3.1, а {version!r}")
    sha = _name(raw, "stand.kafka_sha512").lower()
    if not re.fullmatch(r"[0-9a-f]{128}", sha):
        raise ConfigError(
            "ключ stand.kafka_sha512: нужна SHA-512 архива Kafka — 128 шестнадцатеричных "
            "символов без пробелов"
        )
    cluster_id = _name(raw, "stand.cluster_id")
    if not re.fullmatch(r"[A-Za-z0-9_-]{22}", cluster_id):
        raise ConfigError(
            "ключ stand.cluster_id: нужен идентификатор кластера Kafka — 22 символа base64url"
        )
    return StandConfig(
        vm_name=_name(raw, "stand.vm_name"),
        mgmt_switch=_name(raw, "stand.mgmt_switch"),
        lab_switch=_name(raw, "stand.lab_switch"),
        host_ip=host_ip,
        broker_ip=broker_ip,
        prefix=prefix,
        memory_mb=memory_mb,
        cpus=_positive(raw, "stand.cpus"),
        disk_gb=_positive(raw, "stand.disk_gb"),
        kafka_heap_mb=heap,
        kafka_version=version,
        kafka_sha512=sha,
        cluster_id=cluster_id,
        admin_user=_name(raw, "stand.admin_user"),
        mgmt_mac=_mac(raw, "stand.mgmt_mac"),
        install_mac=_mac(raw, "stand.install_mac"),
    )


def parse_stream_config(raw: Any) -> StreamConfig:
    """Проверяет уже прочитанный словарь конфига (удобно для тестов без файла)."""
    if not isinstance(raw, dict):
        raise ConfigError("конфиг потока: ожидался словарь верхнего уровня")

    broker = BrokerConfig(
        bootstrap=_bootstrap(raw),
        connect_timeout_s=_positive(raw, "broker.connect_timeout_s"),
    )
    topics = TopicsConfig(
        flows=_name(raw, "topics.flows"),
        rejected=_name(raw, "topics.rejected"),
        partitions=_positive(raw, "topics.partitions"),
        retention_hours=_positive(raw, "topics.retention_hours"),
    )
    if topics.flows == topics.rejected:
        raise ConfigError("ключи topics.flows и topics.rejected: топики должны различаться")

    lateness = _get(raw, "consumer.allowed_lateness_ms", int)
    if lateness < 0:
        raise ConfigError(
            f"ключ consumer.allowed_lateness_ms: опоздание не может быть отрицательным ({lateness})"
        )
    ttl = _get(raw, "consumer.lease_ttl_s", int)
    if ttl <= 5:
        # Аренда продлевается каждые ttl/6 секунд; при ttl ≤ 5 это чаще раза в секунду, и
        # любая пачка подольше «теряла» бы аренду посреди обработки
        raise ConfigError(f"ключ consumer.lease_ttl_s: нужно больше 5 секунд, а записано {ttl}")
    consumer = ConsumerConfig(
        group=_name(raw, "consumer.group"),
        batch_max_messages=_positive(raw, "consumer.batch_max_messages"),
        batch_max_wait_ms=_positive(raw, "consumer.batch_max_wait_ms"),
        allowed_lateness_ms=lateness,
        lease_ttl_s=ttl,
        stats_interval_s=_positive(raw, "consumer.stats_interval_s"),
        db_retry_s=_positive(raw, "consumer.db_retry_s"),
        report_interval_s=_positive(raw, "consumer.report_interval_s"),
    )

    speed_raw = _get(raw, "replay.default_speed", (int, float, str))
    progress = _get(raw, "replay.progress_interval_s", (int, float))
    if progress <= 0:
        raise ConfigError(f"ключ replay.progress_interval_s: нужно > 0, а записано {progress}")
    replay = ReplayConfig(default_speed=parse_speed(speed_raw), progress_interval_s=float(progress))

    return StreamConfig(
        broker=broker,
        topics=topics,
        consumer=consumer,
        replay=replay,
        stand=_parse_stand(raw),
        raw=raw,
    )


def load_stream_config(path: str | Path = DEFAULT_STREAM_CONFIG) -> StreamConfig:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"не найден файл конфига {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: не читается как YAML: {exc}") from exc
    return parse_stream_config(raw)
