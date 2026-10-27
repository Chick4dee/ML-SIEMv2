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
class VictimConfig:
    vm: str
    ip: str
    services: tuple[str, ...]
    ssh_user: str
    ssh_password: str
    memory_mb: int
    cpus: int
    disk_gb: int


@dataclass(frozen=True)
class AttackerConfig:
    vm: str
    ip: str
    mgmt: str
    memory_mb: int
    cpus: int
    disk_gb: int


@dataclass(frozen=True)
class SensorConfig:
    placement: str
    vm: str
    iface: str
    source_id: str
    buffer_flows: int
    pcap_limit_gb: float
    report_interval_s: float
    liveness_s: float
    extra_memory_mb: int


@dataclass(frozen=True)
class LabConfig:
    """Раздел `lab` (фича 006, data-model «Машины стенда»)."""

    subnet: ipaddress.IPv4Network
    victim: VictimConfig
    attacker: AttackerConfig
    sensor: SensorConfig
    clock_skew_max_s: float
    host_free_gb_min: float
    lab_mac: dict[str, str]

    def in_lab(self, ip: str) -> bool:
        """Адрес внутри сети стенда? Для проверки целей сценариев (FR-013)."""
        try:
            return ipaddress.ip_address(ip) in self.subnet
        except ValueError:
            return False


@dataclass(frozen=True)
class NormalConfig:
    """Раздел `normal`: фоновая норма (R14)."""

    period_s: float
    mix: dict[str, int]
    step_timeout_s: float


@dataclass(frozen=True)
class ScenarioConfig:
    """Запись раздела `scenarios` (R11). `pcap`/`src_map`/`dst_map` — только у контрольного."""

    name: str
    version: str
    tool: str
    args: str
    target: str
    expected_class: str
    rate_limit: str
    duration_limit_s: int
    catch_threshold: float
    pcap: str | None = None
    src_map: str | None = None
    dst_map: str | None = None


@dataclass(frozen=True)
class StreamConfig:
    broker: BrokerConfig
    topics: TopicsConfig
    consumer: ConsumerConfig
    replay: ReplayConfig
    stand: StandConfig
    # Сырой словарь — для журнала и для PowerShell-скриптов (Read-StreamConfig.ps1)
    raw: dict[str, Any]
    # Фича 006: None — конфиг без раздела `lab` (как до 006), команды стенда 005 работают
    lab: LabConfig | None = None
    normal: NormalConfig | None = None
    scenarios: tuple[ScenarioConfig, ...] = ()

    def scenario(self, name: str, version: str | None = None) -> ScenarioConfig:
        """Сценарий по имени (и версии, если задана) или ConfigError с перечнем имён."""
        for sc in self.scenarios:
            if sc.name == name and (version is None or sc.version == version):
                return sc
        known = ", ".join(f"{sc.name}@{sc.version}" for sc in self.scenarios) or "нет"
        raise ConfigError(f"сценарий {name}{'@' + version if version else ''} не найден: {known}")


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


SERVICES = ("web", "ssh", "ftp", "dns")
SENSOR_PLACEMENTS = ("broker", "vm")
MGMT_CHANNELS = ("powershell-direct", "com")
# Порты служб жертвы: нужны, чтобы подставить {port} в аргументы сценариев (R4)
SERVICE_PORTS = {"web": 80, "ssh": 22, "ftp": 21, "dns": 53}


def _positive_number(raw: dict, key: str) -> float:
    value = float(_get(raw, key, (int, float)))
    if value <= 0:
        raise ConfigError(f"ключ {key}: нужно число > 0, а записано {value}")
    return value


def _parse_lab(raw: dict) -> LabConfig:
    subnet_text = _name(raw, "lab.subnet")
    try:
        subnet = ipaddress.ip_network(subnet_text, strict=True)
    except ValueError:
        raise ConfigError(
            f"ключ lab.subnet: {subnet_text!r} — не сеть IPv4 вида 10.88.0.0/24"
        ) from None
    if not isinstance(subnet, ipaddress.IPv4Network):
        raise ConfigError(f"ключ lab.subnet: нужна сеть IPv4, а записано {subnet_text!r}")

    victim_ip, attacker_ip = _ip(raw, "lab.victim.ip"), _ip(raw, "lab.attacker.ip")
    for key, ip in (("lab.victim.ip", victim_ip), ("lab.attacker.ip", attacker_ip)):
        if ipaddress.IPv4Address(ip) not in subnet:
            raise ConfigError(f"ключ {key}: адрес {ip} не в подсети стенда {subnet}")
    if victim_ip == attacker_ip:
        raise ConfigError(
            "ключи lab.victim.ip и lab.attacker.ip: адреса жертвы и атакующего совпадают"
        )
    # Служебная сеть 005 и сеть стенда не должны пересекаться: иначе изоляция (FR-005) мнимая
    stand_net = ipaddress.ip_network(
        f"{_ip(raw, 'stand.host_ip')}/{_get(raw, 'stand.prefix', int)}", strict=False
    )
    if stand_net.overlaps(subnet):
        raise ConfigError(
            f"ключ lab.subnet: сеть стенда {subnet} пересекается со служебной сетью {stand_net}"
        )

    services = _get(raw, "lab.victim.services", list)
    bad = [x for x in services if x not in SERVICES]
    if not services or bad:
        raise ConfigError(
            f"ключ lab.victim.services: допустимы {list(SERVICES)}, а записано {services!r}"
        )
    victim = VictimConfig(
        vm=_name(raw, "lab.victim.vm"),
        ip=victim_ip,
        services=tuple(services),
        ssh_user=_name(raw, "lab.victim.ssh_user"),
        ssh_password=_name(raw, "lab.victim.ssh_password"),
        memory_mb=_positive(raw, "lab.victim.memory_mb", 512),
        cpus=_positive(raw, "lab.victim.cpus"),
        disk_gb=_positive(raw, "lab.victim.disk_gb"),
    )
    mgmt = _name(raw, "lab.attacker.mgmt")
    if mgmt not in MGMT_CHANNELS:
        raise ConfigError(f"ключ lab.attacker.mgmt: допустимы {list(MGMT_CHANNELS)}, а {mgmt!r}")
    attacker = AttackerConfig(
        vm=_name(raw, "lab.attacker.vm"),
        ip=attacker_ip,
        mgmt=mgmt,
        memory_mb=_positive(raw, "lab.attacker.memory_mb", 512),
        cpus=_positive(raw, "lab.attacker.cpus"),
        disk_gb=_positive(raw, "lab.attacker.disk_gb"),
    )
    placement = _name(raw, "lab.sensor.placement")
    if placement not in SENSOR_PLACEMENTS:
        raise ConfigError(
            f"ключ lab.sensor.placement: допустимы {list(SENSOR_PLACEMENTS)}, а {placement!r}"
        )
    sensor = SensorConfig(
        placement=placement,
        vm=_name(raw, "lab.sensor.vm"),
        iface=_name(raw, "lab.sensor.iface"),
        source_id=_name(raw, "lab.sensor.source_id"),
        buffer_flows=_positive(raw, "lab.sensor.buffer_flows"),
        pcap_limit_gb=_positive_number(raw, "lab.sensor.pcap_limit_gb"),
        report_interval_s=_positive_number(raw, "lab.sensor.report_interval_s"),
        liveness_s=_positive_number(raw, "lab.sensor.liveness_s"),
        extra_memory_mb=_positive(raw, "lab.sensor.extra_memory_mb", 0),
    )
    macs = {k: _mac(raw, f"lab.lab_mac.{k}") for k in _get(raw, "lab.lab_mac", dict)}
    for need in ("victim", "attacker", "sensor"):
        if need not in macs:
            raise ConfigError(f"в конфиге нет ключа lab.lab_mac.{need}")
    if len(set(macs.values())) != len(macs):
        raise ConfigError("ключи lab.lab_mac.*: MAC-адреса должны различаться")
    return LabConfig(
        subnet=subnet,
        victim=victim,
        attacker=attacker,
        sensor=sensor,
        clock_skew_max_s=_positive_number(raw, "lab.clock_skew_max_s"),
        host_free_gb_min=_positive_number(raw, "lab.host_free_gb_min"),
        lab_mac=macs,
    )


def _parse_normal(raw: dict, lab: LabConfig) -> NormalConfig:
    mix: dict[str, int] = {}
    for svc in _get(raw, "normal.mix", dict):
        if svc not in SERVICES:
            raise ConfigError(f"ключ normal.mix.{svc}: допустимы службы {list(SERVICES)}")
        if svc not in lab.victim.services:
            raise ConfigError(
                f"ключ normal.mix.{svc}: у жертвы нет службы {svc} (lab.victim.services)"
            )
        mix[svc] = _positive(raw, f"normal.mix.{svc}", 0)
    if not any(mix.values()):
        raise ConfigError("ключ normal.mix: нужна хотя бы одна служба с весом > 0")
    return NormalConfig(
        period_s=_positive_number(raw, "normal.period_s"),
        mix=mix,
        step_timeout_s=_positive_number(raw, "normal.step_timeout_s"),
    )


def _check_variants(variants: Any, parent: dict, where: str) -> None:
    """Варианты сценария версии 2 (008): имена уникальны, у каждого есть инструмент и аргументы
    (свои или родителя), домены параметров — непустые списки, а holdout входит в values."""
    if not isinstance(variants, list) or not variants:
        raise ConfigError(f"ключ {where}.variants: нужен непустой список вариантов")
    seen: set[str] = set()
    for j, v in enumerate(variants):
        w = f"{where}.variants[{j}]"
        if not isinstance(v, dict) or not str(v.get("name", "")).strip():
            raise ConfigError(f"ключ {w}: нужен словарь с непустым name")
        if v["name"] in seen:
            raise ConfigError(f"ключ {w}: вариант {v['name']!r} записан дважды")
        seen.add(v["name"])
        for key in ("tool", "args"):
            if not isinstance(v.get(key, parent.get(key)), str):
                raise ConfigError(f"ключ {w}.{key}: нужна строка (у варианта или у сценария)")
        bind = v.get("source_bind")
        if bind is not None and not (
            bind == "route" or (isinstance(bind, str) and bind.startswith("flag "))
        ):
            raise ConfigError(
                f"ключ {w}.source_bind: допустимо route или 'flag <аргументы>', а записано {bind!r}"
            )
        for pname, dom in (v.get("params") or {}).items():
            values = dom.get("values") if isinstance(dom, dict) else None
            if not isinstance(values, list) or not values:
                raise ConfigError(f"ключ {w}.params.{pname}.values: нужен непустой список")
            hold = dom.get("holdout") or []
            if not set(map(str, hold)) <= set(map(str, values)):
                raise ConfigError(
                    f"ключ {w}.params.{pname}.holdout: значения должны входить в values"
                )
            if len(hold) >= len(values):
                raise ConfigError(
                    f"ключ {w}.params.{pname}.holdout: holdout не может занимать все значения"
                )


def _check_sources(raw: dict, lab: LabConfig) -> None:
    """`lab.sources` (008): имена и адреса уникальны, адреса в сети стенда, не совпадают с "
    "жертвой."""
    items = (raw.get("lab") or {}).get("sources")
    if items is None:
        return
    if not isinstance(items, list) or not items:
        raise ConfigError("ключ lab.sources: нужен непустой список источников")
    names, ips = set(), set()
    for i, src in enumerate(items):
        w = f"lab.sources[{i}]"
        if not isinstance(src, dict) or not src.get("name") or not src.get("ip"):
            raise ConfigError(f"ключ {w}: нужны name и ip")
        if src["name"] in names or src["ip"] in ips:
            raise ConfigError(f"ключ {w}: имя или адрес источника повторяется")
        if not lab.in_lab(str(src["ip"])):
            raise ConfigError(f"ключ {w}.ip: адрес {src['ip']} не в сети стенда {lab.subnet}")
        if str(src["ip"]) == lab.victim.ip:
            raise ConfigError(f"ключ {w}.ip: адрес источника совпадает с жертвой")
        if src.get("role", "attacker") not in ("attacker", "client"):
            raise ConfigError(f"ключ {w}.role: допустимы attacker и client")
        names.add(src["name"])
        ips.add(src["ip"])


def _parse_scenarios(raw: dict, lab: LabConfig) -> tuple[ScenarioConfig, ...]:
    from mlsiem.data.taxonomy import CANONICAL

    out: list[ScenarioConfig] = []
    seen: set[tuple[str, str]] = set()
    for i, item in enumerate(_get(raw, "scenarios", list)):
        where = f"scenarios[{i}]"
        if not isinstance(item, dict):
            raise ConfigError(f"ключ {where}: ожидался словарь, а записано {item!r}")

        def get(key: str, kind, _item=item, _where=where):
            # _get идёт по пути из точек; оборачиваем запись, чтобы в сообщении был индекс
            try:
                return _get({"s": _item}, f"s.{key}", kind)
            except ConfigError as exc:
                raise ConfigError(str(exc).replace(f"s.{key}", f"{_where}.{key}")) from None

        name = get("name", str).strip()
        version = str(get("version", (str, int))).strip()
        if not name or not version:
            raise ConfigError(f"ключ {where}: нужны непустые name и version")
        if (name, version) in seen:
            raise ConfigError(f"ключ {where}: сценарий {name}@{version} записан дважды")
        seen.add((name, version))
        target = get("target", str)
        if target not in lab.victim.services:
            raise ConfigError(f"ключ {where}.target: у жертвы нет службы {target!r}")
        expected = get("expected_class", str)
        hard = bool(item.get("hard"))
        if hard and expected != "benign":
            raise ConfigError(f"ключ {where}.expected_class: у сложной нормы (hard) нужен benign")
        if (
            expected != "out_of_taxonomy"
            and expected not in CANONICAL
            and not (hard and expected == "benign")
        ):
            raise ConfigError(
                f"ключ {where}.expected_class: {expected!r} — не класс таксономии и не "
                "out_of_taxonomy"
            )
        threshold = float(get("catch_threshold", (int, float)))
        if not 0 < threshold <= 1:
            raise ConfigError(f"ключ {where}.catch_threshold: нужно число в (0, 1], а {threshold}")
        duration = get("duration_limit_s", int)
        if duration < 1:
            raise ConfigError(f"ключ {where}.duration_limit_s: нужно целое ≥ 1, а {duration}")
        if name == "control_replay" or item.get("pcap") is not None:
            for key in ("pcap", "src_map", "dst_map"):
                if not isinstance(item.get(key), str) or not item[key].strip():
                    raise ConfigError(f"ключ {where}.{key}: у контрольного сценария нужна строка")
        variants = item.get("variants")
        if variants is not None:
            _check_variants(variants, item, where)
        out.append(
            ScenarioConfig(
                name=name,
                version=version,
                tool=item["tool"]
                if "tool" in item
                else (get("tool", str) if variants is None else "(варианты)"),
                args=item["args"]
                if "args" in item
                else (get("args", str) if variants is None else "-"),
                target=target,
                expected_class=expected,
                rate_limit=str(
                    item.get("rate_limit", "см. варианты")
                    if variants is not None
                    else get("rate_limit", (str, int, float))
                ),
                duration_limit_s=duration,
                catch_threshold=threshold,
                pcap=item.get("pcap"),
                src_map=item.get("src_map"),
                dst_map=item.get("dst_map"),
            )
        )
    return tuple(out)


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

    stand = _parse_stand(raw)
    # Фича 006: разделы стенда необязательны — конфиг без `lab` работает, как до 006
    lab = normal = None
    scenarios: tuple[ScenarioConfig, ...] = ()
    if "lab" in raw:
        lab = _parse_lab(raw)
        _check_sources(raw, lab)
        normal = _parse_normal(raw, lab) if "normal" in raw else None
        scenarios = _parse_scenarios(raw, lab) if "scenarios" in raw else ()
    return StreamConfig(
        broker=broker,
        topics=topics,
        consumer=consumer,
        replay=replay,
        stand=stand,
        raw=raw,
        lab=lab,
        normal=normal,
        scenarios=scenarios,
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
