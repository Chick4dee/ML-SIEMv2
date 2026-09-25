"""Кто атакует: атакующая сторона потока по данным самого потока (фича 004, research R8, FR-023).

Проблема из 002/003. nfstream записывает поток «от того, чей пакет увидел первым». Если
первым попался ответ сервера (начало сессии выпало из захвата или пакеты пришли не по
порядку), то поток выглядит как «жертва 149.171.126.17:80 → атакующий 175.45.176.0», и
группировка по src_ip заводила инцидент «атака с адреса жертвы».

Решение — смотреть на сам поток, правила по порядку, срабатывает первое:
1. `tcp_syn` — TCP, у стороны src нет ни одного SYN, а у dst есть: соединение открывала
   сторона dst, поток записан «от ответчика» → ПЕРЕВЁРНУТ;
2. `tcp_syn_src` — TCP, у src есть SYN: инициатор — src → прямой (даже если порт src < 1024);
3. `service_port` — порт src «сервисный» (< 1024), а порт dst — нет: сервис отвечает на
   эфемерный порт клиента → ПЕРЕВЁРНУТ;
4. `default` — иначе прямой, как в 002.

Для перевёрнутого потока атакующий — dst, жертва — src; исходные src_*/dst_* потока при
этом нигде не меняются, меняется только то, кого группировка считает атакующим.

ВАЖНО (FR-023). Правило не знает ни сетей UNSW-NB15 (где жертвы, где фон), ни меток потоков:
иначе мы бы «подсказали» ему правильный ответ, и на стенде с другими адресами оно бы
сломалось. Поэтому модуль не импортирует конфиг SOC, метки подозрительных источников и
разбор источников, и не читает колонку `label` — тест проверяет это по исходному коду.
"""

from __future__ import annotations

import polars as pl

# Порты ниже этого — «сервисные» (well-known, IANA): на них слушают серверы, а клиенты
# получают эфемерные порты от 1024 и выше. Этого достаточно для запасного правила: точный
# список сервисов для него не нужен
SERVICE_PORT_BELOW = 1024
TCP = 6

# Поля потока, которые нужны правилу (все — из схемы 001, есть и в датасете, и в PCAP)
DIRECTION_COLUMNS = (
    "flow_uid",
    "protocol",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "src2dst_syn_packets",
    "dst2src_syn_packets",
)

RULE_TITLES = {
    "tcp_syn": "TCP: SYN только у второй стороны — соединение открывала она",
    "tcp_syn_src": "TCP: SYN у первой стороны — она инициатор",
    "service_port": "сервисный порт (< 1024) отвечает на эфемерный порт клиента",
    "default": "признаков ответного потока нет",
    "as_is": "направление не определялось (grouping.direction = as_is)",
}


def attacker_side(flows: pl.DataFrame) -> pl.DataFrame:
    """Для каждого потока: flow_uid, reversed, direction_rule, attacker_ip, victim_ip.

    Векторно на polars — сотни тысяч потоков за доли секунды. Пропуски (у ICMP нет портов,
    у UDP — флагов) считаются нулями: такие потоки просто не подходят под TCP-правила.
    """
    missing = [c for c in DIRECTION_COLUMNS if c not in flows.columns]
    if missing:
        raise ValueError(f"для определения атакующей стороны во входе нет полей потока: {missing}")
    tcp = pl.col("protocol").fill_null(0) == TCP
    s2d_syn = pl.col("src2dst_syn_packets").fill_null(0)
    d2s_syn = pl.col("dst2src_syn_packets").fill_null(0)
    sport = pl.col("src_port").fill_null(-1)
    dport = pl.col("dst_port").fill_null(-1)
    rule = (
        pl.when(tcp & (s2d_syn == 0) & (d2s_syn > 0))
        .then(pl.lit("tcp_syn"))
        .when(tcp & (s2d_syn > 0))
        .then(pl.lit("tcp_syn_src"))
        .when((sport >= 0) & (sport < SERVICE_PORT_BELOW) & (dport >= SERVICE_PORT_BELOW))
        .then(pl.lit("service_port"))
        .otherwise(pl.lit("default"))
    )
    out = flows.select("flow_uid", "src_ip", "dst_ip", rule.alias("direction_rule"))
    reversed_ = pl.col("direction_rule").is_in(["tcp_syn", "service_port"])
    return out.select(
        "flow_uid",
        reversed_.alias("reversed"),
        "direction_rule",
        pl.when(reversed_).then(pl.col("dst_ip")).otherwise(pl.col("src_ip")).alias("attacker_ip"),
        pl.when(reversed_).then(pl.col("src_ip")).otherwise(pl.col("dst_ip")).alias("victim_ip"),
    )


def as_is(flows: pl.DataFrame) -> pl.DataFrame:
    """Поведение 002: атакующий — src_ip, ничего не переворачивается (режим `as_is`)."""
    return flows.select(
        "flow_uid",
        pl.lit(False).alias("reversed"),
        pl.lit("as_is").alias("direction_rule"),
        pl.col("src_ip").alias("attacker_ip"),
        pl.col("dst_ip").alias("victim_ip"),
    )


def sides(flows: pl.DataFrame, mode: str) -> pl.DataFrame:
    """Атакующая сторона по режиму `grouping.direction`: `auto` — правило, `as_is` — как в 002."""
    if mode == "auto":
        return attacker_side(flows)
    if mode == "as_is":
        return as_is(flows)
    raise ValueError(f"grouping.direction: ожидалось auto или as_is, а передано {mode!r}")
