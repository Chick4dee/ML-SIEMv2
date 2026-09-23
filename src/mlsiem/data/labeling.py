"""Сопоставление потоков nfstream с записями разметки (ground truth) датасета.

Авторы датасетов резали трафик на потоки своим инструментом (Argus), а мы — nfstream,
и границы потоков не совпадают. Поэтому метки переносятся «по смыслу»:

- совпадает 5-кортеж (IP и порты обеих сторон + протокол) в любой ориентации — кто
  клиент, а кто сервер, два инструмента могут решить по-разному;
- у протоколов без портов (ICMP, OSPF, GRE…) сравниваем только IP и протокол: nfstream
  пишет им порты 0, а Argus кладёт в «порт» тип/код ICMP, и сравнение портов дало бы промах;
- время: расстояние от начала нашего потока до ИНТЕРВАЛА записи [start, end] (0, если
  начало внутри), с допуском 60 с. Именно интервал, а не начало к началу: nfstream режет
  длинные потоки по active_timeout, и старты их кусков оказываются на полчаса позже записи;
- если кандидатов несколько — берём ближайший по времени, при равенстве — с более ранним
  началом записи, дальше — по метке по алфавиту. Так результат не зависит от порядка строк
  в файле разметки.

Алгоритм перенесён из v1 (там он проверен на всех захватах), код написан заново.
"""

from __future__ import annotations

import polars as pl

TOLERANCE_MS = 60_000

# Колонки нормализованной таблицы разметки, которую готовят sources/unsw.py и sources/ctu13.py
GT_COLUMNS = [
    "gt_start_ms",
    "gt_end_ms",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "label_raw",
    "label_detail",
    "label",
]

# Протоколы, у которых порты настоящие
PORTED_PROTOCOLS = (6, 17)

# Имена протоколов в файлах разметки (нотация Argus) → номер IANA. Argus называет протоколы
# по старым ключевым словам IANA, поэтому таблица длинная: в GT UNSW-NB15 их 129 — генератор
# атак перебирал почти все номера. В v1 таблица была из четырёх строк, и атаки по
# экзотическим протоколам молча становились benign.
# rtp/rtcp/udt — это Argus распознал приложение поверх UDP, на уровне IP это UDP (17).
# Не сопоставляются намеренно: `unas` (unassigned), `any`, `ip`, `ib`, `sccopmce` — однозначного
# номера у них нет; arp/rarp/llc/ipx/spx — не IP вовсе, nfstream их не видит.
PROTO_NUMBERS = {
    "icmp": 1,
    "igmp": 2,
    "ggp": 3,
    "ipnip": 4,
    "st2": 5,
    "tcp": 6,
    "cbt": 7,
    "egp": 8,
    "igp": 9,
    "bbn-rcc": 10,
    "nvp": 11,
    "pup": 12,
    "argus": 13,
    "emcon": 14,
    "xnet": 15,
    "chaos": 16,
    "udp": 17,
    "mux": 18,
    "dcn": 19,
    "hmp": 20,
    "prm": 21,
    "xns-idp": 22,
    "trunk-1": 23,
    "trunk-2": 24,
    "leaf-1": 25,
    "leaf-2": 26,
    "rdp": 27,
    "irtp": 28,
    "iso-tp4": 29,
    "netblt": 30,
    "mfe-nsp": 31,
    "merit-inp": 32,
    "sep": 33,
    "3pc": 34,
    "idpr": 35,
    "xtp": 36,
    "ddp": 37,
    "idpr-cmtp": 38,
    "tp++": 39,
    "il": 40,
    "ipv6": 41,
    "sdrp": 42,
    "ipv6-route": 43,
    "ipv6-frag": 44,
    "idrp": 45,
    "rsvp": 46,
    "gre": 47,
    "mhrp": 48,
    "bna": 49,
    "esp": 50,
    "ah": 51,
    "i-nlsp": 52,
    "swipe": 53,
    "narp": 54,
    "mobile": 55,
    "tlsp": 56,
    "skip": 57,
    "ipv6-icmp": 58,
    "ipv6-no": 59,
    "ipv6-opts": 60,
    "cftp": 62,
    "sat-expak": 64,
    "kryptolan": 65,
    "rvd": 66,
    "ippc": 67,
    "sat-mon": 69,
    "visa": 70,
    "ipcv": 71,
    "cpnx": 72,
    "cphb": 73,
    "wsn": 74,
    "pvp": 75,
    "br-sat-mon": 76,
    "sun-nd": 77,
    "wb-mon": 78,
    "wb-expak": 79,
    "iso-ip": 80,
    "vmtp": 81,
    "secure-vmtp": 82,
    "vines": 83,
    "ttp": 84,
    "nsfnet-igp": 85,
    "dgp": 86,
    "tcf": 87,
    "eigrp": 88,
    "ospf": 89,
    "sprite-rpc": 90,
    "larp": 91,
    "mtp": 92,
    "ax.25": 93,
    "ipip": 94,
    "micp": 95,
    "etherip": 97,
    "encap": 98,
    "pri-enc": 99,
    "gmtp": 100,
    "ifmp": 101,
    "pnni": 102,
    "pim": 103,
    "aris": 104,
    "scps": 105,
    "qnx": 106,
    "a/n": 107,
    "ipcomp": 108,
    "snp": 109,
    "compaq-peer": 110,
    "ipx-n-ip": 111,
    "vrrp": 112,
    "pgm": 113,
    "zero": 114,
    "l2tp": 115,
    "ddx": 116,
    "iatp": 117,
    "stp": 118,
    "srp": 119,
    "uti": 120,
    "smp": 121,
    "sm": 122,
    "ptp": 123,
    "isis": 124,
    "fire": 125,
    "crtp": 126,
    "crudp": 127,
    "iplt": 129,
    "sps": 130,
    "pipe": 131,
    "sctp": 132,
    "fc": 133,
    "rtp": 17,
    "rtcp": 17,
    "udt": 17,
}


def protocol_number(col: str) -> pl.Expr:
    """Имя протокола из файла разметки → номер IANA (неизвестное → null, не сопоставится)."""
    return (
        pl.col(col)
        .str.strip_chars()
        .str.to_lowercase()
        .replace_strict(PROTO_NUMBERS, default=None, return_dtype=pl.Int64)
    )


def _candidates(flows: pl.DataFrame, gt: pl.DataFrame, keys: list[str]) -> pl.DataFrame:
    """Все пары «поток — запись» с совпадающими ключами и расстоянием по времени ≤ допуска."""
    t = pl.col("bidirectional_first_seen_ms")
    return (
        flows.join(gt, on=keys, how="inner")
        .with_columns(
            pl.max_horizontal(
                pl.col("gt_start_ms") - t, t - pl.col("gt_end_ms"), pl.lit(0, pl.Int64)
            ).alias("_dt_ms")
        )
        .filter(pl.col("_dt_ms") <= TOLERANCE_MS)
        .select("_row", "_dt_ms", "gt_start_ms", "label", "label_detail", "label_raw")
    )


def label_flows(flows: pl.DataFrame, gt: pl.DataFrame, *, default_label: str) -> pl.DataFrame:
    """Добавляет к потокам колонки label_raw, label_detail, label.

    Несопоставленные потоки получают `default_label` (UNSW — benign, CTU-13 — unlabeled),
    а label_raw/label_detail у них пустые — так видно, что метка поставлена по умолчанию.
    """
    gt = gt.select(GT_COLUMNS)
    if flows.height and gt.height:
        # Разметку заранее режем по времени захвата: в GT UNSW 174 тыс. записей на два дня,
        # а одному PCAP нужна малая их часть — join становится в разы меньше
        lo = flows["bidirectional_first_seen_ms"].min() - TOLERANCE_MS
        hi = flows["bidirectional_first_seen_ms"].max() + TOLERANCE_MS
        gt = gt.filter((pl.col("gt_end_ms") >= lo) & (pl.col("gt_start_ms") <= hi))

    # Обе ориентации записи: меняем местами стороны и склеиваем
    swapped = gt.rename(
        {
            "src_ip": "dst_ip",
            "dst_ip": "src_ip",
            "src_port": "dst_port",
            "dst_port": "src_port",
        }
    ).select(GT_COLUMNS)
    gt_both = pl.concat([gt, swapped]).unique(maintain_order=True)

    indexed = flows.with_row_index("_row")
    key_cols = [
        "_row",
        "bidirectional_first_seen_ms",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
    ]
    ported = pl.col("protocol").is_in(PORTED_PROTOCOLS)
    candidates = pl.concat(
        [
            _candidates(
                indexed.filter(ported).select(key_cols),
                gt_both.filter(ported),
                ["src_ip", "src_port", "dst_ip", "dst_port", "protocol"],
            ),
            _candidates(
                indexed.filter(~ported).select(key_cols).drop("src_port", "dst_port"),
                gt_both.filter(~ported).drop("src_port", "dst_port"),
                ["src_ip", "dst_ip", "protocol"],
            ),
        ]
    )
    best = (
        candidates.sort(
            ["_row", "_dt_ms", "gt_start_ms", "label", "label_detail", "label_raw"],
            nulls_last=True,
        )
        .unique(subset="_row", keep="first", maintain_order=True)
        .select("_row", "label_raw", "label_detail", "label")
    )
    return (
        indexed.join(best, on="_row", how="left")
        .sort("_row")
        .drop("_row")
        .with_columns(pl.col("label").fill_null(default_label))
    )
