"""Тесты сопоставления потоков с разметкой на синтетических таблицах."""

import polars as pl

from mlsiem.data.labeling import GT_COLUMNS, label_flows

T0 = 1_000_000_000


def _flows(rows):
    """rows: (start_ms, src_ip, src_port, dst_ip, dst_port, protocol)."""
    return pl.DataFrame(
        rows,
        schema={
            "bidirectional_first_seen_ms": pl.Int64,
            "src_ip": pl.String,
            "src_port": pl.Int64,
            "dst_ip": pl.String,
            "dst_port": pl.Int64,
            "protocol": pl.Int64,
        },
        orient="row",
    )


def _gt(rows):
    """rows: (start, end, src_ip, src_port, dst_ip, dst_port, protocol, label)."""
    return pl.DataFrame(
        [(*r, r[-1].upper(), f"detail-{r[-1]}-{r[0]}") for r in rows],
        schema={
            "gt_start_ms": pl.Int64,
            "gt_end_ms": pl.Int64,
            "src_ip": pl.String,
            "src_port": pl.Int64,
            "dst_ip": pl.String,
            "dst_port": pl.Int64,
            "protocol": pl.Int64,
            "label": pl.String,
            "label_raw": pl.String,
            "label_detail": pl.String,
        },
        orient="row",
    ).select(GT_COLUMNS)


def _labels(flows, gt, default="benign"):
    return label_flows(flows, gt, default_label=default)["label"].to_list()


def test_five_tuple_both_orientations():
    flows = _flows(
        [
            (T0, "1.1.1.1", 1000, "2.2.2.2", 80, 6),  # прямая ориентация
            (T0, "2.2.2.2", 80, "1.1.1.1", 1000, 6),  # обратная
            (T0, "1.1.1.1", 1001, "2.2.2.2", 80, 6),  # другой порт — нет пары
        ]
    )
    gt = _gt([(T0, T0 + 1000, "1.1.1.1", 1000, "2.2.2.2", 80, 6, "exploits")])
    out = label_flows(flows, gt, default_label="benign")
    assert out["label"].to_list() == ["exploits", "exploits", "benign"]
    assert out["label_raw"].to_list() == ["EXPLOITS", "EXPLOITS", None]


def test_icmp_matches_by_three_tuple():
    # у nfstream порты ICMP нулевые, а в разметке там тип/код — порты игнорируются
    flows = _flows([(T0, "1.1.1.1", 0, "2.2.2.2", 0, 1)])
    gt = _gt([(T0, T0, "2.2.2.2", 771, "1.1.1.1", 3, 1, "dos")])
    assert _labels(flows, gt) == ["dos"]


def test_time_tolerance_after_interval_end():
    gt = _gt([(T0, T0 + 10_000, "1.1.1.1", 1, "2.2.2.2", 2, 6, "dos")])
    flows = _flows(
        [
            (T0 + 5_000, "1.1.1.1", 1, "2.2.2.2", 2, 6),  # внутри интервала
            (T0 + 10_000 + 60_000, "1.1.1.1", 1, "2.2.2.2", 2, 6),  # ровно 60 с после конца
            (T0 + 10_000 + 61_000, "1.1.1.1", 1, "2.2.2.2", 2, 6),  # 61 с — уже нет
            (T0 - 61_000, "1.1.1.1", 1, "2.2.2.2", 2, 6),  # 61 с до начала — нет
        ]
    )
    assert _labels(flows, gt) == ["dos", "dos", "benign", "benign"]


def test_nearest_then_earlier_start_then_label():
    flows = _flows([(T0 + 50_000, "1.1.1.1", 1, "2.2.2.2", 2, 6)])
    # ближайшая по времени запись побеждает
    gt = _gt(
        [
            (T0, T0 + 1_000, "1.1.1.1", 1, "2.2.2.2", 2, 6, "dos"),  # 49 с
            (T0 + 45_000, T0 + 46_000, "1.1.1.1", 1, "2.2.2.2", 2, 6, "worms"),  # 4 с
        ]
    )
    assert _labels(flows, gt) == ["worms"]
    # поток внутри двух интервалов: расстояние 0 у обоих → раньше начавшаяся запись
    gt = _gt(
        [
            (T0 + 40_000, T0 + 60_000, "1.1.1.1", 1, "2.2.2.2", 2, 6, "dos"),
            (T0 + 30_000, T0 + 60_000, "1.1.1.1", 1, "2.2.2.2", 2, 6, "worms"),
        ]
    )
    assert _labels(flows, gt) == ["worms"]
    # полное равенство времени → по метке по алфавиту
    gt = _gt(
        [
            (T0 + 30_000, T0 + 60_000, "1.1.1.1", 1, "2.2.2.2", 2, 6, "worms"),
            (T0 + 30_000, T0 + 60_000, "1.1.1.1", 1, "2.2.2.2", 2, 6, "dos"),
        ]
    )
    assert _labels(flows, gt) == ["dos"]


def test_result_independent_of_gt_row_order():
    flows = _flows([(T0 + i * 1000, "1.1.1.1", 1, "2.2.2.2", 2, 6) for i in range(20)])
    gt = _gt(
        [
            (T0 + i * 3000, T0 + i * 3000 + 500, "1.1.1.1", 1, "2.2.2.2", 2, 6, lab)
            for i, lab in zip(range(8), ["dos", "worms", "generic", "fuzzers"] * 2, strict=True)
        ]
    )
    first = label_flows(flows, gt, default_label="benign")
    for seed in range(5):
        shuffled = gt.sample(fraction=1.0, shuffle=True, seed=seed)
        assert label_flows(flows, shuffled, default_label="benign").equals(first)


def test_default_label_and_row_order_preserved():
    flows = _flows([(T0 + i, "9.9.9.9", i, "8.8.8.8", 53, 17) for i in range(5)])
    gt = _gt([(T0, T0, "1.1.1.1", 1, "2.2.2.2", 2, 6, "dos")])
    out = label_flows(flows, gt, default_label="unlabeled")
    assert out["label"].to_list() == ["unlabeled"] * 5
    assert out["src_port"].to_list() == [0, 1, 2, 3, 4]
