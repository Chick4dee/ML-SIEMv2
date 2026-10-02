"""Метки и признаки окна (фича 007, R2–R4): правило метки, сводные признаки на ручном
примере, последовательность с маской и порядком."""

import math

import numpy as np
import polars as pl
import pytest

from mlsiem.data.schema import SCHEMA
from mlsiem.detect import windows as W
from mlsiem.soc.direction import sides

L = 60_000
FEATS = SCHEMA.feature_columns()


def _flows(rows: list[dict]) -> pl.DataFrame:
    """Потоки с заданными контекстными полями; признаки — 1.0, если не указаны."""
    out = []
    for r in rows:
        d = {c: 1.0 for c in FEATS}
        d.update(
            {
                "capture_id": "c",
                "src2dst_syn_packets": 1,
                "dst2src_syn_packets": 0,
                "src_port": 40000,
                W.LAST: r[W.FIRST] + 10,
            }
        )
        d.update(r)
        out.append(d)
    df = pl.DataFrame(out)
    return df.with_columns(pl.col("protocol").cast(pl.Int64))


def _window(rows):
    flows = _flows(rows)
    side = sides(flows, "auto").select(W.SIDE_COLUMNS)
    a = W.assign_windows(flows, side, length_ms=L)
    return flows, side, a


def test_label_rule():
    rows = []
    # Окно 1: две exploits и две dos — равенство; dos раньше в таксономии 001, значит dos
    for i, lab in enumerate(["exploits", "dos", "exploits", "dos", "benign"]):
        rows.append(
            {
                "flow_uid": f"a{i}",
                "src_ip": "1.1.1.1",
                "dst_ip": "2.2.2.2",
                "dst_port": 80,
                "protocol": 6,
                W.FIRST: 1_000 + i,
                "label": lab,
            }
        )
    # Окно 2: одна fuzzers среди нормы
    for i, lab in enumerate(["benign", "benign", "fuzzers"]):
        rows.append(
            {
                "flow_uid": f"b{i}",
                "src_ip": "3.3.3.3",
                "dst_ip": "2.2.2.2",
                "dst_port": 80,
                "protocol": 6,
                W.FIRST: 1_000 + i,
                "label": lab,
            }
        )
    # Окно 3: только норма
    rows.append(
        {
            "flow_uid": "c0",
            "src_ip": "4.4.4.4",
            "dst_ip": "2.2.2.2",
            "dst_port": 80,
            "protocol": 6,
            W.FIRST: 5,
            "label": "benign",
        }
    )
    flows, side, a = _window(rows)
    lab = W.window_labels(a, flows.select("flow_uid", "label"))
    keys = a.unique(subset="window_id", maintain_order=True)
    by_ip = dict(zip(keys["window_id"], keys["attacker_ip"], strict=True))
    got = {by_ip[r["window_id"]]: r for r in lab.to_dicts()}
    assert W.TAXONOMY_ORDER.index("dos") < W.TAXONOMY_ORDER.index("exploits")
    assert got["1.1.1.1"]["label"] == "dos"
    assert got["1.1.1.1"]["n_attack_classes"] == 2
    assert got["1.1.1.1"]["attack_share"] == pytest.approx(0.8)
    assert got["3.3.3.3"]["label"] == "fuzzers"
    assert got["3.3.3.3"]["attack_share"] == pytest.approx(1 / 3)
    assert got["4.4.4.4"]["label"] == "benign"
    assert got["4.4.4.4"]["n_attack_classes"] == 0


def test_summary_features_by_hand():
    c = FEATS[1]
    rows = [
        {
            "flow_uid": "f1",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "dst_port": 80,
            "protocol": 6,
            W.FIRST: 0,
            c: 2.0,
        },
        {
            "flow_uid": "f2",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.3",
            "dst_port": 8080,
            "protocol": 17,
            W.FIRST: 4_000,
            c: 4.0,
        },
        {
            "flow_uid": "f3",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.3",
            "dst_port": 80,
            "protocol": 1,
            W.FIRST: 10_000,
            c: 6.0,
        },
    ]
    flows, side, a = _window(rows)
    f = W.summary_features(flows, side, a).row(0, named=True)
    assert f[f"f_{c}_mean"] == pytest.approx(4.0)
    assert f[f"f_{c}_max"] == pytest.approx(6.0)
    assert f[f"f_{c}_std"] == pytest.approx(np.std([2, 4, 6]))
    assert f["w_log_n_flows"] == pytest.approx(math.log1p(3))
    assert f["w_n_targets"] == 2
    assert f["w_n_dst_ports"] == 2
    assert f["w_share_tcp"] == pytest.approx(1 / 3)
    assert f["w_share_udp"] == pytest.approx(1 / 3)
    assert f["w_share_icmp"] == pytest.approx(1 / 3)
    assert f["w_share_other"] == 0
    assert f["w_span_s"] == pytest.approx(10.0)
    assert f["w_gap_mean_s"] == pytest.approx(5.0)
    assert f["w_gap_min_s"] == pytest.approx(4.0)
    assert f["w_gap_std_s"] == pytest.approx(1.0)
    assert f["w_share_reversed"] == 0
    assert f["w_share_low_port"] == pytest.approx(2 / 3)
    assert list(W.summary_features(flows, side, a).columns[1:]) == W.summary_feature_names()


def test_single_flow_std_not_nan_after_preprocessing():
    from sklearn.impute import SimpleImputer

    rows = [
        {
            "flow_uid": "x",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "dst_port": 80,
            "protocol": 6,
            W.FIRST: 0,
        },
        {
            "flow_uid": "y1",
            "src_ip": "5.5.5.5",
            "dst_ip": "2.2.2.2",
            "dst_port": 80,
            "protocol": 6,
            W.FIRST: 0,
        },
        {
            "flow_uid": "y2",
            "src_ip": "5.5.5.5",
            "dst_ip": "2.2.2.2",
            "dst_port": 80,
            "protocol": 6,
            W.FIRST: 100,
        },
    ]
    flows, side, a = _window(rows)
    feats = W.summary_features(flows, side, a)
    X = feats.select(W.summary_feature_names()).to_numpy()
    assert np.isnan(X).any()  # интервалы окна из одного потока не определены
    Xp = SimpleImputer(strategy="median", keep_empty_features=True).fit_transform(X)
    assert not np.isnan(Xp).any()
    one = feats.filter(pl.col("window_id") == a.filter(pl.col("flow_uid") == "x")["window_id"][0])
    assert one[f"f_{FEATS[0]}_std"][0] == 0.0


def test_sequence_shape_mask_order_and_rel_fields():
    rows = []
    for i in range(5):
        rows.append(
            {
                "flow_uid": f"f{4 - i}",
                "src_ip": "1.1.1.1",
                "dst_ip": f"2.2.2.{i % 2}",
                "dst_port": [80, 80, 443, 80, 22][i],
                "protocol": 6,
                W.FIRST: 1_000 * i,
                FEATS[0]: float(i),
            }
        )
    flows, side, a = _window(rows)
    w = W.build_windows(flows, side, length_ms=L, seq_max=4, assignment=a)
    scaler = W.fit_seq_scaler(flows, L)
    X, mask, scalars = W.sequences(flows, side, a, w, seq_max=4, scaler=scaler)
    assert X.shape == (1, 4, len(FEATS) + 4) and X.dtype == np.float32
    assert len(W.seq_feature_names()) == X.shape[2] == 62
    assert mask.tolist() == [[True, True, True, True]]  # 5 потоков, усечено до 4
    # Порядок — по времени: первый канал = log1p(i) стандартизованный, растёт монотонно
    first = X[0, :, 0]
    assert (np.diff(first) > 0).all()
    rel = X[0, :, len(FEATS) :]
    assert rel[:, 2].tolist() == [1.0, 1.0, 0.0, 0.0]  # новая цель: 2.2.2.0, 2.2.2.1, повторы
    assert rel[:, 3].tolist() == [1.0, 0.0, 1.0, 0.0]  # новый порт: 80, 80, 443, 80
    assert rel[0, 1] == 0.0 and rel[1, 1] == pytest.approx(math.log1p(1.0))
    t_mean, t_std = 30.0, 60.0 / math.sqrt(12)
    assert rel[2, 0] == pytest.approx((2.0 - t_mean) / t_std, rel=1e-5)
    np.testing.assert_allclose(
        scalars[0], [math.log1p(5), 1.0, math.log1p(2), math.log1p(3)], rtol=1e-6
    )


def test_sequence_padding_for_short_window():
    rows = [
        {
            "flow_uid": "a",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "dst_port": 80,
            "protocol": 6,
            W.FIRST: 0,
        },
    ]
    flows, side, a = _window(rows)
    w = W.build_windows(flows, side, length_ms=L, seq_max=8, assignment=a)
    X, mask, _ = W.sequences(flows, side, a, w, seq_max=8, scaler=W.fit_seq_scaler(flows, L))
    assert mask.sum() == 1 and (X[0, 1:] == 0).all()
