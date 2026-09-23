"""Тесты аудита артефактов на синтетике."""

import numpy as np
import polars as pl

from mlsiem.data.audit import audit_fields, stratified_sample
from mlsiem.data.config import AuditConfig

CFG = AuditConfig(
    sample_per_part=500_000, tree_depth=4, dangerous_lift=0.10, suspicious_pr_auc=0.90
)


def _part(n: int, seed: int) -> pl.DataFrame:
    rng = np.random.default_rng(seed)
    labels = np.where(rng.random(n) < 0.3, "dos", "benign")
    attack = labels == "dos"
    return pl.DataFrame(
        {
            "flow_uid": [f"x/{seed}-{i}" for i in range(n)],
            "label": labels,
            # атакующие — всегда из одной подсети, фон — из многих: классический артефакт стенда
            "src_ip": np.where(
                attack, "175.45.176.1", [f"10.0.{i % 50}.{i % 7}" for i in range(n)]
            ),
            "noise": rng.normal(size=n),
            # «идеальный» поведенческий признак
            "bidirectional_packets": np.where(attack, 1000, 3) + rng.integers(0, 2, n),
        }
    )


def _run():
    return audit_fields(
        _part(3000, 1),
        _part(1000, 2),
        [("src_ip", "identity"), ("noise", "feature"), ("bidirectional_packets", "feature")],
        CFG,
        seed=42,
    )


def test_statuses():
    res = {(r["field"], r["variant"]): r for r in _run().iter_rows(named=True)}
    assert res[("src_ip", "raw")]["status"] == "dangerous"
    assert ("src_ip", "subnet24") in res  # вариант подсети тоже посчитан
    assert res[("noise", "raw")]["status"] == "ok"
    # сильный признак модели — suspicious, а не dangerous
    assert res[("bidirectional_packets", "raw")]["status"] == "suspicious"


def test_baseline_is_mean_class_share():
    val = _part(1000, 2)
    share = (val["label"] == "dos").mean()
    expected = (share + (1 - share)) / 2
    baseline = _run()["baseline"].unique().to_list()
    assert baseline == [expected] == [0.5]
    row = _run().row(0, named=True)
    assert abs(row["lift"] - (row["pr_auc_macro"] - row["baseline"])) < 1e-12


def test_stratified_sample_reproducible():
    df = _part(10_000, 5)
    a = stratified_sample(df, 1000, seed=42)
    b = stratified_sample(df.reverse(), 1000, seed=42)
    assert a.sort("flow_uid").equals(b.sort("flow_uid"))
    assert 950 <= a.height <= 1000
    share_full = (df["label"] == "dos").mean()
    share = (a["label"] == "dos").mean()
    assert abs(share - share_full) < 0.01
