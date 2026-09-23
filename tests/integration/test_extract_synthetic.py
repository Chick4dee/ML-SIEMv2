"""Экстрактор на синтетическом PCAP: схема, сортировка, детерминизм, битые файлы."""

from pathlib import Path

import polars as pl
import pyarrow.parquet as pq
import pytest

from mlsiem.data.extract import (
    SORT_KEY,
    content_hash,
    extract_flows,
    sort_flows,
    write_flows_parquet,
)
from mlsiem.data.schema import SCHEMA

FIXTURES = Path(__file__).parents[1] / "fixtures"


@pytest.fixture(scope="module")
def flows(tmp_path_factory):
    return extract_flows(FIXTURES / "synthetic.pcap", "syn", workdir=tmp_path_factory.mktemp("w"))


def test_columns_follow_schema_without_labels(flows):
    expected = [c for c in SCHEMA.names() if c not in SCHEMA.columns_of("label")]
    assert flows.df.columns == expected
    for col in SCHEMA.columns:
        if col.name in flows.df.columns:
            assert flows.df.schema[col.name] == col.dtype, col.name


def test_seven_flows_sorted_with_unique_uid(flows):
    df = flows.df
    assert df.height == 7
    assert df["flow_uid"].to_list() == [f"syn/{i}" for i in range(7)]
    shuffled = df.sample(fraction=1.0, shuffle=True, seed=1).drop("flow_uid", "capture_id")
    assert sort_flows(shuffled).equals(df.drop("flow_uid", "capture_id"))
    assert (df["bidirectional_first_seen_ms"] <= df["bidirectional_last_seen_ms"]).all()
    assert flows.warnings == []


def test_parquet_metadata_and_repeatable_hash(flows, synthetic_pcap, tmp_path):
    out = tmp_path / "syn.parquet"
    write_flows_parquet(flows.df, out, {"mlsiem.capture_id": "syn"})
    meta = pq.read_schema(out).metadata
    assert meta[b"mlsiem.schema_version"] == SCHEMA.version.encode()
    assert meta[b"mlsiem.capture_id"] == b"syn"
    assert pl.read_parquet(out).equals(flows.df)

    again = extract_flows(synthetic_pcap, "syn", workdir=tmp_path)
    assert content_hash(again.df) == content_hash(flows.df)


def test_pcapng_gives_same_flows(flows, synthetic_pcapng, tmp_path):
    ng = extract_flows(synthetic_pcapng, "syn", workdir=tmp_path)
    assert content_hash(ng.df) == content_hash(flows.df)


def test_sort_is_total_even_with_ties():
    # Две строки совпадают по всем 8 полям ключа R3, но различаются остальным —
    # при любом перемешивании порядок должен получаться одним и тем же
    base = {c: [1, 1] for c in SORT_KEY}
    base.update({"src_ip": ["a", "a"], "dst_ip": ["b", "b"], "bidirectional_bytes": [200, 100]})
    df = pl.DataFrame(base)
    first = sort_flows(df)
    assert first["bidirectional_bytes"].to_list() == [100, 200]
    assert sort_flows(df.reverse()).equals(first)


def test_truncated_pcap_does_not_crash(truncated_pcap, tmp_path):
    res = extract_flows(truncated_pcap, "tr", workdir=tmp_path)
    assert res.df.height > 0
    assert res.warnings, "обрыв файла должен попасть в предупреждения"


def test_tail_check_for_huge_files(monkeypatch, synthetic_pcap, truncated_pcap):
    # Притворяемся, что файлы огромные: включается проверка только хвоста
    from mlsiem.data import extract

    monkeypatch.setattr(extract, "FULL_WALK_LIMIT", 0)
    assert extract.check_pcap_integrity(synthetic_pcap) == []
    warnings = extract.check_pcap_integrity(truncated_pcap)
    assert warnings and "обрывается" in warnings[0]
