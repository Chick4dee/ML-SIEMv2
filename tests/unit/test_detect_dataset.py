"""Данные для детектора: только поля feature, пропуски → 0, хеши из манифестов 001."""

import json
import shutil

import polars as pl
import pytest

from mlsiem.data.schema import SCHEMA
from mlsiem.detect.dataset import data_hashes, load_part

FORBIDDEN = [c for g in ("identity", "time", "dpi", "label", "key") for c in SCHEMA.columns_of(g)]


def test_only_feature_columns(synthetic_split):
    part = load_part("unsw_time", "val", data_dir=synthetic_split)
    assert part.X.columns == SCHEMA.feature_columns()
    assert not set(FORBIDDEN) & set(part.X.columns)
    assert all(dt == pl.Float32 for dt in part.X.dtypes)
    assert part.X.null_count().sum_horizontal().item() == 0
    assert len(part.y) == part.X.height == len(part.flow_uid)


def test_labels_and_order(synthetic_split):
    part = load_part("unsw_time", "train", data_dir=synthetic_split)
    assert set(part.y) <= {"benign", "exploits", "dos", "reconnaissance", "fuzzers"}
    assert list(part.flow_uid) == sorted(part.flow_uid)
    manifest = json.loads(
        (synthetic_split / "splits" / "unsw_time.json").read_text(encoding="utf-8")
    )
    assert len(part.y) == manifest["parts"]["train"]["n_flows"]


def test_nulls_become_zero(tmp_path, synthetic_split):
    data = tmp_path / "data"
    shutil.copytree(synthetic_split, data)
    f = data / "flows" / "unsw" / "unsw_22-1-2015_01.parquet"
    df = pl.read_parquet(f).with_columns(pl.lit(None, pl.Int64).alias("bidirectional_packets"))
    df.write_parquet(f)
    part = load_part("unsw_time", "test", data_dir=data)
    assert part.X.null_count().sum_horizontal().item() == 0
    assert (part.X["bidirectional_packets"] == 0).sum() > 0


def test_data_hashes(synthetic_split):
    h = data_hashes("unsw_time", synthetic_split)
    manifest = json.loads(
        (synthetic_split / "splits" / "unsw_time.json").read_text(encoding="utf-8")
    )
    assert h["split_hash"] == manifest["hash"]
    assert h["input_hashes"] == manifest["input_hashes"]
    assert set(h["input_hashes"]) == {"unsw_22-1-2015_01", "unsw_17-2-2015_01"}


def test_missing_split(tmp_path):
    with pytest.raises(ValueError, match="mlsiem data split"):
        load_part("unsw_time", "train", data_dir=tmp_path)


def test_capture_not_done(tmp_path, synthetic_split):
    data = tmp_path / "data"
    shutil.copytree(synthetic_split, data)
    m = data / "flows" / "unsw" / "unsw_17-2-2015_01.json"
    raw = json.loads(m.read_text(encoding="utf-8"))
    raw["status"] = "failed"
    m.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="не готовы"):
        load_part("unsw_time", "train", data_dir=data)
