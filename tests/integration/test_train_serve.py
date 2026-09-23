"""Train = serve: неразмеченный `extract` и размеченный `flows` дают одинаковые признаки."""

import shutil
from pathlib import Path

import polars as pl
import pyarrow.parquet as pq
import pytest
import yaml

from mlsiem import cli
from mlsiem.data.schema import SCHEMA

FIXTURES = Path(__file__).parents[1] / "fixtures"
REPO = Path(__file__).parents[2]
COMPARED = [c for g in ("feature", "identity", "time", "dpi") for c in SCHEMA.columns_of(g)]
LABELS = SCHEMA.columns_of("label")


def _assert_same(adhoc: Path, labeled: Path) -> None:
    a, b = pl.read_parquet(adhoc), pl.read_parquet(labeled)
    assert not set(LABELS) & set(a.columns), "в extract не должно быть колонок разметки"
    assert a.select(COMPARED).equals(b.select(COMPARED))
    # flow_uid отличается только префиксом capture_id — номера строк те же
    strip = pl.col("flow_uid").str.replace(r"^.*/", "")
    assert a.select(strip).equals(b.select(strip))
    meta_a, meta_b = pq.read_schema(adhoc).metadata, pq.read_schema(labeled).metadata
    assert meta_a[b"mlsiem.schema_version"] == meta_b[b"mlsiem.schema_version"]


def test_train_serve_synthetic(tmp_path):
    ctu = tmp_path / "ctu"
    (ctu / "7").mkdir(parents=True)
    shutil.copy(FIXTURES / "synthetic.pcap", ctu / "7" / "capture.pcap")
    shutil.copy(FIXTURES / "mini.binetflow", ctu / "7" / "capture.binetflow")
    raw = yaml.safe_load((REPO / "configs" / "data.yaml").read_text(encoding="utf-8"))
    raw["datasets"]["ctu13"]["root"] = str(ctu)
    cfg = tmp_path / "data.yaml"
    cfg.write_text(yaml.safe_dump(raw), encoding="utf-8")
    data = tmp_path / "data"
    base = ["data", "--config", str(cfg), "--data-dir", str(data)]

    assert cli.main([*base, "flows", "--dataset", "ctu13", "--capture", "7"]) == 0
    out = tmp_path / "adhoc.parquet"
    assert cli.main([*base, "extract", str(FIXTURES / "synthetic.pcap"), "--output", str(out)]) == 0
    assert pq.read_schema(out).metadata[b"mlsiem.capture_id"] == b"adhoc_synthetic"
    _assert_same(out, data / "flows" / "ctu13" / "ctu13_07.parquet")


def test_extract_rejects_wrong_extension(tmp_path):
    bad = tmp_path / "bot.exe"
    bad.write_bytes(b"MZ")
    code = cli.main(
        [
            "data",
            "--config",
            str(REPO / "configs" / "data.yaml"),
            "extract",
            str(bad),
            "--output",
            str(tmp_path / "x.parquet"),
        ]
    )
    assert code == 1


@pytest.mark.slow
def test_train_serve_ctu13_real(tmp_path):
    """Реальный PCAP сценария 7 против data/flows/ctu13/ctu13_07.parquet (quickstart шаг 5)."""
    labeled = REPO / "data" / "flows" / "ctu13" / "ctu13_07.parquet"
    raw = yaml.safe_load((REPO / "configs" / "data.yaml").read_text(encoding="utf-8"))
    pcaps = sorted((Path(raw["datasets"]["ctu13"]["root"]) / "7").glob("*.pcap"))
    if not labeled.exists() or not pcaps:
        pytest.skip("нет данных: сначала `mlsiem data flows --dataset ctu13 --capture 7`")
    out = tmp_path / "adhoc.parquet"
    assert (
        cli.main(
            [
                "data",
                "--data-dir",
                str(tmp_path),
                "--config",
                str(REPO / "configs" / "data.yaml"),
                "extract",
                str(pcaps[0]),
                "--output",
                str(out),
            ]
        )
        == 0
    )
    _assert_same(out, labeled)
