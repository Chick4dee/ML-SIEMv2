"""Новый неразмеченный PCAP через всю цепочку (US5, SC-007)."""

import json
import shutil
from pathlib import Path

import polars as pl
import pyarrow.parquet as pq
import pytest
from fastapi.testclient import TestClient

from mlsiem import cli
from mlsiem.data.extract import extract_flows
from mlsiem.data.schema import SCHEMA
from mlsiem.soc import store
from mlsiem.soc.api import create_app
from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.soc.run import run_chain

REPO = Path(__file__).parents[2]


@pytest.fixture
def soc_cfg(tmp_path):
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    return parse_soc_config(
        {**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs")}
    )


def test_pcap_features_match_extractor(soc_cfg, tiny_detector, synthetic_pcap, tmp_path):
    s = run_chain(f"pcap:{synthetic_pcap}", soc_cfg, detector_dir=tiny_detector)
    assert s.source == "pcap:synthetic.pcap"
    flows_file = soc_cfg.runs_dir / s.run_id / "flows.parquet"
    assert flows_file.exists()
    assert (soc_cfg.runs_dir / s.run_id / "verdicts.parquet").exists()

    ours = pl.read_parquet(flows_file)
    reference = extract_flows(synthetic_pcap, "adhoc_synthetic", workdir=tmp_path / "ref").df
    feats = SCHEMA.feature_columns()
    assert ours.select(feats).equals(reference.select(feats))
    assert ours.height == s.n_flows > 0

    meta = pq.read_schema(flows_file).metadata
    card = json.loads((tiny_detector / "model_card.json").read_text(encoding="utf-8"))
    assert meta[b"mlsiem.schema_version"].decode() == card["schema_version"]
    # Разметки у PCAP нет — и сводки «доля верных алертов» тоже
    assert s.alerts_true_share is None

    with TestClient(create_app(soc_cfg, detector_dir=tiny_detector)) as client:
        runs = client.get("/api/v1/runs").json()["items"]
    assert [r["source"] for r in runs] == ["pcap:synthetic.pcap"]


def test_pcap_without_alerts(soc_cfg, tiny_detector, synthetic_pcap, tmp_path, capsys):
    # Детектор с недостижимым порогом: алертов нет — это не ошибка, а «инцидентов нет»
    det = tmp_path / "strict"
    shutil.copytree(tiny_detector, det)
    card = json.loads((det / "model_card.json").read_text(encoding="utf-8"))
    card["threshold"] = 1.01
    (det / "model_card.json").write_text(json.dumps(card), encoding="utf-8")

    s = run_chain(f"pcap:{synthetic_pcap}", soc_cfg, detector_dir=det)
    assert s.n_alerts == 0 and s.n_incidents == 0
    conn = store.connect(soc_cfg.db)
    row = conn.execute(
        "SELECT n_flows, n_alerts, n_incidents FROM runs WHERE run_id = ?", (s.run_id,)
    ).fetchone()
    conn.close()
    assert (row["n_alerts"], row["n_incidents"]) == (0, 0) and row["n_flows"] > 0

    cfg_path = tmp_path / "soc.yaml"
    import yaml

    cfg_path.write_text(
        yaml.safe_dump({**soc_cfg.raw, "db": str(soc_cfg.db), "runs_dir": str(soc_cfg.runs_dir)}),
        encoding="utf-8",
    )
    code = cli.main(
        [
            "soc",
            "--config",
            str(cfg_path),
            "run",
            "--pcap",
            str(synthetic_pcap),
            "--detector",
            str(det),
        ]
    )
    assert code == 0
    assert "инцидентов нет" in capsys.readouterr().out


def test_truncated_pcap_warns(soc_cfg, tiny_detector, truncated_pcap):
    s = run_chain(f"pcap:{truncated_pcap}", soc_cfg, detector_dir=tiny_detector)
    assert s.warnings and any("обрыва" in w for w in s.warnings)
    conn = store.connect(soc_cfg.db)
    warnings = json.loads(
        conn.execute("SELECT warnings FROM runs WHERE run_id = ?", (s.run_id,)).fetchone()[
            "warnings"
        ]
    )
    conn.close()
    assert warnings == s.warnings


def test_missing_pcap_file(soc_cfg, tiny_detector, tmp_path):
    with pytest.raises(ValueError, match="нет файла"):
        run_chain(f"pcap:{tmp_path / 'none.pcap'}", soc_cfg, detector_dir=tiny_detector)
    # Проверка входа — до открытия хранилища: ни базы, ни каталога прогонов
    assert not soc_cfg.db.exists() and not soc_cfg.runs_dir.exists()
    assert not (tmp_path / "var").exists()


def test_pcap_and_split_are_exclusive(tiny_detector, synthetic_pcap):
    code = cli.main(
        [
            "soc",
            "run",
            "--pcap",
            str(synthetic_pcap),
            "--split",
            "unsw_time",
            "--part",
            "test",
            "--detector",
            str(tiny_detector),
        ]
    )
    assert code == 1
