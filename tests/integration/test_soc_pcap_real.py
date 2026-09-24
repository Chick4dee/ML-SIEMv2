"""PCAP CTU-13 №7 через всю цепочку одной командой (US5, SC-007). Нужен диск A: и данные 001.

Детектор обучен на UNSW-NB15, поэтому его вердикты на ботнет-трафике CTU-13 — не показатель
качества: тест проверяет путь данных (те же признаки, что у потоков 001 этого захвата).
"""

from pathlib import Path

import polars as pl
import pytest
import yaml

from mlsiem.data.schema import SCHEMA
from mlsiem.soc.config import load_soc_config, parse_soc_config

REPO = Path(__file__).parents[2]
DETECTOR = REPO / "models" / "detector"
LABELED = REPO / "data" / "flows" / "ctu13" / "ctu13_07.parquet"


@pytest.mark.slow
def test_soc_pcap_ctu13_real(tmp_path):
    from mlsiem.soc.run import run_chain

    raw = yaml.safe_load((REPO / "configs" / "data.yaml").read_text(encoding="utf-8"))
    pcaps = sorted((Path(raw["datasets"]["ctu13"]["root"]) / "7").glob("*.pcap"))
    if not pcaps or not LABELED.exists() or not (DETECTOR / "model.joblib").exists():
        pytest.skip("нет PCAP CTU-13 №7, потоков 001 ctu13_07 или детектора")
    soc_raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    cfg = parse_soc_config(
        {**soc_raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs")}
    )

    s = run_chain(f"pcap:{pcaps[0]}", cfg, detector_dir=DETECTOR)
    assert s.source == f"pcap:{pcaps[0].name}"
    ours = pl.read_parquet(cfg.runs_dir / s.run_id / "flows.parquet")
    labeled = pl.read_parquet(LABELED)
    feats = SCHEMA.feature_columns()
    assert ours.select(feats).equals(labeled.select(feats))
    assert s.n_flows == labeled.height
