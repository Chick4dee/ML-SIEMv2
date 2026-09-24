"""API-тесты: временная БД с настоящим прогоном на синтетике и TestClient поверх неё."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

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


@pytest.fixture
def run(soc_cfg, synthetic_split, tiny_detector):
    return run_chain(
        "split:unsw_time/test", soc_cfg, detector_dir=tiny_detector, data_dir=synthetic_split
    )


@pytest.fixture
def client(soc_cfg, run, tiny_detector):
    with TestClient(create_app(soc_cfg, detector_dir=tiny_detector)) as c:
        yield c


API = "/api/v1"
ANALYST = {"X-Analyst": "vlad"}
