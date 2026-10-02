"""Панель консоли для живого сенсора (фича 006, US2/T054, FR-025).

У сеанса `sensor:live` на панели «Поток» появляется блок «Сенсор» с пакетами/с, потоками/с,
потерями, буфером и живостью; у сеанса-проигрывателя 005 блока нет (отображение не меняется).
"""

from pathlib import Path

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from fixtures.stream_helpers import make_soc_cfg, make_stream_cfg
from mlsiem.soc import store
from mlsiem.soc.api import create_app

REPO = Path(__file__).parents[2]


def _htmx():
    return {"HX-Request": "true"}


def _session(conn, source_id):
    run = store.create_session(conn, source_id, model_version="m1", summary={"model": {}})
    store.set_session_status(conn, run["run_id"], "running", "тест")
    return run["run_id"]


@pytest.fixture
def env(tmp_path, tiny_detector):
    stream_cfg = make_stream_cfg()
    soc_cfg = make_soc_cfg(tmp_path)
    conn = store.connect(soc_cfg.db)
    store.init_db(conn)
    sensor_run = _session(conn, "sensor:live")
    replay_run = _session(conn, "replay:x:1")
    # Показатели сенсора только у sensor:live
    store.write_stats(
        conn,
        [
            {
                "run_id": sensor_run,
                "processed": 10,
                "packets_per_s": 120.0,
                "flows_per_s": 2.5,
                "drops": 3,
                "buffer_fill": 0.25,
                "liveness": 1,
            }
        ],
    )
    store.mark_lossy(conn, sensor_run)
    # У проигрывателя — обычные показатели 005 без сенсорных полей
    store.write_stats(conn, [{"run_id": replay_run, "processed": 5, "rate_per_s": 1.0}])
    conn.close()
    app = create_app(soc_cfg, detector_dir=tiny_detector, stream_cfg=stream_cfg)
    with TestClient(app) as client:
        yield client, sensor_run, replay_run


def test_sensor_block_shown_for_sensor_live(env):
    client, sensor_run, _ = env
    panel = BeautifulSoup(
        client.get(f"/fragments/stream-panel?run={sensor_run}", headers=_htmx()).text,
        "html.parser",
    )
    block = panel.select_one("[data-stream=sensor]")
    assert block is not None
    for key in ("packets", "sensor-flows", "drops", "buffer", "liveness"):
        assert block.select_one(f"[data-stream={key}]") is not None, key
    assert "120" in block.select_one("[data-stream=packets]").get_text()
    assert "25%" in block.select_one("[data-stream=buffer]").get_text()
    # Флаг «с потерями» виден
    assert panel.select_one("[data-stream=lossy]") is not None


def test_replay_session_has_no_sensor_block(env):
    client, _, replay_run = env
    panel = BeautifulSoup(
        client.get(f"/fragments/stream-panel?run={replay_run}", headers=_htmx()).text,
        "html.parser",
    )
    # Блока «Сенсор» нет — отображение источников 005 не меняется (FR-025)
    assert panel.select_one("[data-stream=sensor]") is None
    assert panel.select_one("[data-stream=lossy]") is None
    # Обычный показатель 005 на месте
    assert panel.select_one("[data-stream=rate]") is not None
