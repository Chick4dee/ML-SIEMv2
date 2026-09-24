"""Скорость консоли на полном прогоне 002 (SC-001: < 1 с) — медленный тест на копии var/soc.db."""

import shutil
import time
from dataclasses import replace
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from mlsiem.soc import store
from mlsiem.soc.api import create_app
from mlsiem.soc.config import load_soc_config

REPO = Path(__file__).parents[2]
REAL_DB = REPO / "var" / "soc.db"
LIMIT_S = 1.0

pytestmark = pytest.mark.slow


@pytest.fixture
def real(tmp_path):
    if not REAL_DB.exists():
        pytest.skip("нет var/soc.db с прогоном 002")
    shutil.copy(REAL_DB, tmp_path / "soc.db")
    cfg = replace(load_soc_config(REPO / "configs" / "soc.yaml"), db=tmp_path / "soc.db")
    with TestClient(create_app(cfg), base_url="http://127.0.0.1:8000") as client:
        conn = store.connect(cfg.db)
        runs = [r for r in store.list_runs(conn) if r["source"].startswith("split:")]
        if not runs:
            pytest.skip("в var/soc.db нет прогона части разбиения")
        run = max(runs, key=lambda r: r["n_incidents"])
        _, items = store.list_incidents(conn, {"run_id": run["run_id"]}, 1, sort="n_alerts")
        biggest = items[0]
        _, alerts = store.list_alerts(conn, biggest["incident_id"], 1)
        conn.close()
        yield client, run, biggest, alerts[0]


def test_response_times(real):
    client, run, biggest, alert = real
    rid = quote(run["run_id"])
    urls = [
        f"/?run={rid}",
        f"/incidents?run={rid}",
        f"/incidents?run={rid}&severity=high,critical",
        f"/incidents?run={rid}&status=new",
        f"/incidents?run={rid}&attack_class=exploits",
        f"/incidents?run={rid}&src=175.45.176.0/24",
        f"/incidents?run={rid}&assignee=__none__",
        f"/incidents?run={rid}&action_state=proposed",
        f"/incidents?run={rid}&flagged=only",
        f"/incidents?run={rid}&flagged=hide&sort=n_alerts&dir=asc",
        f"/incidents?run={rid}&severity=medium&src=175.45.176.0/24&flagged=hide&status=new",
        f"/incidents/{biggest['incident_id']}",
        f"/fragments/incidents/{biggest['incident_id']}/alerts?page=3",
        f"/fragments/alerts/{rid}/{alert['flow_uid']}/probs",
        f"/audit?run={rid}",
    ]
    client.get(urls[0])  # прогрев: шаблоны компилируются при первом обращении
    timings = []
    for url in urls:
        t0 = time.perf_counter()
        r = client.get(url)
        dt = time.perf_counter() - t0
        assert r.status_code == 200, url
        timings.append((dt, url))
    print(f"\nсамый большой инцидент: {biggest['incident_id']} ({biggest['n_alerts']} алертов)")
    for dt, url in timings:
        print(f"  {dt * 1000:7.1f} мс  {url}")
    slow = [(dt, url) for dt, url in timings if dt >= LIMIT_S]
    assert not slow, slow
