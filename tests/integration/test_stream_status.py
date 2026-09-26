"""Наблюдаемость потока (US5): `mlsiem stream status`, `GET /api/v1/stream/status`, блок «Поток»."""

import pytest
import yaml
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from fixtures.stream_helpers import (
    make_cluster,
    make_soc_cfg,
    make_stream_cfg,
    replay_split,
    run_consumer,
)
from mlsiem import cli
from mlsiem.soc import store
from mlsiem.soc.api import create_app
from mlsiem.soc.run import run_chain
from mlsiem.stream import broker as broker_mod
from mlsiem.stream.broker import MemoryBroker

SRC = "replay:unsw_time/test:20260925T140000"


@pytest.fixture
def env(tmp_path, synthetic_split, tiny_detector, monkeypatch):
    stream_cfg, soc_cfg = make_stream_cfg(batch_max_messages=200), make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC, limit=400)
    run_consumer(cluster, stream_cfg, soc_cfg, tiny_detector)
    monkeypatch.setattr(
        broker_mod,
        "make_broker",
        lambda cfg, role="x": MemoryBroker(cluster, vm_name=cfg.stand.vm_name),
    )
    soc_yaml = tmp_path / "soc.yaml"
    soc_yaml.write_text(yaml.safe_dump(soc_cfg.raw, allow_unicode=True), encoding="utf-8")
    return stream_cfg, soc_cfg, cluster, soc_yaml


def test_cli_status(env, capsys):
    stream_cfg, soc_cfg, cluster, soc_yaml = env
    assert cli.main(["stream", "--soc-config", str(soc_yaml), "status"]) == 0
    out = capsys.readouterr().out
    run_id = store.session_run_id(SRC)
    assert "доступен" in out and "Потребитель: не работает" in out
    assert run_id in out and "завершён" in out and "обработано 400" in out

    cluster.down = True
    assert cli.main(["stream", "--soc-config", str(soc_yaml), "status"]) == 0
    out = capsys.readouterr().out
    assert "НЕДОСТУПЕН" in out and "Start-VM" in out


def test_api_stream_status(env, tiny_detector):
    stream_cfg, soc_cfg, cluster, _ = env
    with TestClient(create_app(soc_cfg, detector_dir=tiny_detector, stream_cfg=stream_cfg)) as c:
        r = c.get("/api/v1/stream/status")
        assert r.status_code == 200
        body = r.json()
        assert set(body) == {"broker", "consumer", "sessions"}
        assert body["broker"]["reachable"] is True
        assert body["consumer"]["alive"] is False
        (s,) = body["sessions"]
        assert s["run_id"] == store.session_run_id(SRC) and s["status"] == "completed"
        assert s["processed"] == 400
        assert {
            "lag_messages",
            "lag_seconds",
            "latency_p50_ms",
            "latency_p95_ms",
            "rejected",
            "late",
            "rate_per_s",
            "last_activity_at",
        } <= set(s)
        # Кеш проверки брокера: выключенная «машина» не видна раньше 10 с
        cluster.down = True
        assert c.get("/api/v1/stream/status").json()["broker"]["reachable"] is True
        # Изменяющих методов нет
        assert c.post("/api/v1/stream/status").status_code == 405


def test_panel_block_only_for_stream(env, tiny_detector, synthetic_split):
    stream_cfg, soc_cfg, cluster, _ = env
    batch = run_chain(
        "split:unsw_time/test", soc_cfg, model_dir=tiny_detector, data_dir=synthetic_split, limit=50
    )
    run_id = store.session_run_id(SRC)
    with TestClient(create_app(soc_cfg, detector_dir=tiny_detector, stream_cfg=stream_cfg)) as c:
        html = c.get("/", params={"run": run_id}).text
        soup = BeautifulSoup(html, "html.parser")
        panel = soup.find(id="stream-panel")
        assert panel is not None
        assert panel["hx-trigger"] == f"every {soc_cfg.ui.refresh_seconds}s"
        assert "завершён" in panel.get_text() and "не работает" in panel.get_text()
        assert soup.find("option", value=run_id).get_text().endswith("поток, завершён")

        frag = c.get(
            "/fragments/stream-panel", params={"run": run_id}, headers={"HX-Request": "true"}
        )
        assert frag.status_code == 200 and 'id="stream-panel"' in frag.text
        again = c.get(
            "/fragments/stream-panel",
            params={"run": run_id},
            headers={"HX-Request": "true", "If-None-Match": frag.headers["etag"]},
        )
        assert again.status_code == 204

        batch_html = c.get("/", params={"run": batch.run_id}).text
        assert 'id="stream-panel"' not in batch_html
