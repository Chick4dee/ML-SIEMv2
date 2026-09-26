"""Консоль и API для онлайн-сеансов (US3, contracts/api-ui-additions.md): только добавления.

Два сеанса: один сделан настоящим потребителем на синтетике (вердикты — каталог файлов по
пачкам), второй собран планами группировки вручную — в нём слияние и «алерты после решения».
"""

from urllib.parse import quote

import polars as pl
import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from fixtures.stream_helpers import (
    make_cluster,
    make_soc_cfg,
    make_stream_cfg,
    replay_split,
    run_consumer,
)
from mlsiem.soc import store
from mlsiem.soc.api import create_app
from mlsiem.stream.incremental import plan_batch

API = "/api/v1"
SRC = "replay:unsw_time/test:20260925T150000"
MANUAL = "replay:manual:1"
W = 900_000
A = "175.45.176.1"


def _alert(uid, t, victim="149.171.126.10"):
    return {
        "flow_uid": uid,
        "capture_id": "c",
        "src_ip": A,
        "src_port": 4000,
        "dst_ip": victim,
        "dst_port": 80,
        "protocol": 6,
        "first_seen_ms": t,
        "last_seen_ms": t + 10,
        "predicted_class": "dos",
        "attack_score": 0.9,
        "attacker_ip": A,
        "victim_ip": victim,
        "reversed": 0,
        "direction_rule": "default",
        "fired_experts": "classifier",
        "experts": None,
        "explanation": None,
    }


def _apply(conn, run_id, soc_cfg, rows):
    frame = pl.DataFrame(rows, schema_overrides={"experts": pl.String, "explanation": pl.String})
    store.append_batch(conn, [plan_batch(conn, run_id, frame, soc_cfg)], offsets={})


@pytest.fixture
def env(tmp_path, synthetic_split, tiny_detector):
    stream_cfg, soc_cfg = make_stream_cfg(batch_max_messages=150), make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC, limit=300)
    run_consumer(cluster, stream_cfg, soc_cfg, tiny_detector)

    conn = store.connect(soc_cfg.db)
    manual = store.create_session(conn, MANUAL, model_version="m", summary={})["run_id"]
    t0 = 1_424_000_000_000
    # a, b — два инцидента; c закрыт аналитиком и дописывается; mid склеивает a и b
    _apply(conn, manual, soc_cfg, [_alert("a", t0), _alert("b", t0 + 2 * W)])
    _apply(conn, manual, soc_cfg, [_alert("c", t0 + 10 * W)])
    ids = {
        r["first_seen_ms"]: r["incident_id"]
        for r in conn.execute("SELECT * FROM incidents WHERE run_id = ?", (manual,))
    }
    closed = ids[t0 + 10 * W]
    store.change_status(conn, closed, "vlad", "closed", "confirmed", None, 1)
    _apply(conn, manual, soc_cfg, [_alert("mid", t0 + W), _alert("c2", t0 + 10 * W + 5000)])
    conn.close()
    app = create_app(soc_cfg, detector_dir=tiny_detector, stream_cfg=stream_cfg)
    with TestClient(app) as client:
        yield client, soc_cfg, manual, ids[t0], ids[t0 + 2 * W], closed


def test_api_runs_have_session_fields(env):
    client, *_ = env
    runs = {r["run_id"]: r for r in client.get(f"{API}/runs").json()["items"]}
    s = runs[store.session_run_id(SRC)]
    assert (s["mode"], s["status"], s["source_id"]) == ("stream", "completed", SRC)
    assert s["last_activity_at"]


def test_api_incident_fields_and_filters(env):
    client, soc_cfg, manual, first, second, closed = env
    items = client.get(f"{API}/incidents", params={"run_id": manual}).json()["items"]
    by_id = {i["incident_id"]: i for i in items}
    # Поглощённый скрыт по умолчанию
    assert second not in by_id and first in by_id
    assert by_id[first]["n_alerts"] == 3 and by_id[first]["merged_into"] is None
    assert by_id[closed]["alerts_after_decision"] == 1
    assert by_id[closed]["first_after_decision_ms"] is not None

    shown = client.get(f"{API}/incidents", params={"run_id": manual, "show_merged": "true"}).json()[
        "items"
    ]
    assert {i["incident_id"]: i["merged_into"] for i in shown}[second] == first

    only = client.get(
        f"{API}/incidents", params={"run_id": manual, "after_decision": "only"}
    ).json()
    assert [i["incident_id"] for i in only["items"]] == [closed]

    card = client.get(f"{API}/incidents/{second}").json()
    assert card["merged_into"] == first and card["n_alerts"] == 0
    assert client.get(f"{API}/incidents", params={"after_decision": "всё"}).status_code == 422


def test_card_notes_and_timeline(env):
    client, soc_cfg, manual, first, second, closed = env
    html = client.get(f"/incidents/{quote(closed, safe='')}").text
    soup = BeautifulSoup(html, "html.parser")
    note = soup.select_one(".after-note").get_text(" ", strip=True)
    assert "Новые алерты после решения: 1" in note and "UTC" in note
    timeline = soup.select_one("#incident-log").get_text(" ", strip=True)
    assert "инцидент дополнен потоком" in timeline
    assert "после решения аналитика — решение не изменено" in timeline

    html = client.get(f"/incidents/{quote(second, safe='')}").text
    soup = BeautifulSoup(html, "html.parser")
    merged = soup.select_one(".merged-note")
    assert merged.find("a")["href"] == f"/incidents/{first}"
    assert "инцидент объединён" in soup.select_one("#incident-log").get_text()


def test_list_filters_and_badges(env):
    client, soc_cfg, manual, first, second, closed = env
    html = client.get("/incidents", params={"run": manual}).text
    soup = BeautifulSoup(html, "html.parser")
    assert soup.find("input", attrs={"name": "after_decision"}) is not None
    assert soup.find("input", attrs={"name": "show_merged"}) is not None
    rows = {tr["data-incident"]: tr for tr in soup.select("tr[data-incident]")}
    assert second not in rows
    assert "+1 после решения" in rows[closed].get_text()

    html = client.get("/incidents", params={"run": manual, "after_decision": "only"}).text
    rows = BeautifulSoup(html, "html.parser").select("tr[data-incident]")
    assert [r["data-incident"] for r in rows] == [closed]

    html = client.get("/incidents", params={"run": manual, "show_merged": "1"}).text
    rows = {
        tr["data-incident"]: tr
        for tr in BeautifulSoup(html, "html.parser").select("tr[data-incident]")
    }
    assert "объединён с" in rows[second].get_text()


def test_batch_run_pages_have_no_stream_filters(env, synthetic_split, tiny_detector):
    client, soc_cfg, *_ = env
    from mlsiem.soc.run import run_chain

    batch = run_chain(
        "split:unsw_time/test", soc_cfg, model_dir=tiny_detector, data_dir=synthetic_split, limit=80
    )
    html = client.get("/incidents", params={"run": batch.run_id}).text
    assert 'name="after_decision"' not in html


def test_alert_probs_from_verdicts_dir(env):
    client, soc_cfg, *_ = env
    run_id = store.session_run_id(SRC)
    conn = store.connect(soc_cfg.db)
    uid = conn.execute(
        "SELECT flow_uid FROM alerts WHERE run_id = ? LIMIT 1", (run_id,)
    ).fetchone()[0]
    assert not (soc_cfg.runs_dir / run_id / "verdicts.parquet").exists()
    r = client.get(f"/fragments/alerts/{run_id}/{uid}/probs", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "вероятности недоступны" not in r.text


def test_no_inline_scripts_or_styles(env):
    client, soc_cfg, manual, first, second, closed = env
    for url in (
        "/",
        f"/?run={manual}",
        f"/incidents?run={manual}",
        f"/incidents/{quote(closed, safe='')}",
    ):
        soup = BeautifulSoup(client.get(url).text, "html.parser")
        assert not [s for s in soup.find_all("script") if not s.get("src")], url
        assert not soup.find_all(style=True), url
        assert not soup.find_all("style"), url
