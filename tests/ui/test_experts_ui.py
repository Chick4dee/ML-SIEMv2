"""Консоль фичи 004 (contracts/ui.md): блок «Эксперты», «Кто поднял алерты», значок «ответный»,
класс «аномалия», модель прогона на панели. Старые прогоны открываются без ошибок.

В базе прогон ансамблем на синтетике и «старый» прогон, записанный как в 002 (без полей
экспертов). Ответный поток и объяснение с «опасными» символами добавляются прямо в SQLite —
в синтетике ответных потоков нет по построению.
"""

import json
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from mlsiem.soc import store
from mlsiem.soc.api import create_app
from mlsiem.soc.run import run_chain
from ui.conftest import BASE, htmx, soup

XSS = "<script>alert(1)</script>"


@pytest.fixture
def env(soc_cfg, synthetic_split, tiny_ensemble):
    s = run_chain(
        "split:unsw_time/test", soc_cfg, model_dir=tiny_ensemble, data_dir=synthetic_split
    )
    conn = store.connect(soc_cfg.db)
    # «старый» прогон 002: алерт без экспертов, в сводке нет модели
    store.write_run(
        conn,
        {
            "run_id": "old-run",
            "source": "split:unsw_time/test",
            "input_hash": "h",
            "detector_version": "20260924-886cf326",
            "started_at": "2020-01-01T00:00:00.000Z",
            "n_flows": 1,
            "summary": {},
        },
        [
            {
                "flow_uid": "old/1",
                "capture_id": "c",
                "src_ip": "175.45.176.9",
                "src_port": 4000,
                "dst_ip": "149.171.126.3",
                "dst_port": 80,
                "protocol": 6,
                "first_seen_ms": 1,
                "last_seen_ms": 2,
                "predicted_class": "dos",
                "attack_score": 0.99,
                "incident_id": "inc-old",
            }
        ],
        [
            {
                "incident_id": "inc-old",
                "src_ip": "175.45.176.9",
                "attack_class": "dos",
                "targets": '["149.171.126.3"]',
                "first_seen_ms": 1,
                "last_seen_ms": 2,
                "n_alerts": 1,
                "max_score": 0.99,
                "mean_score": 0.99,
                "severity": "medium",
                "severity_reason": "база",
            }
        ],
    )
    # ответный поток класса anomaly в прогоне ансамбля — с «опасным» объяснением
    experts = {
        "anomaly": {"fired": True, "score": 0.999, "threshold": 0.98},
        "classifier": {"fired": False, "score": 0.2, "threshold": 0.7},
    }
    store.write_run(
        conn,
        {
            "run_id": "rev-run",
            "source": "split:unsw_time/test",
            "input_hash": "h2",
            "detector_version": s.detector_version,
            "started_at": "2020-01-02T00:00:00.000Z",
            "n_flows": 1,
            "summary": store.get_run(conn, s.run_id)["summary"],
        },
        [
            {
                "flow_uid": "rev/1",
                "capture_id": "c",
                "src_ip": "149.171.126.17",
                "src_port": 80,
                "dst_ip": "175.45.176.0",
                "dst_port": 40000,
                "protocol": 6,
                "first_seen_ms": 1,
                "last_seen_ms": 2,
                "predicted_class": "anomaly",
                "attack_score": 0.95,
                "incident_id": "inc-rev",
                "attacker_ip": "175.45.176.0",
                "victim_ip": "149.171.126.17",
                "reversed": 1,
                "fired_experts": "anomaly",
                "experts": json.dumps(experts),
                "explanation": "сработал только детектор " + XSS,
            }
        ],
        [
            {
                "incident_id": "inc-rev",
                "src_ip": "175.45.176.0",
                "attack_class": "anomaly",
                "targets": '["149.171.126.17"]',
                "first_seen_ms": 1,
                "last_seen_ms": 2,
                "n_alerts": 1,
                "max_score": 0.95,
                "mean_score": 0.95,
                "severity": "medium",
                "severity_reason": "база",
            }
        ],
    )
    conn.close()
    with TestClient(create_app(soc_cfg, detector_dir=tiny_ensemble), base_url=BASE) as c:
        yield c, s


def _probs(client, run_id, flow_uid):
    return client.get(f"/fragments/alerts/{quote(run_id)}/{flow_uid}/probs", headers=htmx())


def _first_alert(soc_cfg, run_id):
    conn = store.connect(soc_cfg.db)
    try:
        return store.recent_alerts(conn, run_id, 1)[0]
    finally:
        conn.close()


def test_experts_block(env, soc_cfg):
    client, s = env
    a = _first_alert(soc_cfg, s.run_id)
    page = soup(_probs(client, s.run_id, a["flow_uid"]))
    box = page.select_one("section.experts-box")
    assert box is not None
    # объяснение — первым после заголовка
    first = box.find("h3").find_next_sibling()
    assert "explanation" in first["class"] and first.get_text(strip=True)
    rows = box.select("table.experts-table tr[data-expert]")
    assert [r["data-expert"] for r in rows] == ["classifier", "anomaly"]
    text = box.get_text(" ", strip=True)
    assert "классификатор атак" in text and "детектор аномалий" in text
    assert "перцентиль нормы" in text and "Итоговый вердикт" in text and "ансамбль" in text
    # вероятности 003 — на месте
    assert page.select("table.probs-table tbody tr")


def test_old_run_note(env):
    client, _ = env
    r = _probs(client, "old-run", "old/1")
    assert r.status_code == 200
    text = soup(r).select_one("section.experts-box").get_text(" ", strip=True)
    assert "Прогон сделан до появления ансамбля: один детектор 20260924-886cf326" in text


def test_reversed_and_escaping(env):
    client, _ = env
    r = _probs(client, "rev-run", "rev/1")
    box = soup(r).select_one("section.experts-box")
    assert "Ответный поток: атакующая сторона — 175.45.176.0" in box.get_text(" ", strip=True)
    assert XSS not in r.text and "&lt;script&gt;" in r.text
    card = soup(client.get("/incidents/inc-rev"))
    row = card.select_one("tr[data-flow='rev/1']")
    assert row.select_one(".badge.reversed").get_text() == "ответный"
    assert row.select_one(".experts-short").get_text(strip=True) == "А"
    assert "аномалия (класс неизвестен)" in card.select_one(".facts").get_text()


def test_card_experts_summary_and_legend(env, soc_cfg):
    client, s = env
    conn = store.connect(soc_cfg.db)
    _, items = store.list_incidents(conn, {"run_id": s.run_id}, 1)
    conn.close()
    page = soup(client.get(f"/incidents/{items[0]['incident_id']}"))
    summary = page.select_one("#experts-summary")
    assert "Кто поднял алерты" in summary.get_text()
    assert "учтён у обоих" in summary.get_text()
    assert summary.select("li[data-expert]")
    heads = [th.get_text(strip=True) for th in page.select("table.alerts th")]
    assert "Эксперты" in heads
    legend = page.select_one(".legend").get_text(" ", strip=True)
    assert "К — классификатор атак" in legend and "М —" in legend
    old = soup(client.get("/incidents/inc-old")).select_one("#experts-summary")
    assert "до появления ансамбля" in old.get_text()


def test_filter_has_anomaly(env):
    client, _ = env
    options = soup(client.get("/incidents")).select("select[name=attack_class] option")
    assert any(
        o["value"] == "anomaly" and o.get_text() == "аномалия (класс неизвестен)" for o in options
    )


def test_dashboard_model_and_counters(env):
    client, s = env
    page = soup(client.get(f"/?run={s.run_id}"))
    box = page.select_one("#run-model")
    assert "Модель прогона" in box.get_text() and "ансамбль" in box.get_text()
    assert box.select("[data-counter^='expert:']")
    assert box.select_one("[data-counter='reversed']")["data-count"] == "0"
    old = soup(client.get("/?run=old-run"))
    assert "прогон до ансамбля" in old.get_text()


def test_no_inline_code(env, soc_cfg):
    client, s = env
    a = _first_alert(soc_cfg, s.run_id)
    for r in (
        client.get("/incidents/inc-rev"),
        _probs(client, s.run_id, a["flow_uid"]),
        client.get(f"/?run={s.run_id}"),
    ):
        page = soup(r)
        for sc in page.find_all("script"):
            assert sc.get("src", "").startswith("/static/") and not sc.get_text(strip=True)
        for el in page.find_all(True):
            assert "style" not in el.attrs
