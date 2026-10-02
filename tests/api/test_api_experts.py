"""API: только добавления фичи 004 (contracts/api-v1-additions.md, FR-018, FR-020).

В базе два прогона: новый — ансамблем, и «старый» — записанный так, как писал 002/003 (без
полей экспертов). Новые поля у старого прогона — null (кроме атакующей стороны, которую
миграция заполнила из src/dst), а все поля 002/003 на месте у обоих.
"""

import pytest
from fastapi.testclient import TestClient

from mlsiem.soc import store
from mlsiem.soc.api import create_app
from mlsiem.soc.run import run_chain

API = "/api/v1"

# Поля ответов 002/003 — «снимок», которого клиенты старых фич вправе ждать
ALERT_KEYS_002 = {
    "alert_id",
    "run_id",
    "incident_id",
    "flow_uid",
    "capture_id",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "first_seen_ms",
    "last_seen_ms",
    "predicted_class",
    "attack_score",
}
ALERT_KEYS_004 = {"attacker_ip", "victim_ip", "reversed", "experts", "fired_experts", "explanation"}
CARD_KEYS_003 = {
    "incident_id",
    "run_id",
    "src_ip",
    "attack_class",
    "targets",
    "first_seen_ms",
    "last_seen_ms",
    "n_alerts",
    "severity",
    "status",
    "resolution",
    "action",
    "version",
    "assignee",
    "flags",
    "severity_reason",
    "max_score",
    "mean_score",
    "created_at",
    "updated_at",
    "history",
}
RUN_KEYS_002 = {
    "run_id",
    "source",
    "input_hash",
    "detector_version",
    "limit",
    "started_at",
    "finished_at",
    "n_flows",
    "n_alerts",
    "n_incidents",
    "summary",
    "warnings",
    "incidents_by_status",
}
# Фича 005 (contracts/api-ui-additions.md) добавила к тем же ответам поля сеанса и потока;
# у пакетных прогонов они со значениями по умолчанию (batch/completed/null/0)
RUN_KEYS_005 = {"mode", "status", "source_id", "last_activity_at"}
CARD_KEYS_005 = {"merged_into", "alerts_after_decision", "first_after_decision_ms"}
# Фича 007 (contracts/api-ui-additions.md): вид алерта и окно, число алертов окон у
# инцидента, раздел «эксперт окон» у прогона — тоже только добавления
ALERT_KEYS_007 = {"kind", "window"}
CARD_KEYS_007 = {"n_window_alerts"}
RUN_KEYS_007 = {"windows"}


def _old_run(cfg) -> str:
    """Прогон «как писал 002»: алерты без полей 004, в сводке нет модели."""
    conn = store.connect(cfg.db)
    store.init_db(conn)
    alert = {
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
    incident = {
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
    store.write_run(
        conn,
        {
            "run_id": "old-run",
            "source": "split:unsw_time/test",
            "input_hash": "h",
            "detector_version": "20260924-886cf326",
            "started_at": "2026-09-24T00:00:00.000Z",
            "n_flows": 1,
            "summary": {"threshold": 0.98},
        },
        [alert],
        [incident],
    )
    conn.close()
    return "old-run"


@pytest.fixture
def ens_client(soc_cfg, synthetic_split, tiny_ensemble):
    s = run_chain(
        "split:unsw_time/test", soc_cfg, model_dir=tiny_ensemble, data_dir=synthetic_split
    )
    _old_run(soc_cfg)
    with TestClient(create_app(soc_cfg, detector_dir=tiny_ensemble)) as c:
        yield c, s


def _first_incident(client, run_id):
    return client.get(f"{API}/incidents", params={"run_id": run_id}).json()["items"][0]


def test_alert_fields_new_run(ens_client):
    client, s = ens_client
    inc = _first_incident(client, s.run_id)
    items = client.get(f"{API}/incidents/{inc['incident_id']}/alerts").json()["items"]
    for a in items:
        assert set(a) == ALERT_KEYS_002 | ALERT_KEYS_004 | ALERT_KEYS_007
        assert isinstance(a["reversed"], bool)
        assert set(a["experts"]) == {"classifier", "anomaly"}
        assert isinstance(a["fired_experts"], list)
        assert a["explanation"]
        assert a["attacker_ip"] == inc["src_ip"]


def test_alert_fields_old_run(ens_client):
    client, _ = ens_client
    (a,) = client.get(f"{API}/incidents/inc-old/alerts").json()["items"]
    assert set(a) == ALERT_KEYS_002 | ALERT_KEYS_004 | ALERT_KEYS_007
    assert a["experts"] is None and a["fired_experts"] is None and a["explanation"] is None
    assert (a["attacker_ip"], a["victim_ip"], a["reversed"]) == (a["src_ip"], a["dst_ip"], False)


def test_experts_summary(ens_client):
    client, s = ens_client
    inc = _first_incident(client, s.run_id)
    card = client.get(f"{API}/incidents/{inc['incident_id']}").json()
    assert CARD_KEYS_003 | {"experts_summary"} | CARD_KEYS_005 | CARD_KEYS_007 == set(card)
    es = card["experts_summary"]
    assert es["available"] is True
    assert set(es["by_expert"]) <= {"classifier", "anomaly"}
    assert sum(c["n_alerts"] for c in es["combinations"]) == card["n_alerts"]
    assert "учитывается у каждого" in es["note"]
    old = client.get(f"{API}/incidents/inc-old").json()["experts_summary"]
    assert old["available"] is False
    assert "до появления ансамбля" in old["note"] and "20260924-886cf326" in old["note"]


def test_runs_model(ens_client):
    client, s = ens_client
    runs = {r["run_id"]: r for r in client.get(f"{API}/runs").json()["items"]}
    for r in runs.values():
        assert RUN_KEYS_002 | {"model"} | RUN_KEYS_005 | RUN_KEYS_007 == set(r)
    new = runs[s.run_id]["model"]
    assert new["kind"] == "ensemble" and new["selected"] == "ensemble:stack_logreg"
    assert set(new["experts"]) == {"classifier", "anomaly"}
    assert runs["old-run"]["model"] == {
        "kind": "detector",
        "version": "20260924-886cf326",
        "selected": None,
        "experts": None,
    }


def test_anomaly_filter_accepted(ens_client):
    client, s = ens_client
    r = client.get(f"{API}/incidents", params={"attack_class": "anomaly", "run_id": s.run_id})
    assert r.status_code == 200
    assert all(i["attack_class"] == "anomaly" for i in r.json()["items"])


def test_health_reports_ensemble_version(ens_client, tiny_ensemble):
    import json

    client, _ = ens_client
    card = json.loads((tiny_ensemble / "ensemble_card.json").read_text(encoding="utf-8"))
    assert client.get(f"{API}/health").json()["detector_version"] == card["ensemble_version"]
