"""API: изменения — X-Analyst, статусы, подтверждение/отклонение, конфликты, формат ошибок."""

import re

import pytest

from api.conftest import ANALYST, API

CYRILLIC = re.compile("[а-яА-ЯёЁ]")


def first_incident(client):
    return client.get(f"{API}/incidents", params={"limit": 1}).json()["items"][0]


def assert_error(r, status, code):
    assert r.status_code == status, r.text
    body = r.json()
    assert set(body) == {"error", "message"}
    assert body["error"] == code
    assert CYRILLIC.search(body["message"]), "сообщение об ошибке должно быть по-русски"


@pytest.mark.parametrize("headers", [{}, {"X-Analyst": ""}, {"X-Analyst": "   "}])
def test_post_requires_analyst(client, headers):
    inc = first_incident(client)
    r = client.post(
        f"{API}/incidents/{inc['incident_id']}/status",
        json={"status": "in_progress", "expected_version": 1},
        headers=headers,
    )
    assert_error(r, 400, "bad_request")
    r = client.post(
        f"{API}/actions/{inc['action']['action_id']}/confirm",
        json={"expected_version": 1},
        headers=headers,
    )
    assert_error(r, 400, "bad_request")


def test_status_flow_and_history(client):
    inc = first_incident(client)
    url = f"{API}/incidents/{inc['incident_id']}/status"
    r = client.post(url, json={"status": "in_progress", "expected_version": 1}, headers=ANALYST)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "in_progress" and r.json()["version"] == 2
    r = client.post(
        url,
        json={
            "status": "closed",
            "resolution": "false_positive",
            "comment": "сканер",
            "expected_version": 2,
        },
        headers=ANALYST,
    )
    card = r.json()
    assert r.status_code == 200
    assert card["status"] == "closed" and card["resolution"] == "false_positive"
    assert [h["field"] for h in card["history"]] == ["status", "status", "resolution"]
    assert all(h["analyst"] == "vlad" for h in card["history"])
    again = client.get(f"{API}/incidents/{inc['incident_id']}").json()
    assert again["history"] == card["history"]


def test_close_without_resolution(client):
    inc = first_incident(client)
    r = client.post(
        f"{API}/incidents/{inc['incident_id']}/status",
        json={"status": "closed", "expected_version": 1},
        headers=ANALYST,
    )
    assert_error(r, 400, "bad_request")


def test_reopen_closed_is_invalid(client):
    inc = first_incident(client)
    url = f"{API}/incidents/{inc['incident_id']}/status"
    client.post(
        url,
        json={"status": "closed", "resolution": "confirmed", "expected_version": 1},
        headers=ANALYST,
    )
    r = client.post(url, json={"status": "in_progress", "expected_version": 2}, headers=ANALYST)
    assert_error(r, 409, "invalid_transition")


def test_unknown_status_value(client):
    inc = first_incident(client)
    r = client.post(
        f"{API}/incidents/{inc['incident_id']}/status",
        json={"status": "new", "expected_version": 1},
        headers=ANALYST,
    )
    assert_error(r, 422, "bad_request")


def test_confirm_action(client):
    inc = first_incident(client)
    action_id = inc["action"]["action_id"]
    r = client.post(
        f"{API}/actions/{action_id}/confirm", json={"expected_version": 1}, headers=ANALYST
    )
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["state"] == "executed" and a["decided_by"] == "vlad"
    assert a["simulation"]["simulated"] is True
    audit = client.get(f"{API}/audit", params={"incident_id": inc["incident_id"]}).json()["items"]
    assert [e["event"] for e in audit] == ["action_proposed", "action_executed"]
    assert audit[1]["actor"] == "vlad"
    r = client.post(
        f"{API}/actions/{action_id}/confirm", json={"expected_version": 2}, headers=ANALYST
    )
    assert_error(r, 409, "invalid_transition")


def test_reject_needs_comment(client):
    action_id = first_incident(client)["action"]["action_id"]
    url = f"{API}/actions/{action_id}/reject"
    assert_error(
        client.post(url, json={"expected_version": 1}, headers=ANALYST), 400, "bad_request"
    )
    assert_error(
        client.post(url, json={"expected_version": 1, "comment": " "}, headers=ANALYST),
        400,
        "bad_request",
    )
    r = client.post(url, json={"expected_version": 1, "comment": "ложная тревога"}, headers=ANALYST)
    assert r.status_code == 200 and r.json()["state"] == "rejected"


def test_stale_version_conflict(client):
    inc = first_incident(client)
    r = client.post(
        f"{API}/actions/{inc['action']['action_id']}/confirm",
        json={"expected_version": 5},
        headers=ANALYST,
    )
    assert_error(r, 409, "conflict")
    r = client.post(
        f"{API}/incidents/{inc['incident_id']}/status",
        json={"status": "in_progress", "expected_version": 9},
        headers=ANALYST,
    )
    assert_error(r, 409, "conflict")
    assert client.get(f"{API}/incidents/{inc['incident_id']}").json()["version"] == 1


def test_missing_expected_version(client):
    inc = first_incident(client)
    r = client.post(f"{API}/actions/{inc['action']['action_id']}/confirm", json={}, headers=ANALYST)
    assert_error(r, 422, "bad_request")


@pytest.mark.parametrize("method", ["put", "patch", "delete"])
def test_audit_is_read_only(client, method):
    r = getattr(client, method)(f"{API}/audit")
    assert r.status_code == 405
    assert r.json()["error"] == "bad_request"
