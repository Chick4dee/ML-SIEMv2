"""Дополнения API v1 фичи 003 (contracts/api-v1-additions.md): только добавления."""

import pytest

from api.conftest import ANALYST, API
from mlsiem.soc import store


def first(client, **params):
    return client.get(f"{API}/incidents", params={"limit": 1, **params}).json()["items"][0]


def test_assign_and_unassign(client):
    inc = first(client)
    url = f"{API}/incidents/{inc['incident_id']}/assign"
    r = client.post(url, json={"assignee": "alice", "expected_version": 1}, headers=ANALYST)
    assert r.status_code == 200, r.text
    card = r.json()
    assert card["assignee"] == "alice" and card["version"] == 2
    assert card["history"][-1]["field"] == "assignee"
    r = client.post(url, json={"assignee": None, "expected_version": 2}, headers=ANALYST)
    assert r.json()["assignee"] is None
    r = client.post(url, json={"assignee": "", "expected_version": 3}, headers=ANALYST)
    assert r.status_code == 400 and r.json()["error"] == "bad_request"  # «снимать нечего»


def test_assign_errors(client):
    inc = first(client)
    url = f"{API}/incidents/{inc['incident_id']}/assign"
    r = client.post(url, json={"assignee": "x", "expected_version": 9}, headers=ANALYST)
    assert r.status_code == 409 and r.json()["error"] == "conflict"
    r = client.post(url, json={"assignee": "a" * 65, "expected_version": 1}, headers=ANALYST)
    assert r.status_code == 400
    r = client.post(url, json={"assignee": "x", "expected_version": 1})
    assert r.status_code == 400 and "X-Analyst" in r.json()["message"]
    r = client.post(
        f"{API}/incidents/nope/assign",
        json={"assignee": "x", "expected_version": 1},
        headers=ANALYST,
    )
    assert r.status_code == 404


def _ids(client, **params):
    return [
        i["incident_id"]
        for i in client.get(f"{API}/incidents", params={"limit": 500, **params}).json()["items"]
    ]


def test_new_list_params(client):
    everything = _ids(client)
    inc = first(client)
    client.post(
        f"{API}/incidents/{inc['incident_id']}/assign",
        json={"assignee": "alice", "expected_version": 1},
        headers=ANALYST,
    )
    assert _ids(client, assignee="alice") == [inc["incident_id"]]
    assert len(_ids(client, assignee="__none__")) == len(everything) - 1
    src = inc["src_ip"]
    assert inc["incident_id"] in _ids(client, src_ip=src)
    assert set(_ids(client, src_ip=src.rsplit(".", 1)[0] + ".0/24")) >= set(
        _ids(client, src_ip=src)
    )
    assert len(_ids(client, action_state="proposed")) == len(everything)
    assert _ids(client, action_state="executed") == []
    by_alerts = client.get(
        f"{API}/incidents", params={"sort": "n_alerts", "dir": "desc", "limit": 500}
    ).json()["items"]
    counts = [i["n_alerts"] for i in by_alerts]
    assert counts == sorted(counts, reverse=True)
    # без sort порядок прежний (002)
    assert _ids(client) == everything


def test_bad_src_ip(client):
    r = client.get(f"{API}/incidents", params={"src_ip": "999.1.1.1"})
    assert r.status_code == 400 and r.json()["error"] == "bad_request"


def test_assignee_and_flags_fields(client):
    item = first(client)
    assert "assignee" in item and item["flags"] == []
    card = client.get(f"{API}/incidents/{item['incident_id']}").json()
    assert card["assignee"] is None and card["flags"] == []


def test_flagged_filter_and_fields(client, soc_cfg, run):
    from ui.conftest import add_incident

    conn = store.connect(soc_cfg.db)
    add_incident(conn, run.run_id, "victim-src", src_ip="149.171.126.14", targets=("175.45.176.2",))
    conn.close()
    only = _ids(client, flagged="only", run_id=run.run_id)
    hide = _ids(client, flagged="hide", run_id=run.run_id)
    assert "victim-src" in only and "victim-src" not in hide
    assert set(only) | set(hide) == set(_ids(client, run_id=run.run_id))
    assert set(only).isdisjoint(hide)
    card = client.get(f"{API}/incidents/victim-src").json()
    kinds = {f["kind"] for f in card["flags"]}
    assert "network" in kinds
    net = next(f for f in card["flags"] if f["kind"] == "network")
    assert net["network_name"] == "жертвы UNSW-NB15" and net["role"] == "victims"
    assert "149.171.126.0/24" in net["explanation"]


def test_audit_event_assigned(client):
    inc = first(client)
    client.post(
        f"{API}/incidents/{inc['incident_id']}/assign",
        json={"assignee": "alice", "expected_version": 1},
        headers=ANALYST,
    )
    items = client.get(f"{API}/audit", params={"event": "incident_assigned"}).json()["items"]
    assert len(items) == 1 and items[0]["details"]["new"] == "alice"
    client.post(
        f"{API}/incidents/{inc['incident_id']}/status",
        json={"status": "in_progress", "expected_version": 2},
        headers=ANALYST,
    )
    last = client.get(f"{API}/audit", params={"incident_id": inc["incident_id"]}).json()["items"][
        -1
    ]
    assert last["details"]["assignee"] == "alice" and last["details"]["by_non_assignee"] is True


def test_run_summary_has_threshold(client):
    summary = client.get(f"{API}/runs").json()["items"][0]["summary"]
    assert 0 < summary["threshold"] < 1 and "benign" in summary["classes"]


@pytest.mark.parametrize(
    "path",
    ["/incidents/x/status", "/incidents/x/assign", "/actions/x/confirm", "/actions/x/reject"],
)
def test_no_cors_preflight(client, path):
    r = client.options(
        API + path,
        headers={
            "Origin": "http://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Analyst, Content-Type",
        },
    )
    # без разрешающего preflight браузер не отправит запрос с X-Analyst с чужого сайта
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}
