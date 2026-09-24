"""API: чтение — список с фильтрами и страницами, карточка, алерты, аудит, прогоны, health."""

from api.conftest import API

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def all_incidents(client, **params):
    r = client.get(f"{API}/incidents", params={"limit": 500, **params})
    assert r.status_code == 200, r.text
    return r.json()


def test_list_default_page_and_order(client, run):
    r = client.get(f"{API}/incidents")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == run.n_incidents
    assert len(body["items"]) == min(50, run.n_incidents)
    items = all_incidents(client)["items"]
    keys = [(SEV_RANK[i["severity"]], i["first_seen_ms"], i["incident_id"]) for i in items]
    assert keys == sorted(keys)
    first = items[0]
    for field in (
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
    ):
        assert field in first
    assert first["action"]["state"] == "proposed"


def test_pagination(client, run):
    total = run.n_incidents
    page1 = client.get(f"{API}/incidents", params={"limit": 2, "offset": 0}).json()
    page2 = client.get(f"{API}/incidents", params={"limit": 2, "offset": 2}).json()
    assert page1["total"] == page2["total"] == total
    ids = [i["incident_id"] for i in page1["items"] + page2["items"]]
    assert len(set(ids)) == len(ids)
    assert client.get(f"{API}/incidents", params={"limit": 501}).status_code == 422
    assert client.get(f"{API}/incidents", params={"limit": 0}).json()["error"] == "bad_request"


def test_filters(client, run):
    items = all_incidents(client)["items"]
    sev = items[0]["severity"]
    only = all_incidents(client, severity=sev)["items"]
    assert only and all(i["severity"] == sev for i in only)
    both = all_incidents(client, severity="critical,high")["items"]
    assert all(i["severity"] in ("critical", "high") for i in both)
    cls = items[0]["attack_class"]
    assert all(i["attack_class"] == cls for i in all_incidents(client, attack_class=cls)["items"])
    assert all_incidents(client, run_id=run.run_id)["total"] == run.n_incidents
    assert all_incidents(client, run_id="нет-такого")["total"] == 0
    assert all_incidents(client, status="new")["total"] == run.n_incidents
    assert all_incidents(client, status="closed")["total"] == 0
    bad = client.get(f"{API}/incidents", params={"severity": "extreme"})
    assert bad.status_code == 400 and bad.json()["error"] == "bad_request"


def test_time_filter_is_overlap(client):
    items = all_incidents(client)["items"]
    inc = items[0]
    mid = (inc["first_seen_ms"] + inc["last_seen_ms"]) // 2
    ids = {i["incident_id"] for i in all_incidents(client, from_ms=mid, to_ms=mid)["items"]}
    assert inc["incident_id"] in ids
    for i in all_incidents(client, from_ms=mid, to_ms=mid)["items"]:
        assert i["first_seen_ms"] <= mid <= i["last_seen_ms"]
    late = all_incidents(client, from_ms=max(i["last_seen_ms"] for i in items) + 1)
    assert late["total"] == 0


def test_card(client):
    inc = all_incidents(client)["items"][0]
    r = client.get(f"{API}/incidents/{inc['incident_id']}")
    assert r.status_code == 200
    card = r.json()
    for field in ("severity_reason", "max_score", "mean_score", "history"):
        assert field in card
    a = card["action"]
    for field in (
        "action_id",
        "rule_id",
        "rule_text",
        "state",
        "decided_by",
        "decided_at",
        "comment",
        "simulation",
        "version",
    ):
        assert field in a
    assert card["history"] == []


def test_alerts_paged_in_order(client):
    inc = max(all_incidents(client)["items"], key=lambda i: i["n_alerts"])
    r = client.get(f"{API}/incidents/{inc['incident_id']}/alerts", params={"limit": 500})
    body = r.json()
    assert body["total"] == inc["n_alerts"] == len(body["items"])
    keys = [(a["first_seen_ms"], a["flow_uid"]) for a in body["items"]]
    assert keys == sorted(keys)
    assert {a["incident_id"] for a in body["items"]} == {inc["incident_id"]}
    page = client.get(
        f"{API}/incidents/{inc['incident_id']}/alerts", params={"limit": 1, "offset": 1}
    )
    assert page.json()["items"][0]["flow_uid"] == body["items"][1]["flow_uid"]


def test_audit_filters_and_order(client, run):
    r = client.get(f"{API}/audit", params={"limit": 500})
    items = r.json()["items"]
    assert [e["entry_id"] for e in items] == sorted(e["entry_id"] for e in items)
    proposed = client.get(f"{API}/audit", params={"event": "action_proposed", "limit": 500}).json()
    assert proposed["total"] == run.n_incidents
    inc_id = proposed["items"][0]["incident_id"]
    by_inc = client.get(f"{API}/audit", params={"incident_id": inc_id}).json()
    assert by_inc["total"] >= 1 and all(e["incident_id"] == inc_id for e in by_inc["items"])
    assert (
        client.get(f"{API}/audit", params={"actor": "system"}).json()["total"]
        == run.n_incidents + 1
    )
    assert client.get(f"{API}/audit", params={"event": "nope"}).status_code == 400


def test_runs_and_health(client, run, tiny_detector):
    runs = client.get(f"{API}/runs").json()
    assert runs["total"] == 1 and runs["items"][0]["run_id"] == run.run_id
    assert runs["items"][0]["summary"]["incidents_by_severity"]
    h = client.get(f"{API}/health").json()
    assert h["status"] == "ok"
    assert h["detector_version"] == run.detector_version
    assert h["db"].endswith("soc.db")


def test_not_found(client):
    r = client.get(f"{API}/incidents/inc-000000000000")
    assert r.status_code == 404
    assert r.json()["error"] == "not_found" and "не найден" in r.json()["message"]
    assert client.get(f"{API}/incidents/inc-000000000000/alerts").status_code == 404
    r = client.post(
        f"{API}/actions/act-нет/confirm",
        json={"expected_version": 1},
        headers={"X-Analyst": "vlad"},
    )
    assert r.status_code == 404 and r.json()["error"] == "not_found"
