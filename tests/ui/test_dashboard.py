"""Обзорная панель (US4): счётчики совпадают с API и ведут ровно в свои списки (SC-004)."""

from mlsiem.soc import store
from ui.conftest import add_incident, add_run, found_total, htmx, soup


def counters(response) -> dict[str, tuple[int, str]]:
    return {
        a["data-counter"]: (int(a["data-count"]), a["href"])
        for a in soup(response).select("#dashboard-counters a[data-counter]")
    }


def test_every_counter_leads_to_same_count(ui_client, db, run):
    # разнообразим состояние: решения, назначение, помеченный источник
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 100)
    store.assign(db, items[0]["incident_id"], "vlad", "alice", 1)
    store.change_status(db, items[1]["incident_id"], "vlad", "closed", "confirmed", None, 1)
    store.confirm_action(db, items[2]["action"]["action_id"], "vlad", 1)
    add_incident(db, run.run_id, "victim", src_ip="149.171.126.14", targets=("1.1.1.1",))

    r = ui_client.get("/")
    assert r.status_code == 200
    got = counters(r)
    assert {"total", "actions_pending", "unassigned", "flagged"} <= set(got)
    assert any(k.startswith("status:") for k in got)
    assert any(k.startswith("severity:") for k in got)
    assert any(k.startswith("class:") for k in got)
    for key, (n, href) in got.items():
        listed = ui_client.get(href)
        assert found_total(listed) == n, (key, href)


def test_counters_match_api(ui_client, run):
    got = counters(ui_client.get("/"))
    api = ui_client.get("/api/v1/incidents", params={"run_id": run.run_id, "limit": 500}).json()
    assert got["total"][0] == api["total"] == run.n_incidents
    for status in store.INCIDENT_STATUSES:
        n = sum(1 for i in api["items"] if i["status"] == status)
        assert got[f"status:{status}"][0] == n
    pending = sum(1 for i in api["items"] if i["action"] and i["action"]["state"] == "proposed")
    assert got["actions_pending"][0] == pending
    flagged = sum(1 for i in api["items"] if i["flags"])
    assert got["flagged"][0] == flagged


def test_run_summary_and_recent_alerts(ui_client, db, run, soc_cfg):
    page = soup(ui_client.get("/"))
    summary = page.select_one(".run-summary").get_text(" ", strip=True)
    assert run.source in summary and run.detector_version in summary
    assert str(run.n_flows) in summary and str(run.n_alerts) in summary
    rows = page.select("#recent-alerts tbody tr")
    assert len(rows) == min(soc_cfg.ui.recent_alerts, run.n_alerts)
    expected = store.recent_alerts(db, run.run_id, soc_cfg.ui.recent_alerts)
    links = [tr.find("a")["href"] for tr in rows]
    assert links == [f"/incidents/{a['incident_id']}" for a in expected]


def test_empty_run(ui_client, db):
    add_run(db, "zzzz-empty", started_at="2099-01-01T00:00:00.000Z")
    r = ui_client.get("/?run=zzzz-empty")
    got = counters(r)
    assert {n for n, _ in got.values()} == {0}
    assert "все счётчики — нули" in soup(r).get_text()
    # без параметра — последний прогон, это он и есть
    assert counters(ui_client.get("/")) == got


def test_fragments(ui_client, run):
    r = ui_client.get(f"/fragments/dashboard?run={run.run_id}", headers=htmx())
    assert r.status_code == 200 and "<html" not in r.text
    assert soup(r).select_one("#dashboard-counters")
    r = ui_client.get(f"/fragments/recent-alerts?run={run.run_id}", headers=htmx())
    assert soup(r).select_one("#recent-alerts tbody tr")
    # без htmx — та же разметка внутри страницы (работает без JS)
    r = ui_client.get(f"/fragments/dashboard?run={run.run_id}")
    assert "<html" in r.text and soup(r).select_one("#dashboard-counters")


def test_empty_database(empty_client):
    r = empty_client.get("/")
    assert "uv run mlsiem soc run" in r.text
