"""Живое обновление (US4, FR-023–025): опрашиваемые контейнеры, ETag/204, баннер нового
прогона, штамп карточки. Сам опрос в браузере проверяется вручную (quickstart §6)."""

import json

from mlsiem.soc import store
from mlsiem.soc.run import run_chain
from ui.conftest import htmx, soup

POLLED = ("#incident-table", "#dashboard-counters", "#recent-alerts", "#runs-banner", "#stamp")


def _polled(page):
    return [el for el in page.select("[hx-trigger]") if "every" in el["hx-trigger"]]


def test_polled_containers_use_config_interval_and_hold_no_forms(ui_client, db, run, soc_cfg):
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 1)
    pages = [
        ui_client.get("/"),
        ui_client.get("/incidents"),
        ui_client.get(f"/incidents/{items[0]['incident_id']}"),
    ]
    seen = set()
    for r in pages:
        for el in _polled(soup(r)):
            assert el["hx-trigger"] == f"every {soc_cfg.ui.refresh_seconds}s"
            assert el.find("form") is None and el.find("textarea") is None
            seen.add("#" + el["id"])
    assert seen == set(POLLED)


def test_table_etag_204(ui_client, db, run):
    r = ui_client.get("/incidents", headers=htmx())
    etag = r.headers["ETag"]
    table = soup(r).select_one("#incident-table")
    # следующий опрос пришлёт его в If-None-Match
    assert json.loads(table["hx-headers"]) == {"If-None-Match": etag}
    same = ui_client.get("/incidents", headers=htmx(**{"If-None-Match": etag}))
    assert same.status_code == 204 and same.text == ""
    # другой вид (фильтр) — другой ETag
    other = ui_client.get("/incidents?severity=low", headers=htmx(**{"If-None-Match": etag}))
    assert other.status_code == 200
    # после решения — новое содержимое
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 1)
    store.change_status(db, items[0]["incident_id"], "vlad", "in_progress", None, None, 1)
    changed = ui_client.get("/incidents", headers=htmx(**{"If-None-Match": etag}))
    assert changed.status_code == 200 and changed.headers["ETag"] != etag


def test_dashboard_etag_204(ui_client, db, run):
    url = f"/fragments/dashboard?run={run.run_id}"
    etag = ui_client.get(url, headers=htmx()).headers["ETag"]
    assert ui_client.get(url, headers=htmx(**{"If-None-Match": etag})).status_code == 204
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 1)
    store.assign(db, items[0]["incident_id"], "vlad", "alice", 1)
    assert ui_client.get(url, headers=htmx(**{"If-None-Match": etag})).status_code == 200


def test_new_run_banner(ui_client, run, soc_cfg, synthetic_split, tiny_detector):
    url = f"/fragments/runs-banner?run={run.run_id}"
    assert soup(ui_client.get(url, headers=htmx())).select_one(".banner") is None
    # дашборд открыт без ?run — выбранный прогон зашит в адреса опроса
    page = soup(ui_client.get("/"))
    assert f"run={run.run_id}" in page.select_one("#dashboard-counters")["hx-get"]
    assert f"run={run.run_id}" in page.select_one("#runs-banner")["hx-get"]

    second = run_chain(
        "split:unsw_time/test",
        soc_cfg,
        detector_dir=tiny_detector,
        data_dir=synthetic_split,
        limit=300,
    )
    banner = soup(ui_client.get(url, headers=htmx())).select_one("#runs-banner .banner")
    assert "Появился новый прогон" in banner.get_text() and second.run_id in banner.get_text()
    assert banner.find("a", string="переключиться")["href"] == f"/?run={second.run_id}"
    # счётчики старого прогона по-прежнему про старый прогон
    old = soup(ui_client.get(f"/fragments/dashboard?run={run.run_id}", headers=htmx()))
    assert int(old.select_one("[data-counter=total]")["data-count"]) == run.n_incidents
    # у последнего прогона баннер пустой
    latest = f"/fragments/runs-banner?run={second.run_id}"
    assert soup(ui_client.get(latest, headers=htmx())).select_one(".banner") is None


def test_card_stamp(ui_client, db, run):
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 1)
    inc = store.get_incident(db, items[0]["incident_id"])
    page = soup(ui_client.get(f"/incidents/{inc['incident_id']}"))
    stamp_url = page.select_one("#stamp")["hx-get"]
    assert stamp_url.endswith("?v=1&av=1")
    r = ui_client.get(stamp_url, headers=htmx())
    assert soup(r).select_one("#stamp .banner") is None
    store.assign(db, inc["incident_id"], "anna", "anna", 1)
    bar = soup(ui_client.get(stamp_url, headers=htmx())).select_one("#stamp .banner")
    assert "изменён другим аналитиком" in bar.get_text()
    # то же — после решения по действию
    stamp2 = soup(ui_client.get(f"/incidents/{inc['incident_id']}")).select_one("#stamp")["hx-get"]
    assert soup(ui_client.get(stamp2, headers=htmx())).select_one(".banner") is None
    store.reject_action(db, inc["action"]["action_id"], "anna", 1, "нет")
    assert soup(ui_client.get(stamp2, headers=htmx())).select_one(".banner") is not None


def test_decisions_refresh_timeline(ui_client, db, run):
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 1)
    log = soup(ui_client.get(f"/incidents/{items[0]['incident_id']}")).select_one("#incident-log")
    assert log["hx-trigger"] == "incident-changed from:body"


def test_stale_bar_present_and_hidden(ui_client):
    bar = soup(ui_client.get("/")).select_one("#stale-bar")
    assert bar.has_attr("hidden") and "устаревшими" in bar.get_text()
