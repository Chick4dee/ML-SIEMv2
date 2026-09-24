"""Список инцидентов (US1): порядок, колонки, фильтры, фрагменты htmx, пустые состояния."""

import pytest

from mlsiem.soc import store
from mlsiem.soc.run import run_chain
from ui.conftest import found_total, htmx, incident_ids, soup

COLUMNS = [
    "Серьёзность",
    "Статус",
    "Резолюция",
    "Класс",
    "Источник",
    "Цели",
    "Алертов",
    "Начало",
    "Последний алерт",
    "Ответственный",
    "Действие",
]


def store_ids(db, run_id, sort="severity", direction="desc", **filters):
    _, items = store.list_incidents(
        db, {"run_id": run_id, **filters}, 1000, sort=sort, direction=direction
    )
    return [i["incident_id"] for i in items]


def test_default_view(ui_client, db, run):
    r = ui_client.get("/incidents")
    assert r.status_code == 200
    page = soup(r)
    assert page.find("html") is not None
    headers = [
        th.get_text(" ", strip=True).rstrip(" ↓↑") for th in page.select("table.incidents th")
    ]
    assert headers == COLUMNS
    # последний прогон; серьёзность ↓, затем время начала ↓
    assert incident_ids(r) == store_ids(db, run.run_id)
    first = store.get_incident(db, incident_ids(r)[0])
    assert first["severity"] == "high"
    assert found_total(r) == run.n_incidents
    row = page.select_one("tr[data-incident]")
    cells = [td.get_text(" ", strip=True) for td in row.find_all("td")]
    assert cells[0] == "высокая" and cells[1] == "новый"
    assert "UTC" in cells[7] and "UTC" in cells[8]
    assert cells[10] == "ждёт решения"


@pytest.mark.parametrize(
    "query, filters",
    [
        ("status=new", {"status": ["new"]}),
        ("severity=medium,low", {"severity": ["medium", "low"]}),
        ("attack_class=dos", {"attack_class": "dos"}),
        ("src=175.45.176.3", {"src_ip": "175.45.176.3"}),
        ("src=175.45.176.0/30", {"src_ip": "175.45.176.0/30"}),
        ("assignee=__none__", {"assignee": "__none__"}),
        ("action_state=proposed", {"action_state": ["proposed"]}),
        ("severity=medium&attack_class=dos&src=175.45.176.2", None),
    ],
)
def test_each_filter_matches_store(ui_client, db, run, query, filters):
    if filters is None:
        filters = {"severity": ["medium"], "attack_class": "dos", "src_ip": "175.45.176.2"}
    expected = store_ids(db, run.run_id, **filters)
    r = ui_client.get(f"/incidents?{query}")
    assert incident_ids(r) == expected
    assert found_total(r) == len(expected)
    # фрагмент htmx — тот же результат, но без обёртки страницы
    f = ui_client.get(f"/incidents?{query}", headers=htmx())
    assert "<html" not in f.text and incident_ids(f) == expected


@pytest.mark.parametrize("sort", ["severity", "first_seen", "last_seen", "n_alerts"])
@pytest.mark.parametrize("direction", ["asc", "desc"])
def test_sorts(ui_client, db, run, sort, direction):
    r = ui_client.get(f"/incidents?sort={sort}&dir={direction}", headers=htmx())
    assert incident_ids(r) == store_ids(db, run.run_id, sort, direction)


def test_filters_form_works_without_js(ui_client):
    form = soup(ui_client.get("/incidents")).select_one("form.filters")
    assert form["method"] == "get" and form["action"] == "/incidents"
    assert form["hx-get"] == "/incidents" and form["hx-push-url"] == "true"
    assert "change" in form["hx-trigger"]
    assert form.find("button", attrs={"type": "submit"}).get_text(strip=True) == "показать"
    for th_link in soup(ui_client.get("/incidents")).select("th.sortable a"):
        assert th_link["href"].startswith("/incidents?") and th_link["hx-get"] == th_link["href"]


def test_pagination_links(ui_client, soc_cfg, db, run):
    from ui.conftest import add_incident

    for k in range(60):
        add_incident(db, run.run_id, f"extra-{k:02d}", severity="low")
    r = ui_client.get("/incidents")
    assert len(incident_ids(r)) == soc_cfg.ui.page_size == 50
    nxt = soup(r).select_one(".pager a[rel=next]")
    assert nxt["href"] == f"/incidents?run={run.run_id}&page=2"
    r2 = ui_client.get(nxt["href"])
    assert len(incident_ids(r2)) == 60 + run.n_incidents - 50
    assert soup(r2).select_one(".pager a[rel=prev]") is not None


def test_empty_filter_result(ui_client):
    r = ui_client.get("/incidents?src=8.8.8.8")
    page = soup(r)
    assert incident_ids(r) == [] and found_total(r) == 0
    empty = page.select_one("#incident-table .empty")
    assert "ни один" in empty.get_text() and empty.find("a", string="Сбросить фильтры")


def test_bad_params_warn(ui_client, db, run):
    r = ui_client.get("/incidents?severity=ultra&src=999.1.1.1&page=-2&sort=drop&attack_class=dos")
    warnings = [w.get_text() for w in soup(r).select("#incident-table .warning")]
    assert len(warnings) == 4
    assert incident_ids(r) == store_ids(db, run.run_id, attack_class="dos")


def test_run_switch(ui_client, db, run, soc_cfg, synthetic_split, tiny_detector):
    second = run_chain(
        "split:unsw_time/test",
        soc_cfg,
        detector_dir=tiny_detector,
        data_dir=synthetic_split,
        limit=200,
    )
    latest = ui_client.get("/incidents")
    assert set(incident_ids(latest)) == set(store_ids(db, second.run_id))
    old = ui_client.get(f"/incidents?run={run.run_id}")
    assert set(incident_ids(old)) == set(store_ids(db, run.run_id))
    assert set(incident_ids(old)).isdisjoint(incident_ids(latest))
    option = soup(old).select_one("select[name=run] option[selected]")
    assert option["value"] == run.run_id


def test_empty_database(empty_client):
    for url in ("/", "/incidents"):
        r = empty_client.get(url)
        assert r.status_code == 200
        text = soup(r).get_text(" ")
        assert "Прогонов пока нет" in text
        assert "uv run mlsiem soc run --split unsw_time --part test" in text
