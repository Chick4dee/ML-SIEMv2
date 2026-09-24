"""Журнал аудита (US5): новые сверху, по-русски, фильтры как в store, только чтение."""

import pytest

from mlsiem.soc import store
from ui.conftest import htmx, soup


@pytest.fixture
def decided(db, run):
    """Несколько решений разных аналитиков — чтобы журналу было что показать."""
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 3, sort="severity")
    a, b, c = items
    store.assign(db, a["incident_id"], "vlad", "alice", 1, "тебе")
    store.change_status(db, a["incident_id"], "bob", "in_progress", None, "смотрю", 2)
    store.confirm_action(db, a["action"]["action_id"], "alice", 1)
    store.reject_action(db, b["action"]["action_id"], "vlad", 1, "это фон")
    store.change_status(db, c["incident_id"], "vlad", "closed", "false_positive", None, 1)
    return a, b, c


def entry_ids(response):
    return [int(tr["data-entry"]) for tr in soup(response).select("tr[data-entry]")]


def test_newest_first_in_russian(ui_client, db, decided):
    r = ui_client.get("/audit")
    assert r.status_code == 200
    ids = entry_ids(r)
    assert ids == sorted(ids, reverse=True)
    total, _ = store.list_audit(db, {}, 1)
    assert int(soup(r).select_one("[data-total]")["data-total"]) == total
    text = soup(r).get_text(" ", strip=True)
    for phrase in (
        "назначение ответственного",
        "ответственный: — → alice",
        "смена статуса",
        "статус: новый → в работе",
        "действие подтверждено (симуляция)",
        "реальных изменений сети не было",
        "действие отклонено",
        "это фон",
        "решение принято не ответственным (ответственный — alice)",
        "резолюция: — → ложное срабатывание",
        "загружен прогон",
    ):
        assert phrase in text, phrase
    # время UTC, автор, ссылка на инцидент
    row = soup(r).select_one("tr[data-event=incident_assigned]")
    cells = row.find_all("td")
    assert cells[1].get_text().endswith("UTC") and cells[2].get_text() == "vlad"
    assert cells[4].find("a")["href"] == f"/incidents/{decided[0]['incident_id']}"


@pytest.mark.parametrize(
    "query, filters",
    [
        ("actor=vlad", {"actor": "vlad"}),
        ("event=incident_assigned", {"event": "incident_assigned"}),
        ("event=action_executed", {"event": "action_executed"}),
        (None, None),  # по инциденту — подставляется в тесте
        (
            "actor=vlad&event=incident_status_changed",
            {"actor": "vlad", "event": "incident_status_changed"},
        ),
    ],
)
def test_filters_match_store(ui_client, db, run, decided, query, filters):
    if query is None:
        iid = decided[0]["incident_id"]
        query, filters = f"incident={iid}", {"incident_id": iid}
    _, expected = store.list_audit(db, filters, 1000, newest_first=True)
    r = ui_client.get(f"/audit?{query}")
    assert entry_ids(r) == [e["entry_id"] for e in expected]
    frag = ui_client.get(f"/audit?{query}", headers=htmx())
    assert "<html" not in frag.text and entry_ids(frag) == entry_ids(r)


def test_run_filter(ui_client, db, run, decided):
    _, expected = store.list_audit(db, {"run_id": run.run_id}, 1000, newest_first=True)
    assert entry_ids(ui_client.get(f"/audit?run={run.run_id}")) == [e["entry_id"] for e in expected]
    assert entry_ids(ui_client.get("/audit?run=nope")) == []


def test_unknown_event_warns(ui_client, db, decided):
    r = ui_client.get("/audit?event=hacked&actor=vlad")
    warning = soup(r).select_one("#audit-table .warning").get_text()
    assert "событие" in warning and "hacked" in warning
    _, expected = store.list_audit(db, {"actor": "vlad"}, 1000, newest_first=True)
    assert entry_ids(r) == [e["entry_id"] for e in expected]


def test_pagination(ui_client, db, run, soc_cfg):
    for k in range(soc_cfg.ui.page_size + 5):
        store.append_audit(db, "bot", "run_loaded", run_id=run.run_id, details={"k": k})
    r = ui_client.get("/audit?actor=bot")
    assert len(entry_ids(r)) == soc_cfg.ui.page_size
    nxt = soup(r).select_one(".pager a[rel=next]")
    assert nxt["href"] == "/audit?actor=bot&page=2"
    assert len(entry_ids(ui_client.get(nxt["href"]))) == 5


def test_read_only(ui_client, db, decided):
    page = soup(ui_client.get("/audit"))
    # единственная форма — фильтры GET; ни одной кнопки изменения
    forms = page.select("main form")
    assert [f["method"] for f in forms] == ["get"]
    buttons = [b.get_text(strip=True) for b in page.select("main button")]
    assert buttons == ["показать"]
    before = store.list_audit(db, {}, 1000)
    for method in ("post", "put", "delete", "patch"):
        r = getattr(ui_client, method)("/audit")
        assert r.status_code == 405, method
    assert store.list_audit(db, {}, 1000) == before
