"""Решения аналитика из консоли (US2): назначение, статус, действие, ошибки, вопросы."""

import pytest

from mlsiem.soc import store
from ui.conftest import db_snapshot, login, post_form, soup


@pytest.fixture
def inc(db, run):
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 1, sort="severity")
    return store.get_incident(db, items[0]["incident_id"])


def url(inc, what):
    return f"/incidents/{inc['incident_id']}/{what}"


def aurl(inc, what):
    return f"/actions/{inc['action']['action_id']}/{what}"


def fresh(db, inc):
    return store.get_incident(db, inc["incident_id"])


# ---------------------------------------------------------------- имя аналитика


def test_analyst_cookie_and_next(ui_client):
    r = post_form(ui_client, "/analyst", {"name": "Влад", "next": "/audit?x=1"}, htmx_request=False)
    assert r.status_code == 303 and r.headers["location"] == "/audit?x=1"
    header = soup(ui_client.get("/")).select_one(".analyst-name").get_text()
    assert header == "Влад"


@pytest.mark.parametrize("bad_next", ["https://evil.example/", "//evil.example", "/\\evil"])
def test_external_next_ignored(ui_client, bad_next):
    r = post_form(ui_client, "/analyst", {"name": "vlad", "next": bad_next}, htmx_request=False)
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_bad_analyst_name(ui_client):
    r = post_form(ui_client, "/analyst", {"name": "a" * 65, "next": "/"}, htmx_request=False)
    assert r.status_code == 400
    assert "64" in soup(r).select_one(".error").get_text()


# ---------------------------------------------------------------- назначение


def test_take_assign_unassign(ui_client, db, inc):
    login(ui_client, "vlad")
    r = post_form(ui_client, url(inc, "assign"), {"take": "1", "expected_version": "1"})
    assert r.status_code == 200 and r.headers["HX-Trigger"] == "incident-changed"
    assert "<html" not in r.text and soup(r).select_one("#decisions")
    assert fresh(db, inc)["assignee"] == "vlad"
    assert soup(r).select_one(".assignee").get_text() == "vlad"

    r = post_form(ui_client, url(inc, "assign"), {"assignee": "alice", "expected_version": "2"})
    assert fresh(db, inc)["assignee"] == "alice"
    r = post_form(ui_client, url(inc, "assign"), {"assignee": "", "expected_version": "3"})
    card = fresh(db, inc)
    assert card["assignee"] is None
    assert [h["new"] for h in card["history"]] == ["vlad", "alice", None]
    # список показывает ответственного
    login(ui_client, "vlad")
    post_form(ui_client, url(inc, "assign"), {"take": "1", "expected_version": "4"})
    row = soup(ui_client.get("/incidents")).select_one(f"tr[data-incident='{inc['incident_id']}']")
    assert "vlad" in row.get_text()


# ---------------------------------------------------------------- статус


def test_in_progress_then_close(ui_client, db, inc):
    login(ui_client, "vlad")
    r = post_form(ui_client, url(inc, "status"), {"status": "in_progress", "expected_version": "1"})
    assert r.status_code == 200 and fresh(db, inc)["status"] == "in_progress"
    r = post_form(
        ui_client,
        url(inc, "status"),
        {
            "status": "closed",
            "resolution": "false_positive",
            "comment": "ответное направление",
            "expected_version": "2",
        },
    )
    card = fresh(db, inc)
    assert (card["status"], card["resolution"]) == ("closed", "false_positive")
    assert card["history"][-1]["comment"] == "ответное направление"
    page = soup(r)
    # у закрытого инцидента нет формы статуса, но форма назначения есть
    assert page.select_one("#panel-status form") is None
    assert page.select_one("#panel-assign form") is not None


def test_close_without_resolution_keeps_comment(ui_client, db, inc):
    login(ui_client, "vlad")
    before = db_snapshot(db)
    r = post_form(
        ui_client,
        url(inc, "status"),
        {"status": "closed", "comment": "мой текст", "expected_version": "1"},
    )
    assert r.status_code == 400
    page = soup(r)
    assert "резолюция" in page.select_one("#panel-status .error").get_text()
    assert page.select_one("#panel-status textarea[name=comment]").get_text() == "мой текст"
    assert db_snapshot(db) == before


def test_status_form_offers_only_allowed(ui_client, db, inc):
    login(ui_client, "vlad")
    page = soup(ui_client.get(f"/incidents/{inc['incident_id']}"))
    statuses = {i["value"] for i in page.select("#panel-status input[name=status]")}
    assert statuses == {"in_progress", "closed"}
    radios = page.select("#panel-status input[name=resolution]")
    assert {r["value"] for r in radios} == set(store.RESOLUTIONS)
    assert all(r.has_attr("required") for r in radios)
    post_form(ui_client, url(inc, "status"), {"status": "in_progress", "expected_version": "1"})
    page = soup(ui_client.get(f"/incidents/{inc['incident_id']}"))
    assert {i["value"] for i in page.select("#panel-status input[name=status]")} == {"closed"}


# ---------------------------------------------------------------- действие


def test_confirm_asks_first(ui_client, db, inc):
    login(ui_client, "vlad")
    before = db_snapshot(db)
    r = post_form(ui_client, aurl(inc, "confirm"), {"expected_version": "1", "comment": "да"})
    assert r.status_code == 200
    dialog = soup(r).select_one("dialog[data-modal]")
    text = dialog.get_text(" ", strip=True)
    assert "заблокировать адрес источника" in text and inc["action"]["target"] in text
    assert "симулируется" in text
    assert db_snapshot(db) == before
    # форма вопроса повторяет поля и добавляет ack_action
    hidden = {i["name"]: i["value"] for i in dialog.select("input[type=hidden]")}
    assert hidden["ack_action"] == "1" and hidden["comment"] == "да"
    assert hidden["expected_version"] == "1" and hidden["csrf_token"]

    r = post_form(
        ui_client,
        aurl(inc, "confirm"),
        {"expected_version": "1", "comment": "да", "ack_action": "1"},
    )
    assert r.status_code == 200
    action = fresh(db, inc)["action"]
    assert action["state"] == "executed" and action["decided_by"] == "vlad"
    panel = soup(r).select_one("#panel-action")
    assert "Реальных изменений в сети и на хостах не было" in panel.get_text()
    assert action["simulation"]["description"] in panel.get_text()
    assert panel.select("form") == []  # после решения кнопок нет


def test_reject_needs_comment(ui_client, db, inc):
    login(ui_client, "vlad")
    r = post_form(ui_client, aurl(inc, "reject"), {"expected_version": "1", "reject": "1"})
    assert r.status_code == 400
    assert "комментарий" in soup(r).select_one("#panel-action .error").get_text()
    r = post_form(
        ui_client,
        aurl(inc, "reject"),
        {"expected_version": "1", "reject": "1", "comment": "это фон"},
    )
    assert r.status_code == 200 and fresh(db, inc)["action"]["state"] == "rejected"
    assert soup(r).select("#panel-action form") == []


def test_repeated_decision_is_invalid_transition(ui_client, db, inc):
    login(ui_client, "vlad")
    store.reject_action(db, inc["action"]["action_id"], "bob", 1, "нет")
    r = post_form(ui_client, aurl(inc, "confirm"), {"expected_version": "2", "ack_action": "1"})
    assert r.status_code == 409
    assert "решение уже принято" in soup(r).select_one("#panel-action .error").get_text()


def test_conflict_shows_fresh_state_and_keeps_input(ui_client, other_client, db, inc):
    login(ui_client, "vlad")
    login(other_client, "anna")
    # anna успела первой
    post_form(other_client, url(inc, "status"), {"status": "in_progress", "expected_version": "1"})
    r = post_form(
        ui_client,
        url(inc, "status"),
        {
            "status": "closed",
            "resolution": "confirmed",
            "comment": "мой вывод",
            "expected_version": "1",
        },
    )
    assert r.status_code == 409
    page = soup(r)
    assert "изменён кем-то ещё" in page.select_one("#panel-status .error").get_text()
    # актуальное состояние + форма на новой версии с сохранённым комментарием
    assert "в работе" in page.select_one(".state-line").get_text()
    form = page.select_one("#panel-status form input[value=closed]").find_parent("form")
    assert form.select_one("input[name=expected_version]")["value"] == "2"
    assert form.select_one("textarea").get_text() == "мой вывод"
    assert "повторить на новой версии" in form.select_one("button").get_text()
    assert form.select_one("input[value=confirmed]").has_attr("checked")


def test_no_analyst_name(ui_client, db, inc):
    before = db_snapshot(db)
    r = post_form(ui_client, url(inc, "status"), {"status": "in_progress", "expected_version": "1"})
    assert r.status_code == 401
    page = soup(r)
    assert "представьтесь" in page.select_one("#panel-status .error").get_text()
    assert page.select_one("#panel-status a[href^='/analyst']") is not None
    assert db_snapshot(db) == before


@pytest.mark.parametrize("kind", ["status", "confirm", "reject"])
def test_not_assignee_warning(ui_client, db, inc, kind):
    store.assign(db, inc["incident_id"], "system", "alice", 1)
    login(ui_client, "bob")
    target, data = {
        "status": (url(inc, "status"), {"status": "in_progress", "expected_version": "2"}),
        "confirm": (aurl(inc, "confirm"), {"expected_version": "1", "ack_action": "1"}),
        "reject": (aurl(inc, "reject"), {"expected_version": "1", "comment": "нет"}),
    }[kind]
    before = db_snapshot(db)
    r = post_form(ui_client, target, data)
    assert r.status_code == 200
    dialog = soup(r).select_one("dialog[data-modal]").get_text("", strip=False)
    assert "Ответственный — alice. Всё равно продолжить?" in " ".join(dialog.split())
    assert db_snapshot(db) == before
    r = post_form(ui_client, target, {**data, "ack_not_assignee": "1"})
    assert r.status_code == 200 and r.headers["HX-Trigger"] == "incident-changed"
    last = store.incident_audit(db, inc["incident_id"])[-1]
    assert last["actor"] == "bob"
    assert last["details"]["by_non_assignee"] is True and last["details"]["assignee"] == "alice"


def test_assignee_decides_without_warning(ui_client, db, inc):
    store.assign(db, inc["incident_id"], "system", "alice", 1)
    login(ui_client, "alice")
    r = post_form(ui_client, url(inc, "status"), {"status": "in_progress", "expected_version": "2"})
    assert r.status_code == 200 and fresh(db, inc)["status"] == "in_progress"
    assert store.incident_audit(db, inc["incident_id"])[-1]["details"]["by_non_assignee"] is False


def test_without_htmx_redirects_to_card(ui_client, db, inc):
    login(ui_client, "vlad")
    r = post_form(
        ui_client,
        url(inc, "status"),
        {"status": "in_progress", "expected_version": "1"},
        htmx_request=False,
    )
    assert r.status_code == 303 and r.headers["location"] == f"/incidents/{inc['incident_id']}"
    # ошибка без htmx — вся карточка с сообщением
    r = post_form(
        ui_client,
        url(inc, "status"),
        {"status": "closed", "expected_version": "2"},
        htmx_request=False,
    )
    assert r.status_code == 400 and "<html" in r.text and "резолюция" in r.text


def test_forms_have_plain_action(ui_client, inc):
    login(ui_client, "vlad")
    page = soup(ui_client.get(f"/incidents/{inc['incident_id']}"))
    forms = page.select("#decisions form")
    assert forms
    for f in forms:
        assert f["method"] == "post" and f["action"] == f["hx-post"]
        assert f.select_one("input[name=csrf_token]")["value"]
        assert f.select_one("input[name=expected_version]")["value"].isdigit()
