"""Защита от межсайтовых запросов (FR-029a, SC-009): каждый POST консоли — только со страниц
самой консоли. Чужой источник, нет токена, чужой или старый токен → 403, база не меняется,
попытка — в логе `mlsiem.ui.security`."""

import logging
import time

import pytest

from mlsiem.soc import store
from mlsiem.ui.security import CSRF_COOKIE
from ui.conftest import BASE, db_snapshot, login, post_form, soup


@pytest.fixture
def targets(db, run, ui_client):
    """(адрес, поля формы) для каждого изменяющего запроса консоли — валидные сами по себе."""
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 3, sort="severity")
    a, b, c = items
    login(ui_client, "vlad")
    return [
        ("/analyst", {"name": "mallory", "next": "/"}),
        (f"/incidents/{a['incident_id']}/assign", {"take": "1", "expected_version": "1"}),
        (
            f"/incidents/{c['incident_id']}/status",
            {"status": "in_progress", "expected_version": "1"},
        ),
        (
            f"/actions/{b['action']['action_id']}/confirm",
            {"expected_version": "1", "ack_action": "1"},
        ),
        (
            f"/actions/{c['action']['action_id']}/reject",
            {"expected_version": "1", "reject": "1", "comment": "атака чужого сайта"},
        ),
    ]


def _other_session_token(ui_client):
    return ui_client.app.state.csrf.issue(ui_client.app.state.csrf.new_session())


def _expired_token(ui_client):
    guard = ui_client.app.state.csrf
    return guard.issue(ui_client.cookies.get(CSRF_COOKIE), now=time.time() - 13 * 3600)


ATTACKS = {
    # пустой Sec-Fetch-Site = «браузер его не прислал»: решает Origin
    "foreign_origin": dict(headers={"Origin": "http://evil.example", "Sec-Fetch-Site": ""}),
    "cross_site": dict(headers={"Sec-Fetch-Site": "cross-site"}),
    "no_token": dict(token=False),
    "other_session": dict(token="other"),
    "expired": dict(token="expired"),
}


@pytest.mark.parametrize("attack", list(ATTACKS))
def test_rejected_without_changes(ui_client, db, targets, caplog, attack):
    for url, data in targets:
        kw = dict(ATTACKS[attack])
        if kw.get("token") == "other":
            kw["token"] = _other_session_token(ui_client)
        elif kw.get("token") == "expired":
            kw["token"] = _expired_token(ui_client)
        before = db_snapshot(db)
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="mlsiem.ui.security"):
            r = post_form(ui_client, url, data, **kw)
        assert r.status_code == 403, (url, attack, r.text[:300])
        text = soup(r).get_text(" ", strip=True)
        if attack == "expired":
            assert "страница устарела — обновите её" in text
        else:
            assert "не со страницы консоли" in text
        assert db_snapshot(db) == before, (url, attack)
        assert any(
            rec.name == "mlsiem.ui.security" and url in rec.getMessage() for rec in caplog.records
        ), (url, attack)
    # имя аналитика не подменено чужой формой
    assert soup(ui_client.get("/")).select_one(".analyst-name").get_text() == "vlad"


def test_honest_requests_pass(ui_client, db, targets):
    for url, data in targets[1:]:
        r = post_form(ui_client, url, data)
        assert r.status_code == 200, (url, r.text[:300])
    r = post_form(ui_client, targets[0][0], targets[0][1], htmx_request=False)
    assert r.status_code == 303


def test_token_in_header_works(ui_client, db, targets):
    # htmx шлёт токен заголовком X-CSRF-Token (hx-headers на <body>), а не полем формы
    from ui.conftest import csrf

    url, data = targets[2]
    r = post_form(ui_client, url, data, token=False, headers={"X-CSRF-Token": csrf(ui_client)})
    assert r.status_code == 200


def test_no_origin_headers_token_decides(ui_client, targets):
    url, data = targets[2]
    r = ui_client.post(
        url,
        data={**data, "csrf_token": _other_session_token(ui_client)},
        headers={"HX-Request": "true"},
    )
    assert r.status_code == 403


def test_stale_keeps_comment(ui_client, targets):
    url, data = targets[4]
    r = post_form(ui_client, url, data, token=_expired_token(ui_client))
    assert r.status_code == 403
    assert soup(r).select_one("#panel-action textarea[required]").get_text() == data["comment"]


def test_security_headers_on_pages(ui_client, db, run):
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 1)
    for url in ("/", "/incidents", f"/incidents/{items[0]['incident_id']}", "/audit", "/analyst"):
        r = ui_client.get(url)
        assert r.headers["Content-Security-Policy"] == "default-src 'self'; frame-ancestors 'none'"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert r.headers["Referrer-Policy"] == "same-origin"
    # у JSON API и документации — без CSP консоли (Swagger UI грузит скрипты с CDN)
    assert "Content-Security-Policy" not in ui_client.get("/api/v1/health").headers


def test_base_url_is_local(ui_client):
    assert BASE.startswith("http://127.0.0.1")
