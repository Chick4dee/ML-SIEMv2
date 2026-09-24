"""Сквозные проверки страниц (FR-029, FR-030, FR-032, SC-007): без inline-кода и чужих адресов,
всё работает без JS, пользовательские данные выводятся текстом, htmx не подменён."""

import hashlib
import re
from pathlib import Path

import pytest

from mlsiem.soc import store
from ui.conftest import add_incident, login, post_form, soup

VENDOR = Path(__file__).parents[2] / "src" / "mlsiem" / "ui" / "static" / "vendor"
XSS = "<script>alert(1)</script>"


@pytest.fixture
def pages(ui_client, db, run):
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 1)
    return ["/", "/incidents", f"/incidents/{items[0]['incident_id']}", "/audit", "/analyst"]


def test_no_inline_code_and_only_local_assets(ui_client, pages):
    for url in pages:
        page = soup(ui_client.get(url))
        for s in page.find_all("script"):
            assert s.get("src", "").startswith("/static/"), (url, s)
            assert not s.get_text(strip=True), (url, "inline-скрипт")
        for el in page.find_all(True):
            on = [a for a in el.attrs if a.lower().startswith("on")]
            assert not on, (url, el.name, on)
            assert "style" not in el.attrs, (url, el.name, "inline style запрещён CSP")
            assert not any(a.startswith("hx-on") for a in el.attrs), (url, el.name)
        for link in page.find_all("link"):
            assert link["href"].startswith("/static/"), (url, link)
        assert page.find("style") is None
        # никаких внешних адресов в ресурсах
        for el in page.find_all(src=True):
            assert not re.match(r"^(https?:)?//", el["src"]), (url, el)


def test_works_without_js(ui_client, pages):
    for url in pages:
        page = soup(ui_client.get(url))
        for form in page.find_all("form"):
            if form.get("method") == "dialog":
                continue  # «отмена» в диалоге — встроенное поведение браузера
            assert form.get("method") in ("get", "post"), (url, form)
            assert form.get("action"), (url, form)
        for a in page.select(".pager a, th.sortable a, a[data-counter]"):
            assert a.get("href"), (url, a)
        for el in page.select("[hx-get]"):
            # каждый hx-get на ссылке или форме продублирован обычным href/action
            if el.name == "a":
                assert el.get("href"), (url, el)
            if el.name == "form":
                assert el.get("action"), (url, el)


def test_user_data_is_escaped(ui_client, db, run):
    add_incident(db, run.run_id, "xss", src_ip="10.9.9.9", targets=("10.9.9.10",))
    login(ui_client, XSS)
    r = post_form(ui_client, "/incidents/xss/assign", {"take": "1", "expected_version": "1"})
    assert r.status_code == 200
    post_form(
        ui_client,
        "/incidents/xss/status",
        {"status": "in_progress", "comment": XSS, "expected_version": "2"},
    )
    for url in ("/", "/incidents", "/incidents/xss", "/audit"):
        html = ui_client.get(url).text
        assert XSS not in html, url
        page = soup(ui_client.get(url))
        assert all(not s.get_text(strip=True) for s in page.find_all("script")), url
    card = ui_client.get("/incidents/xss").text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in card
    # в шапке, истории, хронологии и журнале — текстом
    page = soup(ui_client.get("/incidents/xss"))
    assert page.select_one(".analyst-name").get_text() == XSS
    assert XSS in page.select_one("#incident-log table.history").get_text()
    assert XSS in page.select_one("ol.timeline").get_text()
    assert XSS in soup(ui_client.get("/audit")).select_one("#audit-table").get_text()


def test_long_targets_shortened(ui_client, db, run):
    targets = tuple(f"10.8.{i // 250}.{i % 250}" for i in range(200))
    add_incident(db, run.run_id, "wide", targets=targets)
    row = soup(ui_client.get("/incidents?src=10.20.30.40")).select_one("tr[data-incident=wide]")
    details = row.select_one("details.long")
    assert details.find("summary").get_text() == "10.8.0.0, 10.8.0.1, 10.8.0.2 и ещё 197"
    card = soup(ui_client.get("/incidents/wide")).select_one(".summary details.long summary")
    assert "и ещё 195" in card.get_text()


def test_vendored_htmx_matches_readme():
    readme = (VENDOR / "README.md").read_text(encoding="utf-8")
    recorded = re.search(r"SHA-256 `htmx\.min\.js`: `([0-9a-f]{64})`", readme).group(1)
    actual = hashlib.sha256((VENDOR / "htmx.min.js").read_bytes()).hexdigest()
    assert actual == recorded, "htmx.min.js изменён — обновите версию и хеш в README вендоринга"
    assert (VENDOR / "LICENSE-htmx.txt").read_text(encoding="utf-8").startswith("Zero-Clause BSD")


def test_static_served(ui_client):
    for path in ("/static/console.css", "/static/console.js", "/static/vendor/htmx.min.js"):
        r = ui_client.get(path)
        assert r.status_code == 200 and len(r.content) > 100, path
