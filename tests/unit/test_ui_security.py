"""Безопасность консоли: имя аналитика в cookie, CSRF-токен, проверка источника запроса."""

import pytest
from starlette.requests import Request

from mlsiem.soc import store
from mlsiem.ui import security
from mlsiem.ui.security import ANALYST_COOKIE, CsrfGuard


def _request(headers: dict | None = None, cookies: dict | None = None, port: int = 8000):
    """Минимальный ASGI-запрос: только заголовки и адрес, больше проверкам ничего не нужно."""
    raw = [(k.lower().encode(), v.encode("latin-1")) for k, v in (headers or {}).items()]
    if cookies:
        raw.append((b"cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()).encode()))
    raw.append((b"host", f"127.0.0.1:{port}".encode()))
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/incidents/x/status",
        "headers": raw,
        "scheme": "http",
        "server": ("127.0.0.1", port),
        "query_string": b"",
    }
    return Request(scope)


# ---------------------------------------------------------------- имя аналитика


@pytest.mark.parametrize("name", ["vlad", "Влад", "Анна-Мария О'Коннор", "a" * 64, "<b>x</b>"])
def test_analyst_cookie_roundtrip(name):
    value = security.analyst_cookie(name)
    # В cookie только безопасные символы — URL-кодирование, кириллица переносится
    assert all(ch.isascii() and ch not in ' ;,"\\' for ch in value)
    assert security.read_analyst(_request(cookies={ANALYST_COOKIE: value})) == name


def test_analyst_name_trimmed():
    value = security.analyst_cookie("  vlad  ")
    assert security.read_analyst(_request(cookies={ANALYST_COOKIE: value})) == "vlad"


@pytest.mark.parametrize("bad", ["", "   ", "a" * 65, "vl\nad", "x\x00", "tab\there"])
def test_bad_analyst_name(bad):
    with pytest.raises(store.BadRequest):
        security.analyst_cookie(bad)


def test_no_cookie_or_broken_cookie():
    assert security.read_analyst(_request()) is None
    # Подделанное вручную значение с управляющим символом — как будто имени нет
    assert security.read_analyst(_request(cookies={ANALYST_COOKIE: "a%0Ab"})) is None


# ---------------------------------------------------------------- токен CSRF


def test_token_for_own_session_only():
    guard = CsrfGuard()
    s1, s2 = guard.new_session(), guard.new_session()
    assert s1 != s2 and len(s1) >= 43
    token = guard.issue(s1)
    assert guard.verify(s1, token) == "ok"
    assert guard.verify(s2, token) == "invalid"


def test_forged_signature():
    guard = CsrfGuard()
    s = guard.new_session()
    boot, ts, sig = guard.issue(s).split(".")
    forged = f"{boot}.{ts}.{'0' * len(sig)}"
    assert guard.verify(s, forged) == "invalid"
    # Подпись от другой метки времени не подходит (нельзя «продлить» токен)
    assert guard.verify(s, f"{boot}.{int(ts) + 100}.{sig}") == "invalid"
    for junk in ("", "abc", "a.b", "a.b.c.d", None):
        assert guard.verify(s, junk) == "invalid"


def test_token_expires_after_12h():
    now = [1_000_000.0]
    guard = CsrfGuard(clock=lambda: now[0])
    s = guard.new_session()
    token = guard.issue(s)
    now[0] += 12 * 3600 - 1
    assert guard.verify(s, token) == "ok"
    now[0] += 2
    assert guard.verify(s, token) == "stale"


def test_token_from_previous_process_is_stale():
    old, new = CsrfGuard(), CsrfGuard()
    s = old.new_session()
    assert new.verify(s, old.issue(s)) == "stale"


def test_no_session():
    guard = CsrfGuard()
    assert guard.verify(None, guard.issue(guard.new_session())) == "invalid"


# ---------------------------------------------------------------- источник запроса


@pytest.mark.parametrize(
    "headers, expected",
    [
        ({"Sec-Fetch-Site": "same-origin"}, True),
        ({"Sec-Fetch-Site": "cross-site"}, False),
        ({"Sec-Fetch-Site": "same-site"}, False),
        ({"Sec-Fetch-Site": "none"}, False),
        ({"Origin": "http://127.0.0.1:8000"}, True),
        ({"Origin": "http://localhost:8000"}, True),
        ({"Origin": "http://evil.example"}, False),
        ({"Origin": "http://127.0.0.1:9999"}, False),
        ({"Origin": "null"}, False),
        # Sec-Fetch-Site главнее: браузер, который его шлёт, честно сообщает источник
        ({"Sec-Fetch-Site": "cross-site", "Origin": "http://127.0.0.1:8000"}, False),
        ({}, None),
    ],
)
def test_origin_check(headers, expected):
    assert security.origin_ok(_request(headers)) is expected
