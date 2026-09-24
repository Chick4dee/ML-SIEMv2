"""Безопасность консоли: имя аналитика, защита от межсайтовых запросов, заголовки (R4, R7).

Почему всё это нужно на 127.0.0.1. «Локально» не значит «безопасно»: любая страница из
интернета, открытая в том же браузере, может отправить форму на `http://127.0.0.1:8000`, и
браузер честно её доставит. Без защиты чужой сайт мог бы подтвердить действие плейбука от
имени аналитика. Поэтому каждый изменяющий запрос консоли проходит две независимые проверки:

1. **Источник.** Современный браузер сам сообщает, откуда запрос: `Sec-Fetch-Site` (надёжнее
   всего) или `Origin`. Если источник назван и он не консоль — отказ сразу.
2. **Токен формы** (подписанный double-submit). У браузера есть cookie `mlsiem_csrf` со
   случайной «сессией»; токен в форме — HMAC этой сессии секретом процесса. Чужая страница
   не может прочитать ни cookie, ни токен со страницы консоли, а подделать подпись без
   секрета нельзя. Секрет живёт только в памяти: перезапуск сервера делает все старые токены
   «устаревшими» — аналитик увидит просьбу обновить страницу, а не загадочную ошибку.

Имя аналитика — просто cookie с URL-кодированием (кириллица в заголовках иначе не пройдёт).
Это не аутентификация (её в проекте нет), а подпись для журнала: кто принял решение.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import secrets
import time
from collections.abc import Callable
from typing import Literal
from urllib.parse import quote, unquote

from starlette.requests import Request
from starlette.responses import Response

from mlsiem.soc import store

log = logging.getLogger("mlsiem.ui.security")

ANALYST_COOKIE = "mlsiem_analyst"
CSRF_COOKIE = "mlsiem_csrf"
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
LOCAL_HOSTS = ("127.0.0.1", "localhost")
ANALYST_COOKIE_AGE = 365 * 24 * 3600
TOKEN_MAX_AGE = 12 * 3600
# base64url от 32 байт — 43 символа; всё остальное в cookie сессии считаем мусором
_SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")

MSG_FOREIGN = "запрос отклонён: он пришёл не со страницы консоли"
MSG_STALE = "страница устарела — обновите её (F5) и повторите действие"

Verdict = Literal["ok", "stale", "invalid"]


# ---------------------------------------------------------------- имя аналитика


def analyst_cookie(name: str) -> str:
    """Значение cookie для имени: проверенное имя в URL-кодировании (`Влад` → `%D0%92…`)."""
    return quote(store.clean_name(name), safe="")


def read_analyst(request: Request) -> str | None:
    """Имя текущего аналитика из cookie или None, если его нет или оно испорчено."""
    raw = request.cookies.get(ANALYST_COOKIE)
    if not raw:
        return None
    try:
        return store.clean_name(unquote(raw))
    except store.BadRequest:
        return None


def set_analyst(response: Response, name: str) -> None:
    response.set_cookie(
        ANALYST_COOKIE,
        analyst_cookie(name),
        max_age=ANALYST_COOKIE_AGE,
        path="/",
        samesite="strict",
    )


# ---------------------------------------------------------------- CSRF


class CsrfGuard:
    """Выпуск и проверка токенов форм.

    Формат токена: `<boot>.<ts>.<подпись>`. `boot` — случайный идентификатор запуска процесса:
    по нему отличаем «токен от прошлого запуска сервера» (честно устарел) от «подпись
    подделана» (атака). `ts` — время выпуска, подпись закрывает и сессию, и время, поэтому
    ни продлить токен, ни перенести его в другую сессию нельзя.
    """

    def __init__(
        self,
        secret: bytes | None = None,
        max_age: int = TOKEN_MAX_AGE,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._secret = secret or secrets.token_bytes(32)
        self.boot = secrets.token_hex(4)
        self.max_age = max_age
        self._clock = clock

    @staticmethod
    def new_session() -> str:
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()

    @staticmethod
    def session_of(request: Request) -> str | None:
        value = request.cookies.get(CSRF_COOKIE)
        return value if value and _SESSION_RE.match(value) else None

    def _sign(self, session: str, ts: int) -> str:
        msg = f"{self.boot}.{session}.{ts}".encode()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def issue(self, session: str, now: float | None = None) -> str:
        ts = int(self._clock() if now is None else now)
        return f"{self.boot}.{ts}.{self._sign(session, ts)}"

    def verify(self, session: str | None, token: str | None) -> Verdict:
        if not session or not token:
            return "invalid"
        parts = token.split(".")
        if len(parts) != 3 or not parts[1].isdigit():
            return "invalid"
        boot, ts_raw, sig = parts
        if boot != self.boot:
            # Токен выпустил прошлый запуск сервера: подделкой это не считаем
            return "stale"
        ts = int(ts_raw)
        if not hmac.compare_digest(sig, self._sign(session, ts)):
            return "invalid"
        if self._clock() - ts > self.max_age:
            return "stale"
        return "ok"

    def ensure_session(self, request: Request) -> tuple[str, bool]:
        """(сессия, нужно ли поставить cookie). Новая сессия — если cookie нет или он испорчен."""
        session = self.session_of(request)
        if session:
            return session, False
        return self.new_session(), True

    @staticmethod
    def set_session(response: Response, session: str) -> None:
        # Без max_age — cookie живёт до закрытия браузера; httponly: скриптам он не нужен,
        # токен для htmx берётся из разметки страницы
        response.set_cookie(CSRF_COOKIE, session, path="/", samesite="strict", httponly=True)


def allowed_origins(request: Request) -> set[str]:
    """Адреса самой консоли: 127.0.0.1 и localhost на том порту, куда пришёл запрос."""
    port = request.url.port
    suffix = f":{port}" if port else ""
    return {f"{request.url.scheme}://{host}{suffix}" for host in LOCAL_HOSTS}


def origin_ok(request: Request) -> bool | None:
    """True/False — браузер назвал источник и он свой/чужой; None — источник не назван."""
    site = request.headers.get("sec-fetch-site")
    if site:
        return site == "same-origin"
    origin = request.headers.get("origin")
    if origin:
        return origin in allowed_origins(request)
    return None


class CsrfRejected(Exception):
    """Изменяющий запрос не прошёл проверку; обработчик в routes отвечает 403 с фрагментом."""

    def __init__(self, message: str, *, stale: bool, form: dict | None = None) -> None:
        self.message = message
        self.stale = stale
        self.form = form or {}
        super().__init__(message)


async def check_request(request: Request, guard: CsrfGuard) -> None:
    """Обе проверки для POST консоли; при отказе — запись в лог и `CsrfRejected`.

    Форма читается здесь же: Starlette кеширует её, так что обработчик потом получит
    те же поля через `Form(...)` без повторного чтения тела.
    """
    form = await request.form()
    fields = {k: v for k, v in form.items() if isinstance(v, str) and k != CSRF_FIELD}
    source = origin_ok(request)
    reason: str | None = None
    stale = False
    if source is False:
        reason = "чужой источник"
    else:
        token = request.headers.get(CSRF_HEADER) or form.get(CSRF_FIELD)
        verdict = guard.verify(guard.session_of(request), token if isinstance(token, str) else None)
        if verdict == "stale":
            reason, stale = "устаревший токен", True
        elif verdict == "invalid":
            reason = "нет или неверный токен"
    if reason is None:
        return
    log.warning(
        "Отклонён изменяющий запрос (%s): %s %s, Origin=%r, Sec-Fetch-Site=%r",
        reason,
        request.method,
        request.url.path,
        request.headers.get("origin"),
        request.headers.get("sec-fetch-site"),
    )
    raise CsrfRejected(MSG_STALE if stale else MSG_FOREIGN, stale=stale, form=fields)


# ---------------------------------------------------------------- заголовки

SECURITY_HEADERS = {
    # Всё — только со своего адреса: никаких CDN, inline-скриптов и чужих фреймов.
    # frame-ancestors + X-Frame-Options — защита от кликджекинга кнопки «подтвердить»
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
}
# Swagger UI в /docs грузит скрипты с CDN — строгая CSP его сломала бы; API — это JSON
_NO_CSP_PREFIXES = ("/api/", "/docs", "/redoc", "/openapi.json")


def needs_security_headers(path: str) -> bool:
    return not path.startswith(_NO_CSP_PREFIXES)
