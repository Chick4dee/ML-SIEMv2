"""UI-тесты консоли: временная БД с прогоном на синтетике, TestClient и помощники.

Браузера здесь нет: всё, что решает сервер (какая страница или фрагмент, какая ошибка,
что оказалось в базе), проверяется через TestClient и разбор HTML (research R14).
Помощники ведут себя как страница консоли: берут CSRF-токен той же «сессии», шлют
`Origin` и `Sec-Fetch-Site: same-origin`, а для htmx — заголовок `HX-Request`.
"""

import json
from pathlib import Path

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from mlsiem.soc import store
from mlsiem.soc.api import create_app
from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.soc.run import run_chain
from mlsiem.ui.security import CSRF_COOKIE

REPO = Path(__file__).parents[2]
BASE = "http://127.0.0.1:8000"


@pytest.fixture
def soc_cfg(tmp_path):
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    return parse_soc_config(
        {**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs")}
    )


@pytest.fixture
def run(soc_cfg, synthetic_split, tiny_detector):
    return run_chain(
        "split:unsw_time/test", soc_cfg, detector_dir=tiny_detector, data_dir=synthetic_split
    )


@pytest.fixture
def app(soc_cfg, run, tiny_detector):
    return create_app(soc_cfg, detector_dir=tiny_detector)


@pytest.fixture
def ui_client(app):
    with TestClient(app, base_url=BASE) as c:
        yield c


@pytest.fixture
def other_client(app):
    """Второй аналитик — отдельный браузер со своими cookie, тот же сервер."""
    with TestClient(app, base_url=BASE) as c:
        yield c


@pytest.fixture
def empty_client(soc_cfg, tiny_detector):
    with TestClient(create_app(soc_cfg, detector_dir=tiny_detector), base_url=BASE) as c:
        yield c


@pytest.fixture
def db(soc_cfg, run):
    conn = store.connect(soc_cfg.db)
    yield conn
    conn.close()


# ---------------------------------------------------------------- помощники


def soup(response) -> BeautifulSoup:
    return BeautifulSoup(response.text, "html.parser")


def htmx(**extra) -> dict:
    return {"HX-Request": "true", **extra}


def csrf(client) -> str:
    """Токен формы для «сессии» этого клиента (как если бы его взяли со страницы)."""
    if not client.cookies.get(CSRF_COOKIE):
        client.get("/analyst")
    return client.app.state.csrf.issue(client.cookies.get(CSRF_COOKIE))


def post_form(client, url: str, data: dict, *, htmx_request: bool = True, token=True, **kw):
    headers = {"Origin": BASE, "Sec-Fetch-Site": "same-origin", **kw.pop("headers", {})}
    # пустое значение = «браузер этот заголовок не прислал»
    headers = {k: v for k, v in headers.items() if v}
    if htmx_request:
        headers["HX-Request"] = "true"
    body = dict(data)
    if token:
        body["csrf_token"] = csrf(client) if token is True else token
    return client.post(url, data=body, headers=headers, follow_redirects=False, **kw)


def login(client, name: str) -> None:
    r = post_form(client, "/analyst", {"name": name, "next": "/"}, htmx_request=False)
    assert r.status_code == 303, r.text


def incident_ids(response) -> list[str]:
    return [tr["data-incident"] for tr in soup(response).select("tr[data-incident]")]


def found_total(response) -> int:
    return int(soup(response).select_one("[data-total]")["data-total"])


def db_snapshot(conn) -> dict:
    """Всё, что могут изменить решения: для проверок «база не изменилась»."""
    return {
        t: [tuple(r) for r in conn.execute(f"SELECT * FROM {t} ORDER BY 1")]
        for t in ("incidents", "actions", "incident_history", "audit_log")
    }


def add_incident(
    conn,
    run_id: str,
    incident_id: str,
    *,
    src_ip: str = "10.20.30.40",
    targets: tuple[str, ...] = ("10.20.30.41",),
    attack_class: str = "dos",
    severity: str = "medium",
    n_alerts: int = 1,
    first_ms: int = 1_424_242_234_000,
    step_ms: int = 10,
    action: bool = True,
    assignee: str | None = None,
) -> dict:
    """Инцидент прямо в SQLite — для краевых случаев (тысячи алертов, спецсимволы и т. п.)."""
    at = store.now_iso()
    last_ms = first_ms + step_ms * max(n_alerts - 1, 0)
    conn.execute(
        "INSERT INTO incidents (incident_id, run_id, src_ip, attack_class, targets, "
        "first_seen_ms, last_seen_ms, n_alerts, max_score, mean_score, severity, "
        "severity_reason, created_at, updated_at, assignee) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0.99, 0.95, ?, 'тестовый инцидент', ?, ?, ?)",
        (
            incident_id,
            run_id,
            src_ip,
            attack_class,
            json.dumps(list(targets)),
            first_ms,
            last_ms,
            n_alerts,
            severity,
            at,
            at,
            assignee,
        ),
    )
    conn.executemany(
        "INSERT INTO alerts (alert_id, run_id, incident_id, flow_uid, capture_id, src_ip, "
        "src_port, dst_ip, dst_port, protocol, first_seen_ms, last_seen_ms, predicted_class, "
        "attack_score) VALUES (?, ?, ?, ?, 'cap', ?, 1000, ?, 80, 6, ?, ?, ?, 0.97)",
        [
            (
                f"{run_id}/{incident_id}-f{k}",
                run_id,
                incident_id,
                f"{incident_id}-f{k}",
                src_ip,
                targets[k % len(targets)],
                first_ms + step_ms * k,
                first_ms + step_ms * k + 5,
                attack_class,
            )
            for k in range(n_alerts)
        ],
    )
    if action:
        conn.execute(
            "INSERT INTO actions (action_id, incident_id, action_type, target, rule_id, "
            "rule_text) VALUES (?, ?, 'block_source_ip', ?, 'noisy_attack', 'шумная атака')",
            (f"act-{incident_id}", incident_id, src_ip),
        )
    return store.get_incident(conn, incident_id)


def add_run(conn, run_id: str, *, started_at: str | None = None, summary: dict | None = None):
    """Пустой прогон прямо в SQLite (для модульных тестов без детектора)."""
    at = started_at or store.now_iso()
    conn.execute(
        # Колонки перечислены явно: схема растёт от фичи к фиче (005 добавила режим сеанса)
        'INSERT INTO runs (run_id, source, input_hash, detector_version, "limit", started_at, '
        "finished_at, n_flows, n_alerts, n_incidents, summary, warnings) VALUES "
        "(?, 'split:test/test', 'h', 'det-1', NULL, ?, ?, 0, 0, 0, ?, '[]')",
        (run_id, at, at, json.dumps(summary or {})),
    )
