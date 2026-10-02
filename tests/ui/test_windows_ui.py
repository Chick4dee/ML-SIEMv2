"""Консоль: алерты окон (фича 007, US3, contracts/api-ui-additions.md «Консоль»).

База с двумя прогонами одной синтетики: с экспертом окон (`force`, модель tiny_windows) и
«до 007» (без раздела windows в сводке). Проверяется то, что решает сервер: метки, блок окна,
переключатель, значок и фильтр списка, панель эксперта окон и блок «Окна» сеанса.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mlsiem.soc import store
from mlsiem.soc.api import create_app
from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.soc.run import run_chain

from .conftest import BASE, htmx, soup

REPO = Path(__file__).parents[2]


@pytest.fixture(scope="module")
def env(tmp_path_factory, tiny_detector, tiny_windows, synthetic_split):
    tmp = tmp_path_factory.mktemp("ui_windows")
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    cfg = parse_soc_config({**raw, "db": str(tmp / "soc.db"), "runs_dir": str(tmp / "runs")})
    common = {"model_dir": tiny_detector, "data_dir": synthetic_split}
    old = run_chain("split:unsw_time/val", cfg, windows_mode="off", **common)
    new = run_chain(
        "split:unsw_time/test",
        cfg,
        windows_mode="force",
        windows_model=tiny_windows,
        **common,
    )
    conn = store.connect(cfg.db)
    with store.transaction(conn):
        conn.execute(
            "UPDATE runs SET summary = json_remove(summary, '$.windows') WHERE run_id = ?",
            (old.run_id,),
        )
    inc = conn.execute(
        "SELECT i.incident_id FROM incidents i WHERE i.run_id = ? AND EXISTS (SELECT 1 FROM "
        "alerts a WHERE a.incident_id = i.incident_id AND a.alert_kind = 'window') "
        "ORDER BY i.incident_id LIMIT 1",
        (new.run_id,),
    ).fetchone()[0]
    conn.close()
    with TestClient(create_app(cfg, detector_dir=tiny_detector), base_url=BASE) as c:
        yield {"client": c, "cfg": cfg, "new": new, "old": old, "incident": inc}


def test_card_labels_and_window_block(env):
    c = env["client"]
    page = soup(c.get(f"/incidents/{env['incident']}"))
    rows = page.select("#alerts tr[data-kind]")
    kinds = {r["data-kind"] for r in rows}
    assert "window" in kinds
    win = page.select_one("#alerts tr[data-kind=window]")
    assert win.select_one(".badge.window").get_text(strip=True) == "окно"
    # Не одиночная «О»: моноширинным шрифтом она читается как ноль экспертов
    experts = win.select_one(".experts-short")
    assert experts.get_text(strip=True) == "Ок"
    assert experts["title"] == "эксперт окон"
    block = win.select_one("details.window-details")
    text = block.get_text(" ", strip=True)
    for needle in ("Интервал окна (UTC)", "Потоков в окне", "Портов назначения", "Цели"):
        assert needle in text, needle
    assert block.select_one("table.window-flows") is not None
    assert block.select_one("table.window-features") is not None  # у бустинга есть вклады
    for r in page.select("#alerts tr[data-kind=flow]"):
        assert r.select_one(".badge.flow").get_text(strip=True) == "поток"


def test_kind_switch(env):
    c = env["client"]
    inc = env["incident"]
    page = soup(c.get(f"/incidents/{inc}"))
    links = {a["data-kind"]: a for a in page.select(".kind-switch a")}
    assert set(links) == {"flow", "window"}  # «все» — текущий вид, без ссылки
    only_w = soup(c.get(links["window"]["hx-get"], headers=htmx()))
    assert {r["data-kind"] for r in only_w.select("tr[data-kind]")} == {"window"}
    only_f = soup(c.get(f"/fragments/incidents/{inc}/alerts?kind=flow", headers=htmx()))
    assert {r["data-kind"] for r in only_f.select("tr[data-kind]")} <= {"flow"}
    full = soup(c.get(f"/incidents/{inc}?alerts_kind=window"))
    assert {r["data-kind"] for r in full.select("#alerts tr[data-kind]")} == {"window"}
    # кривой вид — просто «все», без ошибки
    assert c.get(f"/fragments/incidents/{inc}/alerts?kind=zzz", headers=htmx()).status_code == 200


def test_histogram_colors_windows(env):
    page = soup(env["client"].get(f"/incidents/{env['incident']}"))
    assert page.select(".histogram rect.bar.window")


def test_list_badge_and_filter(env):
    c = env["client"]
    run_id = env["new"].run_id
    page = soup(c.get(f"/incidents?run={run_id}"))
    assert page.select(".badge.window")
    assert page.select_one("input[name=windows][value=only]") is not None
    only = soup(c.get(f"/incidents?run={run_id}&windows=only"))
    rows = only.select("tr[data-incident]")
    assert rows and all(r.select_one(".badge.window") for r in rows)
    bad = c.get(f"/incidents?run={run_id}&windows=maybe")
    assert "фильтр «есть алерты окон» не применён" in bad.text


def test_dashboard_windows_panel(env):
    c = env["client"]
    new = soup(c.get(f"/?run={env['new'].run_id}")).select_one("#run-windows")
    assert new["data-windows"] == "forced"
    assert "принудительно" in new.get_text()
    assert new.select_one("[data-counter=window_alerts]") is not None
    old = soup(c.get(f"/?run={env['old'].run_id}")).select_one("#run-windows")
    assert old["data-windows"] == "none"
    assert "прогон до детектора окон" in old.get_text()


def test_old_run_card_opens(env):
    """FR-017: прогон до 007 открывается без ошибок: только потоки, без переключателя."""
    c = env["client"]
    conn = store.connect(env["cfg"].db)
    inc = conn.execute(
        "SELECT incident_id FROM incidents WHERE run_id = ? LIMIT 1", (env["old"].run_id,)
    ).fetchone()[0]
    conn.close()
    r = c.get(f"/incidents/{inc}")
    assert r.status_code == 200
    page = soup(r)
    assert page.select_one(".kind-switch") is None
    assert {x["data-kind"] for x in page.select("#alerts tr[data-kind]")} == {"flow"}


def test_stream_panel_windows_block(env):
    """У сеанса с экспертом окон — блок «Окна» с четырьмя показателями."""
    c = env["client"]
    run_id = env["new"].run_id
    conn = store.connect(env["cfg"].db)
    with store.transaction(conn):
        conn.execute(
            "UPDATE runs SET mode = 'stream', status = 'running' WHERE run_id = ?", (run_id,)
        )
    conn.close()
    try:
        panel = soup(c.get(f"/fragments/stream-panel?run={run_id}", headers=htmx()))
        block = panel.select_one("[data-stream=windows]")
        assert block is not None
        for key in ("open-windows", "closed-windows", "window-alerts", "window-late"):
            assert block.select_one(f"[data-stream={key}]") is not None, key
    finally:
        conn = store.connect(env["cfg"].db)
        with store.transaction(conn):
            conn.execute(
                "UPDATE runs SET mode = 'batch', status = 'completed' WHERE run_id = ?", (run_id,)
            )
        conn.close()
