"""Карточка инцидента (US1): сводка, действие, алерты постранично, вероятности, гистограмма,
хронология, аудит, 404."""

import json
from urllib.parse import quote

import polars as pl

from mlsiem.soc import store
from ui.conftest import add_incident, htmx, soup


def top_incident(db, run):
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 1, sort="severity")
    return store.get_incident(db, items[0]["incident_id"])


def test_card_content(ui_client, db, run):
    inc = top_incident(db, run)
    r = ui_client.get(f"/incidents/{inc['incident_id']}")
    assert r.status_code == 200
    page = soup(r)
    text = page.get_text(" ", strip=True)
    facts = page.select_one(".summary").get_text(" ", strip=True)
    assert inc["src_ip"] in facts and inc["attack_class"] in facts
    for t in inc["targets"][:5]:
        assert t in facts
    assert str(inc["n_alerts"]) in facts and "UTC" in facts
    assert inc["severity_reason"] in facts and "высокая" in facts
    panel = page.select_one("#decisions").get_text(" ", strip=True)
    assert "новый" in panel and "не назначен" in panel
    action = inc["action"]
    assert action["rule_id"] in panel and action["rule_text"] in panel
    assert "ждёт решения" in panel
    # аудит инцидента: предложение плейбука уже есть
    audit_rows = page.select("#incident-log table.audit tr[data-entry]")
    assert len(audit_rows) == len(store.incident_audit(db, inc["incident_id"])) >= 1
    assert "плейбук предложил действие" in text


def test_history_and_audit_after_decisions(ui_client, db, run):
    inc = top_incident(db, run)
    store.assign(db, inc["incident_id"], "vlad", "alice", 1, "тебе")
    store.change_status(db, inc["incident_id"], "bob", "in_progress", None, "беру", 2)
    page = soup(ui_client.get(f"/incidents/{inc['incident_id']}"))
    history = page.select("#incident-log table.history tbody tr")
    assert len(history) == 2
    assert "ответственный" in history[0].get_text() and "alice" in history[0].get_text()
    assert "новый → в работе" in history[1].get_text(" ", strip=True)
    log = page.select_one("#incident-log").get_text(" ", strip=True)
    assert "не ответственный" in log  # bob решал при ответственном alice


def test_alerts_paged_on_huge_incident(ui_client, db, run, soc_cfg):
    add_incident(db, run.run_id, "huge", n_alerts=5000, first_ms=0, step_ms=20)
    r = ui_client.get("/incidents/huge")
    page = soup(r)
    rows = page.select("#alerts table.alerts tbody tr")
    assert len(rows) == soc_cfg.ui.alerts_page_size
    assert "5000" in page.select_one("#alerts .count").get_text()
    bars = page.select(".histogram svg rect.bar")
    assert len(bars) == 40
    assert sum(int(b.find("title").get_text().split()[0]) for b in bars) == 5000
    # следующая страница — отдельным фрагментом и обычной ссылкой
    nxt = page.select_one("#alerts .pager a[rel=next]")
    assert nxt["href"] == "/incidents/huge?alerts_page=2#alerts"
    frag = ui_client.get(nxt["hx-get"], headers=htmx())
    assert "<html" not in frag.text
    second = soup(frag).select("tbody tr")
    assert len(second) == soc_cfg.ui.alerts_page_size
    assert second[0]["data-flow"] == "huge-f50"


def test_alert_context_columns(ui_client, db, run):
    inc = top_incident(db, run)
    _, alerts = store.list_alerts(db, inc["incident_id"], 1)
    a = alerts[0]
    row = soup(ui_client.get(f"/incidents/{inc['incident_id']}")).select_one(
        f"tr[data-flow='{a['flow_uid']}']"
    )
    text = row.get_text(" ", strip=True)
    assert f"{a['src_ip']}:{a['src_port']}" in text and f"{a['dst_ip']}:{a['dst_port']}" in text
    assert a["predicted_class"] in text and "UTC" in text


def probs_url(a):
    return f"/fragments/alerts/{quote(a['run_id'])}/{quote(a['flow_uid'])}/probs"


def test_probabilities(ui_client, db, run, soc_cfg, tiny_detector):
    inc = top_incident(db, run)
    _, alerts = store.list_alerts(db, inc["incident_id"], 1)
    a = alerts[0]
    r = ui_client.get(probs_url(a), headers=htmx())
    assert r.status_code == 200 and "<html" not in r.text
    page = soup(r)
    card = json.loads((tiny_detector / "model_card.json").read_text(encoding="utf-8"))
    classes = [td.get_text() for td in page.select("tbody tr td:first-child")]
    assert sorted(classes) == sorted(card["classes"])
    row = pl.read_parquet(soc_cfg.runs_dir / run.run_id / "verdicts.parquet").filter(
        pl.col("flow_uid") == a["flow_uid"]
    )
    values = [float(td.get_text().split()[-1]) for td in page.select("tbody tr td:last-child")]
    assert values == sorted(values, reverse=True)
    assert max(values) == round(max(row.select(pl.col("^p_.*$")).row(0)), 4)
    assert f"{card['threshold']:.4f}" in page.get_text() and "порог превышен" in page.get_text()
    # раскрытие алерта в карточке ведёт ровно на этот фрагмент, а без JS — обычной ссылкой
    details = soup(ui_client.get(f"/incidents/{inc['incident_id']}")).select_one(
        f"tr[data-flow='{a['flow_uid']}'] details"
    )
    assert details["hx-get"] == probs_url(a) and details["hx-trigger"] == "toggle once"
    assert details.find("a")["href"] == probs_url(a)


def test_threshold_for_old_run(ui_client, db, run, soc_cfg):
    inc = top_incident(db, run)
    a = store.list_alerts(db, inc["incident_id"], 1)[1][0]
    # прогон «до 003»: порога в сводке нет, детектор тот же — порог из карточки модели
    db.execute("UPDATE runs SET summary = '{}' WHERE run_id = ?", (run.run_id,))
    text = soup(ui_client.get(probs_url(a), headers=htmx())).get_text()
    assert "карточки детектора" in text
    # детектор прогона заменён — порог неизвестен, но вероятности показаны
    db.execute("UPDATE runs SET detector_version = 'other' WHERE run_id = ?", (run.run_id,))
    text = soup(ui_client.get(probs_url(a), headers=htmx())).get_text()
    assert "порог неизвестен" in text


def test_no_verdicts_file(ui_client, db, run, soc_cfg):
    inc = top_incident(db, run)
    a = store.list_alerts(db, inc["incident_id"], 1)[1][0]
    (soc_cfg.runs_dir / run.run_id / "verdicts.parquet").unlink()
    r = ui_client.get(probs_url(a), headers=htmx())
    assert r.status_code == 200 and "вероятности недоступны" in r.text


def test_histogram_svg_is_static(ui_client, db, run):
    inc = top_incident(db, run)
    page = soup(ui_client.get(f"/incidents/{inc['incident_id']}"))
    svg = page.select_one(".histogram svg")
    assert svg.find("script") is None
    assert not any(k.startswith("on") for el in svg.find_all(True) for k in el.attrs)
    caption = page.select_one(".histogram figcaption").get_text(" ", strip=True)
    assert caption.count("UTC") == 2


def test_timeline(ui_client, db, run):
    inc = top_incident(db, run)
    store.change_status(db, inc["incident_id"], "vlad", "in_progress", None, None, 1)
    page = soup(ui_client.get(f"/incidents/{inc['incident_id']}"))
    events = page.select("ol.timeline li")
    kinds = [li["data-kind"] for li in events]
    assert kinds[:2] == ["first_alert", "last_alert"]
    assert kinds[2:] == [
        "incident_created",
        "action_proposed",
        "incident_status_changed",
    ]
    assert "время трафика" in events[0].get_text() and "время решения" in events[-1].get_text()
    # фрагмент хронологии отдельно (для обновления по incident-changed)
    frag = ui_client.get(f"/fragments/incidents/{inc['incident_id']}/timeline", headers=htmx())
    assert "<html" not in frag.text and len(soup(frag).select("ol.timeline li")) == len(events)


def test_unknown_incident(ui_client):
    r = ui_client.get("/incidents/inc-nope")
    assert r.status_code == 404
    page = soup(r)
    assert "Не найдено" in page.get_text()
    assert page.find("a", href="/incidents") is not None
