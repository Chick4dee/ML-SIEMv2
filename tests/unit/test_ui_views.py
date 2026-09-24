"""Сборка видов консоли: адрес ↔ вид списка, хронология, гистограмма, порог (US1)."""

from urllib.parse import parse_qs

import pytest
from starlette.datastructures import QueryParams

from mlsiem.soc import store
from mlsiem.ui import views
from mlsiem.ui.views import IncidentListView
from ui.conftest import add_incident, add_run

RUNS = ["r-new", "r-old"]


def parse(query: str):
    return IncidentListView.parse(QueryParams(query), RUNS)


def test_defaults():
    view, warnings = parse("")
    assert warnings == []
    assert view == IncidentListView(run="r-new", sort="severity", dir="desc", page=1)
    assert view.to_query() == "run=r-new"


def test_all_params():
    view, warnings = parse(
        "run=r-old&status=new,in_progress&severity=high&severity=critical&attack_class=dos"
        "&src=10.0.0.0/24&assignee=alice&action_state=proposed&flagged=only"
        "&sort=n_alerts&dir=asc&page=3"
    )
    assert warnings == []
    assert view.run == "r-old"
    assert view.status == ("new", "in_progress")
    assert view.severity == ("high", "critical")  # и через запятую, и повтором параметра
    assert (view.attack_class, view.src, view.assignee) == ("dos", "10.0.0.0/24", "alice")
    assert (view.action_state, view.flagged) == (("proposed",), "only")
    assert (view.sort, view.dir, view.page) == ("n_alerts", "asc", 3)


def test_roundtrip_url_is_same_view():
    view, _ = parse("status=closed&severity=low&src=10.1.1.1&assignee=__none__&sort=last_seen")
    again, warnings = parse(view.to_query())
    assert again == view and warnings == []


@pytest.mark.parametrize(
    "query, field_name",
    [
        ("severity=ultra", "серьёзность"),
        ("src=999.1.1.1", "источник"),
        ("page=-2", "страница"),
        ("sort=drop", "сортировка"),
        ("dir=up", "направление"),
        ("flagged=maybe", "подозрительный"),
        ("status=open", "статус"),
        ("run=r-missing", "прогон"),
    ],
)
def test_bad_value_ignored_with_warning(query, field_name):
    view, warnings = parse(query + "&attack_class=dos")
    assert len(warnings) == 1 and field_name in warnings[0]
    # остальные фильтры применяются
    assert view.attack_class == "dos"
    assert view.run == "r-new" and view.page == 1 and view.sort == "severity"


def test_partial_multi_value():
    view, warnings = parse("severity=high,ultra")
    assert view.severity == ("high",)
    assert "ultra" in warnings[0]


def test_sort_url_toggles():
    view, _ = parse("sort=n_alerts&dir=desc&page=4")
    assert parse_qs(view.sort_url("n_alerts").split("?")[1]) == {
        "run": ["r-new"],
        "sort": ["n_alerts"],
        "dir": ["asc"],
    }
    # новый ключ — сразу по убыванию и с первой страницы
    assert "dir" not in view.sort_url("first_seen") and "page" not in view.sort_url("first_seen")


# ---------------------------------------------------------------- гистограмма и хронология


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "soc.db")
    store.init_db(c)
    add_run(c, "r1")
    yield c
    c.close()


def test_histogram_bins(conn):
    # 90 с между первым и последним алертом → корзина ceil(90000/40) = 2250 мс
    add_incident(conn, "r1", "h", n_alerts=10, first_ms=0, step_ms=10_000)
    h = store.alert_histogram(conn, "h")
    assert h["bin_ms"] == 2250 and len(h["counts"]) == 40 and sum(h["counts"]) == 10
    add_incident(conn, "r1", "one", n_alerts=1)
    assert store.alert_histogram(conn, "one")["counts"] == [1]


def test_timeline_order_and_clocks(conn, soc_cfg_like):
    add_incident(conn, "r1", "t", n_alerts=3, first_ms=1_424_242_234_000, step_ms=60_000)
    store.append_audit(
        conn,
        "system",
        "action_proposed",
        run_id="r1",
        incident_id="t",
        action_id="act-t",
        details={"action_type": "block_source_ip", "target": "10.20.30.40", "rule_id": "x"},
    )
    store.assign(conn, "t", "vlad", "alice", 1)
    store.change_status(conn, "t", "bob", "in_progress", None, "смотрю", 2)
    card = views.incident_card(conn, soc_cfg_like, "t")
    tl = card["timeline"]
    kinds = [e.kind for e in tl]
    assert kinds == [
        "first_alert",
        "last_alert",
        "incident_created",
        "action_proposed",
        "incident_assigned",
        "incident_status_changed",
    ]
    assert [e.clock for e in tl[:2]] == ["traffic", "traffic"]
    assert {e.clock for e in tl[2:]} == {"decision"}
    assert tl[0].at == "2015-02-18 06:50:34 UTC" and tl[1].at == "2015-02-18 06:52:34 UTC"
    assert [e.sort_ms for e in tl] == sorted(e.sort_ms for e in tl)
    # решение bob при ответственном alice помечено; назначение — нет
    assert tl[-1].non_assignee is True and tl[-1].comment == "смотрю"
    assert tl[-2].non_assignee is False
    assert "в работе" in tl[-1].text


@pytest.fixture
def soc_cfg_like(tmp_path):
    from pathlib import Path

    from mlsiem.soc.config import load_soc_config

    return load_soc_config(Path(__file__).parents[2] / "configs" / "soc.yaml")


def test_threshold_rules(tmp_path):
    import json

    card = tmp_path / "model_card.json"
    card.write_text(json.dumps({"detector_version": "d1", "threshold": 0.7}), encoding="utf-8")
    assert views.run_threshold({"summary": {"threshold": 0.9}, "detector_version": "d1"}, tmp_path)[
        0
    ] == pytest.approx(0.9)
    assert views.run_threshold({"summary": {}, "detector_version": "d1"}, tmp_path)[
        0
    ] == pytest.approx(0.7)
    value, note = views.run_threshold({"summary": {}, "detector_version": "d0"}, tmp_path)
    assert value is None and "неизвестен" in note
