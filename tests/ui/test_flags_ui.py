"""Метки подозрительного источника в консоли (US3): бейджи, объяснение, фильтр, обычные решения."""

import pytest

from mlsiem.soc import store
from ui.conftest import add_incident, incident_ids, login, post_form, soup


@pytest.fixture
def flagged(db, run):
    """Два помеченных инцидента поверх синтетического прогона.

    victim — источник из сети жертв и одновременно цель инцидентов синтетики (149.171.126.14);
    reply — адрес атакующего 175.45.176.2 выступает целью, а источник — «фон».
    """
    add_incident(db, run.run_id, "victim", src_ip="149.171.126.14", targets=("175.45.176.2",))
    add_incident(db, run.run_id, "bg", src_ip="59.166.0.3", targets=("8.8.8.8",), severity="high")
    return ["victim", "bg"]


def test_badges_in_list(ui_client, flagged):
    page = soup(ui_client.get("/incidents"))
    row = page.select_one("tr[data-incident='victim']")
    badges = [b.get_text(" ", strip=True) for b in row.select(".badge.flag")]
    assert any("жертвы UNSW-NB15" in b for b in badges)
    assert any("цель в других" in b for b in badges)
    assert all(b["title"] for b in row.select(".badge.flag"))  # объяснение во всплывающей подсказке
    bg = page.select_one("tr[data-incident='bg']")
    assert "фон UNSW-NB15" in bg.get_text()


def test_card_explains_with_links(ui_client, db, run, flagged):
    page = soup(ui_client.get("/incidents/victim"))
    box = page.select_one(".flags-box")
    text = box.get_text(" ", strip=True)
    assert "источник входит в сеть «жертвы UNSW-NB15» (149.171.126.0/24)" in text
    assert "подсказка" in text and "не меняет" in text
    # ссылки на инциденты, где 149.171.126.14 — цель
    _, items = store.list_incidents(db, {"run_id": run.run_id}, 100)
    targets_of = [i["incident_id"] for i in items if "149.171.126.14" in i["targets"]]
    links = [a["href"] for a in box.select(".related a")]
    assert links and set(links) == {f"/incidents/{i}" for i in targets_of}


def test_flag_filter(ui_client, db, run, flagged):
    all_ids = set(incident_ids(ui_client.get("/incidents")))
    only = set(incident_ids(ui_client.get("/incidents?flagged=only")))
    hide = set(incident_ids(ui_client.get("/incidents?flagged=hide")))
    assert set(flagged) <= only
    assert only | hide == all_ids and only.isdisjoint(hide)
    # у синтетики «атакующие» 175.45.176.x — цель у victim, поэтому тоже помечены
    assert any(store.get_incident(db, i)["src_ip"] == "175.45.176.2" for i in only)


def test_flags_do_not_change_incident(ui_client, db, flagged):
    before = store.get_incident(db, "victim")
    ui_client.get("/incidents?flagged=only")
    ui_client.get("/incidents/victim")
    after = store.get_incident(db, "victim")
    assert after == before and after["severity"] == "medium" and after["status"] == "new"


def test_close_flagged_as_false_positive(ui_client, db, flagged):
    login(ui_client, "vlad")
    r = post_form(
        ui_client,
        "/incidents/victim/status",
        {"status": "closed", "resolution": "false_positive", "expected_version": "1"},
    )
    assert r.status_code == 200
    inc = store.get_incident(db, "victim")
    assert (inc["status"], inc["resolution"]) == ("closed", "false_positive")
    # остальные помеченные не тронуты — массовых операций нет
    assert store.get_incident(db, "bg")["status"] == "new"


def test_flag_filter_radio_in_form(ui_client, flagged):
    radios = soup(ui_client.get("/incidents?flagged=hide")).select(
        "form.filters input[name=flagged]"
    )
    assert [(r["value"], r.has_attr("checked")) for r in radios] == [
        ("", False),
        ("only", False),
        ("hide", True),
    ]
