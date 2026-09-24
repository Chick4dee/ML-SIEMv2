"""Сводка панели, последние алерты и «отпечаток» состояния для опроса (US4)."""

import pytest

from mlsiem.soc import store
from ui.conftest import add_incident, add_run


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "soc.db")
    store.init_db(c)
    add_run(c, "r1")
    add_run(c, "empty")
    add_incident(c, "r1", "a", severity="high", attack_class="dos", n_alerts=3, first_ms=1000)
    add_incident(c, "r1", "b", severity="high", attack_class="exploits", first_ms=5000)
    add_incident(c, "r1", "c", severity="low", attack_class="dos", assignee="alice", n_alerts=2)
    add_incident(c, "r1", "d", severity="medium", attack_class="dos", action=False)
    store.change_status(c, "b", "vlad", "closed", "confirmed", None, 1)
    store.confirm_action(c, "act-c", "alice", 1)
    yield c
    c.close()


def _count(conn, **filters):
    return store.list_incidents(conn, {"run_id": "r1", **filters}, 1000)[0]


def test_summary_matches_list(conn):
    s = store.dashboard_summary(conn, "r1")
    assert s["total"] == 4 == _count(conn)
    assert s["by_status"] == {"new": 3, "in_progress": 0, "closed": 1}
    for status, n in s["by_status"].items():
        assert n == _count(conn, status=[status])
    assert s["by_severity"] == {"critical": 0, "high": 2, "medium": 1, "low": 1}
    for sev, n in s["by_severity"].items():
        assert n == _count(conn, severity=[sev])
    assert s["by_class"] == {"dos": 3, "exploits": 1}
    for cls, n in s["by_class"].items():
        assert n == _count(conn, attack_class=cls)
    # ждут решения: a (proposed), b (proposed — закрытие инцидента действие не трогает)
    assert s["actions_pending"] == 2 == _count(conn, action_state=["proposed"])
    # без ответственного и не закрыт: a и d (c назначен, b закрыт)
    assert (
        s["unassigned"]
        == 2
        == _count(conn, assignee=store.NO_ASSIGNEE, status=["new", "in_progress"])
    )


def test_empty_run_gives_zeros(conn):
    s = store.dashboard_summary(conn, "empty")
    assert s["total"] == s["actions_pending"] == s["unassigned"] == 0
    assert set(s["by_status"].values()) == {0} and s["by_class"] == {}


def test_recent_alerts(conn):
    recent = store.recent_alerts(conn, "r1", 3)
    assert [a["first_seen_ms"] for a in recent] == sorted(
        (a["first_seen_ms"] for a in recent), reverse=True
    )
    # самый поздний поток — второй алерт «c»; при равном времени — по flow_uid
    assert [a["flow_uid"] for a in recent] == ["c-f1", "c-f0", "d-f0"]
    assert [a["incident_id"] for a in recent] == ["c", "c", "d"]
    assert store.recent_alerts(conn, "empty", 5) == []


def test_list_state_changes_only_on_decisions(conn):
    before = store.list_state(conn, "r1")
    assert store.list_state(conn, "r1") == before
    store.list_incidents(conn, {"run_id": "r1"})
    assert store.list_state(conn, "r1") == before
    store.change_status(conn, "a", "vlad", "in_progress", None, None, 1)
    after_status = store.list_state(conn, "r1")
    assert after_status != before
    store.reject_action(conn, "act-a", "vlad", 1, "лишнее")
    assert store.list_state(conn, "r1") != after_status


def test_incident_versions(conn):
    assert store.incident_versions(conn, "c") == (1, 2)
    assert store.incident_versions(conn, "d") == (1, None)
    with pytest.raises(store.NotFound):
        store.incident_versions(conn, "nope")


def test_histogram(conn):
    add_incident(conn, "r1", "big", n_alerts=5000, first_ms=0, step_ms=20)
    h = store.alert_histogram(conn, "big")
    # 100 с интервала → 40 корзин по 2.5 с
    assert h["bin_ms"] == 2500 and len(h["counts"]) == 40
    assert sum(h["counts"]) == 5000
    one = store.alert_histogram(conn, "d")
    assert one["counts"] == [1] and one["bin_ms"] == 1000
    short = store.alert_histogram(conn, "a")  # 3 алерта за 20 мс — одна корзина в 1 с
    assert short["counts"] == [3]
