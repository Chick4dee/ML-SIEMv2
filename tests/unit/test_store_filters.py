"""Фильтры и сортировки списка инцидентов (research R9): одна реализация для консоли и API."""

import pytest

from mlsiem.soc import store
from ui.conftest import add_incident, add_run


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "soc.db")
    store.init_db(c)
    add_run(c, "r1")
    add_run(c, "r2")
    spec = [
        ("a", "10.0.0.1", "critical", 5, 3000, None),
        ("b", "10.0.0.15", "high", 50, 1000, "alice"),
        ("c", "10.0.1.7", "high", 2, 2000, None),
        ("d", "192.168.1.1", "low", 9, 4000, "bob"),
        ("e", "2001:db8::5", "medium", 1, 5000, None),
    ]
    for iid, src, sev, n, first, who in spec:
        add_incident(
            c,
            "r1",
            iid,
            src_ip=src,
            severity=sev,
            n_alerts=n,
            first_ms=first,
            step_ms=1,
            assignee=who,
        )
    # тот же адрес в другом прогоне — фильтр по прогону его не должен видеть
    add_incident(c, "r2", "z", src_ip="10.0.0.1", severity="critical")
    c.execute("UPDATE actions SET state = 'executed' WHERE incident_id IN ('b', 'd')")
    yield c
    c.close()


def ids(conn, filters=None, **kw):
    total, items = store.list_incidents(conn, {"run_id": "r1", **(filters or {})}, 100, **kw)
    assert total == len(items)
    return [i["incident_id"] for i in items]


def test_src_exact_and_cidr(conn):
    assert ids(conn, {"src_ip": "10.0.0.1"}) == ["a"]
    # префикс — ровно по сети: 10.0.0.15 входит в /24, а 10.0.1.7 — нет
    assert sorted(ids(conn, {"src_ip": "10.0.0.0/24"})) == ["a", "b"]
    assert sorted(ids(conn, {"src_ip": "10.0.0.0/16"})) == ["a", "b", "c"]
    assert ids(conn, {"src_ip": "2001:db8::/32"}) == ["e"]
    assert ids(conn, {"src_ip": "8.8.8.8"}) == []


@pytest.mark.parametrize("bad", ["999.1.1.1", "10.0.0.0/99", "abc", "10.0.0.1; DROP TABLE"])
def test_src_invalid(conn, bad):
    with pytest.raises(store.BadRequest, match="источник"):
        ids(conn, {"src_ip": bad})


def test_assignee(conn):
    assert ids(conn, {"assignee": "alice"}) == ["b"]
    assert sorted(ids(conn, {"assignee": store.NO_ASSIGNEE})) == ["a", "c", "e"]


def test_action_state(conn):
    assert sorted(ids(conn, {"action_state": ["executed"]})) == ["b", "d"]
    assert sorted(ids(conn, {"action_state": ["proposed", "executed"]})) == list("abcde")


def test_incident_ids_and_exclude(conn):
    assert sorted(ids(conn, {"incident_ids": ["a", "c", "z"]})) == ["a", "c"]
    assert ids(conn, {"incident_ids": []}) == []
    assert sorted(ids(conn, {"exclude_ids": ["a", "c"]})) == ["b", "d", "e"]


def test_combined_filters(conn):
    assert ids(conn, {"src_ip": "10.0.0.0/16", "severity": ["high"], "assignee": "__none__"}) == [
        "c"
    ]


@pytest.mark.parametrize(
    "sort, direction, expected",
    [
        ("severity", "desc", ["a", "c", "b", "e", "d"]),  # внутри high — свежие первыми
        ("severity", "asc", ["d", "e", "c", "b", "a"]),
        ("first_seen", "asc", ["b", "c", "a", "d", "e"]),
        ("first_seen", "desc", ["e", "d", "a", "c", "b"]),
        ("last_seen", "desc", ["e", "d", "a", "c", "b"]),
        ("n_alerts", "desc", ["b", "d", "a", "c", "e"]),
        ("n_alerts", "asc", ["e", "c", "a", "d", "b"]),
    ],
)
def test_sorts(conn, sort, direction, expected):
    assert ids(conn, sort=sort, direction=direction) == expected


def test_stable_secondary_key(conn):
    # у всех трёх по одному алерту — порядок решает incident_id
    for iid in ("y3", "y1", "y2"):
        add_incident(conn, "r2", iid, n_alerts=1, severity="low")
    _, items = store.list_incidents(
        conn, {"run_id": "r2", "severity": ["low"]}, 10, sort="n_alerts", direction="desc"
    )
    assert [i["incident_id"] for i in items] == ["y1", "y2", "y3"]


@pytest.mark.parametrize("sort", ["drop", "i.severity; --", "incident_id"])
def test_sort_whitelist(conn, sort):
    with pytest.raises(store.BadRequest, match="сортировка"):
        ids(conn, sort=sort)


def test_bad_direction(conn):
    with pytest.raises(store.BadRequest):
        ids(conn, sort="n_alerts", direction="sideways")


def test_default_order_is_002(conn):
    # без sort — серьёзность ↓, first_seen ↑ (порядок API 002 не меняется)
    assert ids(conn) == ["a", "b", "c", "e", "d"]


def test_total_counts_without_limit(conn):
    total, items = store.list_incidents(conn, {"run_id": "r1"}, limit=2)
    assert total == 5 and len(items) == 2


def test_rows_have_assignee(conn):
    _, items = store.list_incidents(conn, {"run_id": "r1", "assignee": "bob"})
    assert items[0]["assignee"] == "bob"
