"""Статусы инцидента: переходы, резолюция, история, аудит, оптимистичная блокировка."""

import json

import pytest

from mlsiem.soc import store
from mlsiem.soc.store import BadRequest, Conflict, InvalidTransition, NotFound


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "soc.db")
    store.init_db(c)
    incidents = [
        {
            "incident_id": "inc-1",
            "src_ip": "1.1.1.1",
            "attack_class": "dos",
            "targets": json.dumps(["9.9.9.1"]),
            "first_seen_ms": 0,
            "last_seen_ms": 1,
            "n_alerts": 1,
            "max_score": 0.9,
            "mean_score": 0.9,
            "severity": "medium",
            "severity_reason": "…",
        }
    ]
    run = {
        "run_id": "r1",
        "source": "split:x/test",
        "input_hash": "abc",
        "detector_version": "v",
        "started_at": store.now_iso(),
        "n_flows": 10,
    }
    store.write_run(c, run, [], incidents, [])
    yield c
    c.close()


@pytest.mark.parametrize(
    "path",
    [
        [("in_progress", None)],
        [("closed", "confirmed")],
        [("in_progress", None), ("closed", "false_positive")],
    ],
)
def test_allowed_transitions(conn, path):
    version = 1
    for status, resolution in path:
        inc = store.change_status(conn, "inc-1", "vlad", status, resolution, None, version)
        assert inc["status"] == status
        assert inc["version"] == version + 1
        version = inc["version"]
    assert inc["resolution"] == path[-1][1]


def test_close_needs_resolution(conn):
    with pytest.raises(BadRequest, match="резолюция"):
        store.change_status(conn, "inc-1", "vlad", "closed", None, None, 1)


def test_resolution_only_when_closing(conn):
    with pytest.raises(BadRequest):
        store.change_status(conn, "inc-1", "vlad", "in_progress", "confirmed", None, 1)


@pytest.mark.parametrize("target", ["new", "in_progress", "closed"])
def test_closed_is_final(conn, target):
    store.change_status(conn, "inc-1", "vlad", "closed", "confirmed", None, 1)
    resolution = "confirmed" if target == "closed" else None
    with pytest.raises(InvalidTransition):
        store.change_status(conn, "inc-1", "vlad", target, resolution, None, 2)


def test_history_and_audit(conn):
    store.change_status(conn, "inc-1", "vlad", "in_progress", None, "беру", 1)
    inc = store.change_status(conn, "inc-1", "anna", "closed", "false_positive", "сканер ИБ", 2)
    hist = [(h["analyst"], h["field"], h["old"], h["new"], h["comment"]) for h in inc["history"]]
    assert hist == [
        ("vlad", "status", "new", "in_progress", "беру"),
        ("anna", "status", "in_progress", "closed", "сканер ИБ"),
        ("anna", "resolution", None, "false_positive", "сканер ИБ"),
    ]
    assert all(h["at"] for h in inc["history"])
    rows = conn.execute(
        "SELECT actor FROM audit_log WHERE event = 'incident_status_changed' ORDER BY entry_id"
    ).fetchall()
    assert [r["actor"] for r in rows] == ["vlad", "anna"]


def test_stale_version(conn):
    store.change_status(conn, "inc-1", "vlad", "in_progress", None, None, 1)
    with pytest.raises(Conflict):
        store.change_status(conn, "inc-1", "anna", "closed", "confirmed", None, 1)
    inc = store.get_incident(conn, "inc-1")
    assert inc["status"] == "in_progress" and inc["version"] == 2
    assert len(inc["history"]) == 1


def test_not_found_and_analyst(conn):
    with pytest.raises(NotFound):
        store.change_status(conn, "inc-нет", "vlad", "in_progress", None, None, 1)
    with pytest.raises(BadRequest):
        store.change_status(conn, "inc-1", "", "in_progress", None, None, 1)
