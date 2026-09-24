"""Назначение ответственного и отметка «решение не ответственным» в аудите (FR-012, FR-012a)."""

import json

import pytest

from mlsiem.soc import store
from ui.conftest import add_incident, add_run


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "soc.db")
    store.init_db(c)
    add_run(c, "r1")
    add_incident(c, "r1", "inc-1")
    add_incident(c, "r1", "inc-2")
    yield c
    c.close()


def audit(conn, incident_id="inc-1"):
    return store.incident_audit(conn, incident_id)


def test_assign_and_unassign(conn):
    card = store.assign(conn, "inc-1", "vlad", "alice", 1, "разберётся")
    assert card["assignee"] == "alice" and card["version"] == 2
    assert card["history"][-1] == {
        "at": card["history"][-1]["at"],
        "analyst": "vlad",
        "field": "assignee",
        "old": None,
        "new": "alice",
        "comment": "разберётся",
    }
    [e] = audit(conn)
    assert e["event"] == "incident_assigned" and e["actor"] == "vlad" and e["run_id"] == "r1"
    assert e["details"] == {"old": None, "new": "alice", "comment": "разберётся"}

    # пустая строка = снять назначение
    card = store.assign(conn, "inc-1", "vlad", "  ", 2)
    assert card["assignee"] is None and card["version"] == 3
    assert audit(conn)[-1]["details"] == {"old": "alice", "new": None, "comment": None}


def test_assign_is_atomic(conn, monkeypatch):
    # сбой на записи аудита — назначения, истории и новой версии тоже нет
    def boom(*a, **kw):
        raise RuntimeError("сбой аудита")

    monkeypatch.setattr(store, "append_audit", boom)
    with pytest.raises(RuntimeError):
        store.assign(conn, "inc-1", "vlad", "alice", 1)
    inc = store.get_incident(conn, "inc-1")
    assert inc["assignee"] is None and inc["version"] == 1 and inc["history"] == []


def test_stale_version(conn):
    with pytest.raises(store.Conflict):
        store.assign(conn, "inc-1", "vlad", "alice", 7)
    assert store.get_incident(conn, "inc-1")["assignee"] is None


@pytest.mark.parametrize("name", ["a" * 65, "al\nice", "x\x00"])
def test_bad_name(conn, name):
    with pytest.raises(store.BadRequest, match="ответственного"):
        store.assign(conn, "inc-1", "vlad", name, 1)


def test_same_name_again(conn):
    store.assign(conn, "inc-1", "vlad", "alice", 1)
    with pytest.raises(store.BadRequest, match="уже"):
        store.assign(conn, "inc-1", "vlad", " alice ", 2)
    with pytest.raises(store.BadRequest, match="нечего"):
        store.assign(conn, "inc-2", "vlad", None, 1)


def test_closed_incident_can_be_assigned(conn):
    store.change_status(conn, "inc-1", "vlad", "closed", "false_positive", None, 1)
    card = store.assign(conn, "inc-1", "vlad", "alice", 2)
    assert (card["status"], card["resolution"], card["assignee"]) == (
        "closed",
        "false_positive",
        "alice",
    )


def test_assign_needs_analyst(conn):
    with pytest.raises(store.BadRequest, match="аналитик"):
        store.assign(conn, "inc-1", " ", "alice", 1)


def test_not_found(conn):
    with pytest.raises(store.NotFound):
        store.assign(conn, "nope", "vlad", "alice", 1)


# ---------------------------------------------------------------- by_non_assignee в решениях


def test_status_change_marks(conn):
    store.change_status(conn, "inc-2", "vlad", "in_progress", None, None, 1)
    d = audit(conn, "inc-2")[-1]["details"]
    assert d["assignee"] is None and d["by_non_assignee"] is False

    store.assign(conn, "inc-1", "vlad", "alice", 1)
    store.change_status(conn, "inc-1", "alice", "in_progress", None, None, 2)
    d = audit(conn)[-1]["details"]
    assert d["assignee"] == "alice" and d["by_non_assignee"] is False

    store.change_status(conn, "inc-1", "bob", "closed", "confirmed", "за alice", 3)
    d = audit(conn)[-1]["details"]
    assert d["assignee"] == "alice" and d["by_non_assignee"] is True


@pytest.mark.parametrize("decide", ["confirm", "reject"])
def test_action_decision_marks(conn, decide):
    store.assign(conn, "inc-1", "vlad", "alice", 1)
    if decide == "confirm":
        store.confirm_action(conn, "act-inc-1", "bob", 1)
    else:
        store.reject_action(conn, "act-inc-1", "bob", 1, "не нужно")
    e = audit(conn)[-1]
    assert e["event"] == f"action_{'executed' if decide == 'confirm' else 'rejected'}"
    assert e["details"]["assignee"] == "alice" and e["details"]["by_non_assignee"] is True


def test_mark_is_written_in_database(conn):
    # отметка — в самой записи журнала, а не вычисляется при чтении
    store.assign(conn, "inc-1", "vlad", "alice", 1)
    store.confirm_action(conn, "act-inc-1", "alice", 1)
    raw = conn.execute("SELECT details FROM audit_log ORDER BY entry_id DESC LIMIT 1").fetchone()[0]
    assert json.loads(raw)["by_non_assignee"] is False
