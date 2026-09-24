"""Машина состояний действия: подтверждение/отклонение, версии, аудит, никаких реальных действий."""

import ast
import json
from pathlib import Path

import pytest

from mlsiem.soc import store
from mlsiem.soc.store import BadRequest, Conflict, InvalidTransition, NotFound

SRC = Path(__file__).parents[2] / "src" / "mlsiem" / "soc"


@pytest.fixture
def conn(tmp_path):
    c = store.connect(tmp_path / "soc.db")
    store.init_db(c)
    incidents = [
        {
            "incident_id": f"inc-{i}",
            "src_ip": "1.1.1.1",
            "attack_class": "dos",
            "targets": json.dumps(["9.9.9.1"]),
            "first_seen_ms": i,
            "last_seen_ms": i + 1,
            "n_alerts": 1,
            "max_score": 0.9,
            "mean_score": 0.9,
            "severity": "medium",
            "severity_reason": "…",
        }
        for i in range(2)
    ]
    actions = [
        {
            "action_id": f"act-inc-{i}",
            "incident_id": f"inc-{i}",
            "action_type": "block_source_ip",
            "target": "1.1.1.1",
            "rule_id": "noisy_attack",
            "rule_text": "правило noisy_attack",
        }
        for i in range(2)
    ]
    run = {
        "run_id": "r1",
        "source": "split:x/test",
        "input_hash": "abc",
        "detector_version": "v",
        "started_at": store.now_iso(),
        "n_flows": 10,
    }
    store.write_run(c, run, [], incidents, actions)
    yield c
    c.close()


def audit(conn, event):
    return conn.execute("SELECT * FROM audit_log WHERE event = ?", (event,)).fetchall()


def test_proposed_on_load(conn):
    a = store.get_action(conn, "act-inc-0")
    assert a["state"] == "proposed" and a["version"] == 1 and a["simulation"] is None
    assert len(audit(conn, "action_proposed")) == 2


def test_confirm(conn):
    a = store.confirm_action(conn, "act-inc-0", "vlad", 1, "согласен")
    assert a["state"] == "executed"
    assert a["decided_by"] == "vlad" and a["decided_at"]
    assert a["version"] == 2
    assert a["simulation"]["action_type"] == "block_source_ip"
    assert a["simulation"]["target"] == "1.1.1.1"
    rows = audit(conn, "action_executed")
    assert len(rows) == 1 and rows[0]["actor"] == "vlad" and rows[0]["incident_id"] == "inc-0"


def test_reject_needs_comment(conn):
    with pytest.raises(BadRequest):
        store.reject_action(conn, "act-inc-0", "vlad", 1, "  ")
    a = store.reject_action(conn, "act-inc-0", "vlad", 1, "это сканер отдела ИБ")
    assert a["state"] == "rejected" and a["comment"] == "это сканер отдела ИБ"
    assert a["simulation"] is None
    assert len(audit(conn, "action_rejected")) == 1


@pytest.mark.parametrize("first", ["confirm", "reject"])
def test_no_second_decision(conn, first):
    if first == "confirm":
        store.confirm_action(conn, "act-inc-0", "vlad", 1)
    else:
        store.reject_action(conn, "act-inc-0", "vlad", 1, "нет")
    with pytest.raises(InvalidTransition):
        store.confirm_action(conn, "act-inc-0", "vlad", 2)
    with pytest.raises(InvalidTransition):
        store.reject_action(conn, "act-inc-0", "vlad", 2, "ещё раз")


def test_stale_version_conflict(conn):
    with pytest.raises(Conflict):
        store.confirm_action(conn, "act-inc-0", "vlad", 7)
    a = store.get_action(conn, "act-inc-0")
    assert a["state"] == "proposed" and a["version"] == 1
    assert audit(conn, "action_executed") == []


def test_empty_analyst(conn):
    with pytest.raises(BadRequest):
        store.confirm_action(conn, "act-inc-0", "", 1)
    with pytest.raises(BadRequest):
        store.confirm_action(conn, "act-inc-0", "   ", 1)


def test_not_found(conn):
    with pytest.raises(NotFound):
        store.confirm_action(conn, "act-нет", "vlad", 1)


def test_other_action_untouched(conn):
    store.confirm_action(conn, "act-inc-0", "vlad", 1)
    assert store.get_action(conn, "act-inc-1")["state"] == "proposed"


FORBIDDEN_MODULES = {"subprocess", "socket", "requests", "urllib", "http", "paramiko", "httpx"}


@pytest.mark.parametrize("module", ["playbooks.py", "store.py"])
def test_no_os_or_network_calls(module):
    tree = ast.parse((SRC / module).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            names = {(node.module or "").split(".")[0]}
        else:
            names = set()
        assert not names & FORBIDDEN_MODULES, f"{module}: запрещённый импорт {names}"
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            assert (node.value.id, node.attr) not in {("os", "system"), ("os", "popen")}
