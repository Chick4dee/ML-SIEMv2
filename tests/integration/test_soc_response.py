"""Реагирование после прогона (US3, SC-005): предложения, решения аналитика, аудит, повтор."""

from pathlib import Path

import pytest

from mlsiem.soc import store
from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.soc.run import run_chain

REPO = Path(__file__).parents[2]


@pytest.fixture
def soc_cfg(tmp_path):
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    return parse_soc_config(
        {**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs")}
    )


def _run(cfg, split, det):
    return run_chain("split:unsw_time/test", cfg, detector_dir=det, data_dir=split)


def test_one_proposed_action_per_incident(soc_cfg, synthetic_split, tiny_detector):
    s = _run(soc_cfg, synthetic_split, tiny_detector)
    conn = store.connect(soc_cfg.db)
    rows = conn.execute(
        "SELECT i.incident_id, a.state, a.action_type FROM incidents i "
        "LEFT JOIN actions a ON a.incident_id = i.incident_id WHERE i.run_id = ?",
        (s.run_id,),
    ).fetchall()
    assert len(rows) == s.n_incidents
    assert all(r["state"] == "proposed" for r in rows)
    proposed = conn.execute(
        "SELECT COUNT(*) FROM audit_log "
        "WHERE event = 'action_proposed' AND run_id = ? AND actor = 'system'",
        (s.run_id,),
    ).fetchone()[0]
    assert proposed == s.n_incidents
    # SC-005: без подтверждения ни одного executed
    assert conn.execute("SELECT COUNT(*) FROM actions WHERE state = 'executed'").fetchone()[0] == 0
    assert sum(s.actions_by_type.values()) == s.n_incidents
    conn.close()


def test_decisions_in_audit(soc_cfg, synthetic_split, tiny_detector):
    s = _run(soc_cfg, synthetic_split, tiny_detector)
    conn = store.connect(soc_cfg.db)
    ids = [
        r[0]
        for r in conn.execute(
            "SELECT action_id FROM actions a JOIN incidents i USING (incident_id) "
            "WHERE i.run_id = ? "
            "ORDER BY action_id LIMIT 2",
            (s.run_id,),
        )
    ]
    store.confirm_action(conn, ids[0], "vlad", 1)
    store.reject_action(conn, ids[1], "anna", 1, "ложная тревога")
    events = conn.execute(
        "SELECT actor, event, action_id, at FROM audit_log WHERE action_id IN (?, ?) "
        "ORDER BY entry_id",
        ids,
    ).fetchall()
    decided = [(e["actor"], e["event"], e["action_id"]) for e in events if e["actor"] != "system"]
    assert decided == [("vlad", "action_executed", ids[0]), ("anna", "action_rejected", ids[1])]
    assert all(e["at"] for e in events)
    assert conn.execute("SELECT COUNT(*) FROM actions WHERE state = 'executed'").fetchone()[0] == 1
    conn.close()


def test_repeat_same_proposals(soc_cfg, synthetic_split, tiny_detector):
    def proposals(run_id):
        conn = store.connect(soc_cfg.db)
        rows = conn.execute(
            "SELECT i.src_ip, i.attack_class, i.first_seen_ms, a.action_type, a.target, a.rule_id "
            "FROM incidents i JOIN actions a USING (incident_id) WHERE i.run_id = ? "
            "ORDER BY i.src_ip, i.attack_class, i.first_seen_ms",
            (run_id,),
        ).fetchall()
        conn.close()
        return [tuple(r) for r in rows]

    s1 = _run(soc_cfg, synthetic_split, tiny_detector)
    s2 = _run(soc_cfg, synthetic_split, tiny_detector)
    assert proposals(s1.run_id) == proposals(s2.run_id)
    assert len(proposals(s1.run_id)) > 0
