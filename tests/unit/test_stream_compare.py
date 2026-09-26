"""Сравнение сеанса с пакетным прогоном (FR-021, R12): эквивалентность и причины расхождений."""

import json

import polars as pl
import pytest

from fixtures.stream_helpers import (
    make_cluster,
    make_soc_cfg,
    make_stream_cfg,
    replay_split,
    run_consumer,
)
from mlsiem.soc import store
from mlsiem.soc.run import run_chain
from mlsiem.stream.compare import CompareError, compare, render_compare, write_compare

SRC = "replay:unsw_time/test:20260925T160000"
LIMIT = 400


@pytest.fixture
def pair(tmp_path, synthetic_split, tiny_detector):
    stream_cfg, soc_cfg = make_stream_cfg(batch_max_messages=100), make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    replay_split(cluster, stream_cfg, synthetic_split, SRC, limit=LIMIT)
    run_consumer(cluster, stream_cfg, soc_cfg, tiny_detector)
    batch = run_chain(
        "split:unsw_time/test",
        soc_cfg,
        model_dir=tiny_detector,
        data_dir=synthetic_split,
        limit=LIMIT,
    )
    conn = store.connect(soc_cfg.db)
    return conn, soc_cfg, store.session_run_id(SRC), batch.run_id


def test_equivalent(pair, tmp_path):
    conn, soc_cfg, session, batch = pair
    rep = compare(conn, soc_cfg.runs_dir, session, batch)
    assert rep["equivalent"] and rep["divergences"] == []
    assert rep["verdicts"]["matched"] == rep["verdicts"]["both"] > 0
    md, js = write_compare(rep, tmp_path / "reports")
    assert "эквивалентно" in md.read_text(encoding="utf-8")
    assert json.loads(js.read_text(encoding="utf-8"))["equivalent"] is True


def test_changed_verdict_is_other(pair):
    conn, soc_cfg, session, batch = pair
    part = sorted((soc_cfg.runs_dir / session / "verdicts").glob("part-*.parquet"))[0]
    v = pl.read_parquet(part)
    uid = v["flow_uid"][0]
    v.with_columns(
        pl.when(pl.col("flow_uid") == uid)
        .then(pl.col("attack_score") + 0.5)
        .otherwise(pl.col("attack_score"))
        .alias("attack_score")
    ).write_parquet(part)
    rep = compare(conn, soc_cfg.runs_dir, session, batch)
    assert not rep["equivalent"]
    assert rep["verdicts"]["mismatched"] == 1
    assert rep["verdicts"]["examples"][0]["flow_uid"] == uid
    assert rep["divergences_by_reason"] == {"other": 1}


def test_changed_incident_boundary(pair):
    conn, soc_cfg, session, batch = pair
    iid = conn.execute(
        "SELECT incident_id FROM incidents WHERE run_id = ? LIMIT 1", (session,)
    ).fetchone()[0]
    conn.execute(
        "UPDATE incidents SET last_seen_ms = last_seen_ms + 1 WHERE incident_id = ?", (iid,)
    )
    rep = compare(conn, soc_cfg.runs_dir, session, batch)
    assert not rep["equivalent"]
    kinds = {d["what"] for d in rep["divergences"]}
    assert {"incident_only_in_session", "incident_only_in_batch"} <= kinds
    assert "НЕ эквивалентно" in render_compare(rep)


def test_known_reasons_keep_equivalence(pair):
    conn, soc_cfg, session, batch = pair
    iid = conn.execute(
        "SELECT incident_id FROM incidents WHERE run_id = ? LIMIT 1", (session,)
    ).fetchone()[0]
    # Слияние не сделано из-за решения аналитика — инцидент в сеансе «короче», чем в пакете
    conn.execute(
        "UPDATE incidents SET last_seen_ms = last_seen_ms + 1 WHERE incident_id = ?", (iid,)
    )
    conn.execute(
        "INSERT INTO stream_divergences (run_id, kind, incident_id, other_incident_id, flow_uid, "
        "at, details) VALUES (?, 'merge_blocked_by_decision', ?, 'inc-x', 'f', 'now', '{}')",
        (session, iid),
    )
    rep = compare(conn, soc_cfg.runs_dir, session, batch)
    assert rep["equivalent"]
    assert set(rep["divergences_by_reason"]) == {"merge_blocked_by_decision"}

    # late_beyond_allowed: алерт инцидента помечен опоздавшим
    iid2 = conn.execute(
        "SELECT incident_id FROM incidents WHERE run_id = ? AND incident_id != ? LIMIT 1",
        (session, iid),
    ).fetchone()[0]
    conn.execute("UPDATE alerts SET late = 1 WHERE incident_id = ?", (iid2,))
    conn.execute("UPDATE incidents SET n_alerts = n_alerts + 100 WHERE incident_id = ?", (iid2,))
    rep = compare(conn, soc_cfg.runs_dir, session, batch)
    assert rep["equivalent"]
    assert "late_beyond_allowed" in rep["divergences_by_reason"]


def test_different_models_refused(pair):
    conn, soc_cfg, session, batch = pair
    conn.execute("UPDATE runs SET model_version = 'другая' WHERE run_id = ?", (session,))
    with pytest.raises(CompareError, match="модели прогонов различаются"):
        compare(conn, soc_cfg.runs_dir, session, batch)
    with pytest.raises(CompareError, match="не найден"):
        compare(conn, soc_cfg.runs_dir, "stream-нет", batch)
