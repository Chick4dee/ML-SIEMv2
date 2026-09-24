"""Прогон части разбиения через цепочку (US2): файлы, БД, инварианты, повторяемость."""

import json
from pathlib import Path

import polars as pl
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


def _incidents(cfg, run_id):
    conn = store.connect(cfg.db)
    rows = conn.execute(
        "SELECT src_ip, attack_class, first_seen_ms, n_alerts, severity, status FROM incidents "
        "WHERE run_id = ? ORDER BY src_ip, attack_class, first_seen_ms",
        (run_id,),
    ).fetchall()
    conn.close()
    return [tuple(r) for r in rows]


def test_run_split(soc_cfg, synthetic_split, tiny_detector):
    s = run_chain(
        "split:unsw_time/test", soc_cfg, detector_dir=tiny_detector, data_dir=synthetic_split
    )
    assert (soc_cfg.runs_dir / s.run_id / "verdicts.parquet").exists()
    verdicts = pl.read_parquet(soc_cfg.runs_dir / s.run_id / "verdicts.parquet")
    manifest = json.loads(
        (synthetic_split / "splits" / "unsw_time.json").read_text(encoding="utf-8")
    )
    assert s.n_flows == verdicts.height == manifest["parts"]["test"]["n_flows"]
    assert s.n_alerts == int(verdicts["is_alert"].sum()) > 0
    assert 0 < s.n_incidents < s.n_alerts
    assert s.alerts_true_share is not None and 0 <= s.alerts_true_share <= 1
    assert sum(s.incidents_by_severity.values()) == s.n_incidents

    incidents = _incidents(soc_cfg, s.run_id)
    assert len(incidents) == s.n_incidents
    assert {r[-1] for r in incidents} == {"new"}
    conn = store.connect(soc_cfg.db)
    n_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE run_id = ?", (s.run_id,)).fetchone()[
        0
    ]
    per_inc = conn.execute(
        "SELECT SUM(n_alerts) FROM incidents WHERE run_id = ?", (s.run_id,)
    ).fetchone()[0]
    conn.close()
    assert n_alerts == per_inc == s.n_alerts


def test_repeat_gives_same_incidents(soc_cfg, synthetic_split, tiny_detector):
    s1 = run_chain(
        "split:unsw_time/test", soc_cfg, detector_dir=tiny_detector, data_dir=synthetic_split
    )
    s2 = run_chain(
        "split:unsw_time/test", soc_cfg, detector_dir=tiny_detector, data_dir=synthetic_split
    )
    assert s1.run_id != s2.run_id
    assert _incidents(soc_cfg, s1.run_id) == _incidents(soc_cfg, s2.run_id)


def test_limit_takes_first_by_time(soc_cfg, synthetic_split, tiny_detector):
    s = run_chain(
        "split:unsw_time/test",
        soc_cfg,
        detector_dir=tiny_detector,
        data_dir=synthetic_split,
        limit=50,
    )
    assert s.n_flows == 50
    verdicts = pl.read_parquet(soc_cfg.runs_dir / s.run_id / "verdicts.parquet")
    from mlsiem.detect.dataset import scan_part

    all_test = scan_part(
        "unsw_time", "test", data_dir=synthetic_split, columns=["bidirectional_first_seen_ms"]
    ).collect()
    first = all_test.sort(["bidirectional_first_seen_ms", "flow_uid"]).head(50)
    assert set(verdicts["flow_uid"]) == set(first["flow_uid"])


def test_missing_detector_touches_nothing(soc_cfg, synthetic_split, tmp_path):
    from mlsiem.detect.artifact import DetectorLoadError

    with pytest.raises(DetectorLoadError):
        run_chain(
            "split:unsw_time/test",
            soc_cfg,
            detector_dir=tmp_path / "none",
            data_dir=synthetic_split,
        )
    assert not soc_cfg.db.exists()
    assert not soc_cfg.runs_dir.exists()
