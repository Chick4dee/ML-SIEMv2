"""Разбор источников (research R9): причины по потокам, счёт «до/после», атакующие не потеряны."""

from pathlib import Path

import pytest

from fixtures.review_db import build_review_db
from mlsiem.soc import store
from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.soc.review import render_review, review_sources, summary_line

REPO = Path(__file__).parents[2]


@pytest.fixture
def cfg(tmp_path):
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    return parse_soc_config(
        {**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs")}
    )


def _review(cfg, before, after=None):
    conn = store.connect(cfg.db)
    try:
        return review_sources(conn, cfg, before, after)
    finally:
        conn.close()


def test_reasons_and_counts(cfg):
    build_review_db(cfg)
    r = _review(cfg, "before", "after")
    by_ip = {i["src_ip"]: i for i in r["incidents"]}
    assert set(by_ip) == {"149.171.126.17", "59.166.0.3"}
    resp = by_ip["149.171.126.17"]
    assert resp["network"]["role"] == "victims"
    assert resp["reasons"] == ["response_direction"] and resp["only_direction"]
    assert resp["flows"][0]["attacker_ip"] == "175.45.176.0"
    assert resp["flows"][0]["direction_rule"] == "tcp_syn"
    dns = by_ip["59.166.0.3"]
    assert dns["reasons"] == ["detector_error"] and dns["network"]["role"] == "background"
    assert r["counts"] == {
        "before": 2,
        "only_direction": 1,
        "detector_error": 1,
        "labeled_attack": 0,
        "after": 1,
    }
    kept = r["attackers_kept"]
    assert {(p["ip"], p["class"]) for p in kept["pairs"]} == {
        ("175.45.176.1", "dos"),
        ("175.45.176.2", "exploits"),
    }
    assert kept["lost"] == []
    line = summary_line(r)
    assert "было 2 → стало 1" in line and "потеряно атакующих 0" in line
    md = render_review(r)
    assert "ответное направление" in md and "ошибка детектора" in md


def test_lost_attacker_detected(cfg):
    build_review_db(cfg, lose_attacker=True)
    r = _review(cfg, "before", "after")
    assert r["attackers_kept"]["lost"] == [{"ip": "175.45.176.2", "class": "exploits"}]
    assert "ПОТЕРЯНЫ АТАКУЮЩИЕ" in render_review(r)


def test_without_after(cfg):
    build_review_db(cfg)
    r = _review(cfg, "before")
    assert r["counts"]["after"] is None and r["attackers_kept"] is None


def test_needs_labels(cfg):
    build_review_db(cfg)
    with pytest.raises(ValueError, match="true_label"):
        _review(cfg, "nolabels")


def test_unknown_run(cfg):
    build_review_db(cfg)
    with pytest.raises(store.NotFound):
        _review(cfg, "nope")
