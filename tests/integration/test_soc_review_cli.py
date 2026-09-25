"""CLI `mlsiem soc review-sources` (contracts/cli.md): файлы отчёта, сводка, коды возврата."""

import json
from pathlib import Path

import yaml

from fixtures.review_db import build_review_db
from mlsiem import cli
from mlsiem.soc.config import load_soc_config, parse_soc_config

REPO = Path(__file__).parents[2]


def _setup(tmp_path, **kw):
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    raw = {**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs")}
    build_review_db(parse_soc_config(raw), **kw)
    path = tmp_path / "soc.yaml"
    path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    return path


def _review(cfg_path, tmp_path, *args):
    return cli.main(
        [
            "soc",
            "--config",
            str(cfg_path),
            "review-sources",
            *args,
            "--reports-dir",
            str(tmp_path / "reports"),
        ]
    )


def test_review_ok(tmp_path, capsys):
    cfg = _setup(tmp_path)
    assert _review(cfg, tmp_path, "--run", "before", "--after", "after") == 0
    out = capsys.readouterr().out
    assert "было 2 → стало 1" in out and "потеряно атакующих 0" in out
    assert "ПОТЕРЯНЫ" not in out
    md = tmp_path / "reports" / "source_review_before.md"
    js = tmp_path / "reports" / "source_review_before.json"
    assert md.exists() and js.exists()
    assert json.loads(js.read_text(encoding="utf-8"))["attackers_kept"]["lost"] == []


def test_review_lost_attackers_still_exit_0(tmp_path, capsys):
    cfg = _setup(tmp_path, lose_attacker=True)
    assert _review(cfg, tmp_path, "--run", "before", "--after", "after") == 0
    assert "ПОТЕРЯНЫ АТАКУЮЩИЕ: 175.45.176.2/exploits" in capsys.readouterr().out


def test_review_unknown_run(tmp_path, capsys):
    cfg = _setup(tmp_path)
    assert _review(cfg, tmp_path, "--run", "nope") == 1
    assert "не найден" in capsys.readouterr().err


def test_review_unlabeled_run(tmp_path, capsys):
    cfg = _setup(tmp_path)
    assert _review(cfg, tmp_path, "--run", "nolabels") == 1
    assert "true_label" in capsys.readouterr().err
