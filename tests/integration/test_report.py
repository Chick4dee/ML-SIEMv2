"""Отчёт на синтетических манифестах, разбиении и аудите: самостоятельный HTML + Markdown."""

import json
import re
import shutil
from pathlib import Path

import polars as pl
import yaml

from mlsiem import cli
from mlsiem.data.config import load_config
from mlsiem.data.report.build import build_report

FIXTURES = Path(__file__).parents[1] / "fixtures"
REPO_CONFIG = Path(__file__).parents[2] / "configs" / "data.yaml"

SECTIONS = [
    "Обзор",
    "Сопоставление по захватам",
    "Классы по частям разбиения",
    "Исключено зазором",
    "Аудит артефактов",
    "Сверка с v1",
    "Известные ограничения источников",
]


def _prepare(tmp_path: Path):
    ctu = tmp_path / "ctu"
    (ctu / "7").mkdir(parents=True)
    shutil.copy(FIXTURES / "synthetic.pcap", ctu / "7" / "capture.pcap")
    shutil.copy(FIXTURES / "mini.binetflow", ctu / "7" / "capture.binetflow")
    raw = yaml.safe_load(REPO_CONFIG.read_text(encoding="utf-8"))
    raw["datasets"]["ctu13"]["root"] = str(ctu)
    cfg_path = tmp_path / "data.yaml"
    cfg_path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    data = tmp_path / "data"
    assert (
        cli.main(
            [
                "data",
                "--config",
                str(cfg_path),
                "--data-dir",
                str(data),
                "flows",
                "--dataset",
                "ctu13",
            ]
        )
        == 0
    )

    parts = {
        p: {"groups": [g], "intervals": [], "n_flows": n, "label_counts": lc}
        for p, g, n, lc in (
            ("train", "1", 5, {"botnet": 4, "background": 1}),
            ("val", "7", 2, {"botnet": 2}),
            ("test", "8", 1, {"botnet": 1}),
        )
    }
    parts["test"]["new_families"] = ["Murlo"]
    split = {
        "split_name": "ctu13_scenario",
        "dataset": "ctu13",
        "parts": parts,
        "params": {"quantiles": [0.7, 0.85], "gap_ms": 600000, "seed": 42},
        "excluded": {"total": 0, "by_label": {}},
        "missing_classes": {"train": [], "val": ["background"], "test": ["background"]},
        "input_hashes": {},
        "hash": "a" * 64,
    }
    (data / "splits").mkdir()
    (data / "splits" / "ctu13_scenario.json").write_text(json.dumps(split), encoding="utf-8")
    (data / "audit").mkdir()
    pl.DataFrame(
        {
            "field": ["src_ip", "bidirectional_packets", "noise"],
            "group": ["identity", "feature", "feature"],
            "variant": ["raw", "raw", "raw"],
            "pr_auc_macro": [0.95, 0.93, 0.5],
            "baseline": [0.5, 0.5, 0.5],
            "lift": [0.45, 0.43, 0.0],
            "status": ["dangerous", "suspicious", "ok"],
        }
    ).write_parquet(data / "audit" / "ctu13_scenario.parquet")
    return load_config(cfg_path), data


def test_self_contained_html_and_md(tmp_path):
    cfg, data = _prepare(tmp_path)
    html_path, md_path = build_report(cfg, data_dir=data, output=tmp_path / "reports")
    html = html_path.read_text(encoding="utf-8")

    # никаких внешних ресурсов: всё внутри файла
    for attr in re.findall(r'(?:src|href)="([^"]*)"', html):
        assert not attr.startswith("http"), attr
    assert "data:image/png;base64," in html
    for title in SECTIONS:
        assert title in html, title
    assert "dangerous" in html and "src_ip" in html
    # сверку не запускали — раздел говорит об этом, а не падает
    assert "Сверка не выполнялась" in html

    md = md_path.read_text(encoding="utf-8")
    for title in SECTIONS:
        assert f"## {title}" in md, title
    assert "Сверка не выполнялась" in md


def test_report_with_compare(tmp_path):
    cfg, data = _prepare(tmp_path)
    pl.DataFrame(
        {
            "capture_id": ["ctu13_07"],
            "in_v1": [True],
            "n_flows_v1": [7],
            "n_flows_v2": [7],
            "rel_diff": [0.0],
            "shares_v1": ["{}"],
            "shares_v2": ["{}"],
            "max_class_share_diff_pp": [0.0],
            "match_rate_v1": [0.5],
            "match_rate_v2": [3 / 7],
            "explained": [None],
        }
    ).write_csv(data / "compare_v1.csv")
    html_path, _ = build_report(cfg, data_dir=data, output=tmp_path / "reports")
    html = html_path.read_text(encoding="utf-8")
    assert "Доля сопоставления CTU-13" in html
    assert "доля сопоставления упала" in html
