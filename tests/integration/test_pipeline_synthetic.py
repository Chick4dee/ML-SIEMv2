"""Конвейер `flows` целиком на синтетическом PCAP с подменённым конфигом.

Строим во временной папке мини-копии обоих датасетов (тот же синтетический PCAP, своя
разметка) и гоняем настоящую команду `mlsiem data flows` — от разбора аргументов до
манифестов и сводки.
"""

import json
import shutil
from pathlib import Path

import polars as pl
import pytest
import yaml

from mlsiem import cli
from mlsiem.data import pipeline

FIXTURES = Path(__file__).parents[1] / "fixtures"
REPO_CONFIG = Path(__file__).parents[2] / "configs" / "data.yaml"


@pytest.fixture
def env(tmp_path):
    unsw = tmp_path / "unsw"
    for day, n in (("22-1-2015", 1), ("22-1-2015", 2)):
        folder = unsw / "pcap files" / f"pcaps {day}"
        folder.mkdir(parents=True, exist_ok=True)
        shutil.copy(FIXTURES / "synthetic.pcap", folder / f"{n}.pcap")
    (unsw / "CSV Files").mkdir()
    shutil.copy(FIXTURES / "mini_gt.csv", unsw / "CSV Files" / "NUSW-NB15_GT.csv")

    ctu = tmp_path / "ctu"
    (ctu / "7").mkdir(parents=True)
    shutil.copy(FIXTURES / "synthetic.pcap", ctu / "7" / "botnet-capture.pcap")
    shutil.copy(FIXTURES / "mini.binetflow", ctu / "7" / "capture.binetflow")

    raw = yaml.safe_load(REPO_CONFIG.read_text(encoding="utf-8"))
    raw["datasets"]["unsw"]["root"] = str(unsw)
    raw["datasets"]["ctu13"]["root"] = str(ctu)
    cfg = tmp_path / "data.yaml"
    cfg.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    return {"config": str(cfg), "data": tmp_path / "data"}


def _run(env, *args):
    return cli.main(["data", "--config", env["config"], "--data-dir", str(env["data"]), *args])


def _manifest(env, dataset, cid):
    return json.loads((env["data"] / "flows" / dataset / f"{cid}.json").read_text("utf-8"))


def test_unsw_mode(env):
    assert _run(env, "flows", "--dataset", "unsw") == 0
    out = env["data"] / "flows" / "unsw"
    df = pl.read_parquet(out / "unsw_22-1-2015_01.parquet")
    labels = df["label"].to_list()
    # сопоставилась только FTP-сессия; остальное в UNSW — benign, unlabeled не бывает
    assert labels.count("exploits") == 1
    assert labels.count("benign") == df.height - 1
    assert "unlabeled" not in labels
    m = _manifest(env, "unsw", "unsw_22-1-2015_01")
    assert m["status"] == "done" and m["n_flows"] == 7 and m["n_matched"] == 1
    assert m["peak_rss_mb"] > 0
    summary = pl.read_csv(out / "summary.csv")
    assert summary["capture_id"].to_list() == ["unsw_22-1-2015_01", "unsw_22-1-2015_02"]
    assert (env["data"] / "flows" / "schema.json").exists()


def test_ctu13_mode_skip_and_force(env, capsys):
    assert _run(env, "flows", "--dataset", "ctu13", "--capture", "7") == 0
    path = env["data"] / "flows" / "ctu13" / "ctu13_07.parquet"
    df = pl.read_parquet(path)
    counts = dict(df["label"].value_counts().iter_rows())
    # botnet (HTTP), normal → benign (DNS), background (ICMP); остальное — unlabeled
    assert counts == {"botnet": 1, "benign": 1, "background": 1, "unlabeled": 4}
    first = _manifest(env, "ctu13", "ctu13_07")

    capsys.readouterr()
    assert _run(env, "flows", "--dataset", "ctu13", "--capture", "7") == 0
    assert "пропущено 1" in capsys.readouterr().out
    assert _manifest(env, "ctu13", "ctu13_07") == first  # пропуск не перезаписывает манифест

    assert _run(env, "flows", "--dataset", "ctu13", "--capture", "7", "--force") == 0
    again = _manifest(env, "ctu13", "ctu13_07")
    assert again["content_hash"] == first["content_hash"]


def test_timezone_change_triggers_recompute(env):
    assert _run(env, "flows", "--dataset", "ctu13") == 0
    raw = yaml.safe_load(Path(env["config"]).read_text(encoding="utf-8"))
    raw["datasets"]["ctu13"]["timezone"] = "UTC"
    Path(env["config"]).write_text(yaml.safe_dump(raw), encoding="utf-8")
    assert _run(env, "flows", "--dataset", "ctu13") == 0
    # в UTC записи съехали на час — ничего не сопоставилось
    assert _manifest(env, "ctu13", "ctu13_07")["n_matched"] == 0


def test_failure_in_second_capture(env, monkeypatch):
    real = pipeline.label_flows
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("сломались посреди второго захвата")
        return real(*args, **kwargs)

    monkeypatch.setattr(pipeline, "label_flows", flaky)
    assert _run(env, "flows", "--dataset", "unsw") == 2
    out = env["data"] / "flows" / "unsw"
    assert _manifest(env, "unsw", "unsw_22-1-2015_01")["status"] == "done"
    second = _manifest(env, "unsw", "unsw_22-1-2015_02")
    assert second["status"] == "failed" and "второго" in second["error"]
    assert not (out / "unsw_22-1-2015_02.parquet").exists()
    assert not [p for p in out.iterdir() if ".tmp-" in p.name]

    # следующий запуск доделывает только упавший захват
    monkeypatch.setattr(pipeline, "label_flows", real)
    assert _run(env, "flows", "--dataset", "unsw") == 0
    assert _manifest(env, "unsw", "unsw_22-1-2015_02")["status"] == "done"


def test_memory_error_stops_run(env, monkeypatch):
    def boom(*args, **kwargs):
        raise MemoryError

    monkeypatch.setattr(pipeline, "label_flows", boom)
    assert _run(env, "flows", "--dataset", "unsw") == 1
    assert _manifest(env, "unsw", "unsw_22-1-2015_01")["status"] == "failed"
    # второй захват даже не начинали — прогон остановлен целиком
    assert not (env["data"] / "flows" / "unsw" / "unsw_22-1-2015_02.json").exists()
