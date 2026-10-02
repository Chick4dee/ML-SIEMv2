"""Разбор ошибок модели окон (фича 007, US4): матрица, размеры окон, окна против потоков,
примеры пропусков. Логика — на ручных примерах; весь разбор на синтетике — в конце."""

import numpy as np
import polars as pl
import yaml

from fixtures.small_configs import small_windows_raw
from mlsiem.cli import main
from mlsiem.detect import windows_audit as A


def test_confusion_by_class():
    got = A.confusion_by_class(
        ["benign", "exploits", "exploits", "dos"],
        ["benign", "exploits", "benign", "exploits"],
        ["benign", "exploits", "fuzzers"],
    )
    assert got["labels"] == ["benign", "exploits", "dos"]  # fuzzers не встречался
    assert got["matrix"]["exploits"] == {"benign": 1, "exploits": 1, "dos": 0}
    assert got["matrix"]["dos"]["exploits"] == 1


def test_size_buckets():
    assert [A.size_bucket(n) for n in (1, 2, 10, 11, 64, 65, 128, 129)] == [
        "1",
        "2–10",
        "2–10",
        "11–64",
        "11–64",
        "65–128",
        "65–128",
        ">128",
    ]


def test_quality_by_size():
    n = [1, 1, 5, 5, 200]
    y = [True, False, True, False, True]
    score = [0.9, 0.1, 0.2, 0.8, 0.9]
    alert = [True, False, False, True, True]
    rows = {r["bucket"]: r for r in A.quality_by_size(n, y, score, alert)}
    assert set(rows) == {"1", "2–10", ">128"}  # пустые корзины не выводятся
    assert rows["1"] == {
        "bucket": "1",
        "n_windows": 2,
        "n_attack": 1,
        "pr_auc_binary": 1.0,
        "recall": 1.0,
        "false_alerts": 0,
    }
    assert rows["2–10"]["recall"] == 0.0 and rows["2–10"]["false_alerts"] == 1
    assert rows[">128"]["pr_auc_binary"] is None  # одни атаки — метрика не определена


def test_flows_caught_any_flow():
    assignment = pl.DataFrame(
        {"flow_uid": ["f1", "f2", "f3", "f4"], "window_id": ["w1", "w1", "w2", "w3"]}
    )
    alerts = pl.DataFrame({"flow_uid": ["f1", "f2", "f3"], "is_alert": [False, True, False]})
    got = dict(A.flows_caught(assignment, alerts).iter_rows())
    # w3: у потока нет вердикта — не пойман
    assert got == {"w1": True, "w2": False, "w3": False}


def test_catch_table_by_class():
    frame = pl.DataFrame(
        {
            "label": ["exploits"] * 4 + ["dos", "benign"],
            "window_alert": [True, True, False, False, True, True],
            "caught_by_flows": [True, False, True, False, False, True],
        }
    )
    rows = {r["label"]: r for r in A.catch_table(frame)}
    assert set(rows) == {"exploits", "dos"}  # норма не входит
    assert rows["exploits"] == {
        "label": "exploits",
        "n_windows": 4,
        "only_windows": 1,
        "only_flows": 1,
        "both": 1,
        "none": 1,
    }
    assert rows["dos"]["only_windows"] == 1


def test_missed_examples_limit_and_order():
    k = 30
    frame = pl.DataFrame(
        {
            "window_id": [f"w{i:02d}" for i in range(k)],
            "attacker_ip": ["a"] * k,
            "label": ["exploits"] * (k - 1) + ["benign"],
            "n_flows": [3] * k,
            "attack_share": [0.5] * k,
            "attack_score": np.linspace(0.0, 0.29, k),
            "window_alert": [False] * (k - 1) + [False],
            "caught_by_flows": [False] * k,
        }
    )
    got = A.missed_examples(frame)
    assert len(got) == A.MAX_EXAMPLES
    assert got[0]["window_id"] == "w00"  # самый уверенный пропуск — первым
    assert all(r["label"] != "benign" for r in got)


def test_cli_errors_on_synthetic(tiny_windows, synthetic_split, tmp_path, capsys):
    cfg = tmp_path / "windows.yaml"
    cfg.write_text(yaml.safe_dump(small_windows_raw(tmp_path)), encoding="utf-8")
    code = main(
        [
            "detect",
            "--data-dir",
            str(synthetic_split),
            "windows-errors",
            "--model",
            str(tiny_windows),
            "--config",
            str(cfg),
            "--reports-dir",
            str(tmp_path / "reports"),
        ]
    )
    assert code == 0
    report = (tmp_path / "reports" / "windows_errors.md").read_text(encoding="utf-8")
    for needle in (
        "## Матрица ошибок",
        "## Качество по размеру окна",
        "## Окна против потоков",
        "## Пропущенные атакующие окна",
    ):
        assert needle in report, needle
    assert "только окна" in capsys.readouterr().out
