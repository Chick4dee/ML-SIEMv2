"""Эксперимент окон целиком на синтетике (фича 007, US1, SC-002, SC-003)."""

import json

import pytest

from fixtures.small_configs import small_windows_raw
from mlsiem.cli import main
from mlsiem.detect.windows import parse_windows_config
from mlsiem.detect.windows_experiment import run_windows_experiment


def test_outputs_and_report(tiny_windows_experiment):
    root, exp = tiny_windows_experiment["root"], tiny_windows_experiment["exp"]
    model = tiny_windows_experiment["model"]
    assert (model / "window_card.json").exists() and (model / "experiment.json").exists()
    assert set(exp["participants"]) == {"lgbm", "current"}
    assert set(exp["mlflow_runs"]) == {"lgbm", "current"}
    assert exp["decision"]["audit_verdict"] == "not_run" and not exp["decision"]["accepted"]
    report = (root / "reports" / "windows_experiment.md").read_text(encoding="utf-8")
    for needle in (
        "бустинг окон",
        "текущая модель",
        "macro надёжных",
        "macro всех",
        "атака/нет",
        "ненадёжен",
        "усечённых",
        "смешанных",
        "Устройство",
        "Воспроизводимость",
        "шаг 1 пропущен",
    ):
        assert needle in report, needle
    saved = json.loads((model / "experiment.json").read_text(encoding="utf-8"))
    assert saved["selection"]["winner"] == "lgbm"


def test_repeat_same_seed_same_boosting(
    tiny_windows_experiment, synthetic_split, tiny_detector, tmp_path
):
    """SC-003: повтор с тем же сидом — macro бустинга до 0.001 (здесь — точно)."""
    cfg = parse_windows_config(small_windows_raw(tmp_path))
    again = run_windows_experiment(
        cfg,
        skip_nn=True,
        mlflow_dir=None,
        data_dir=synthetic_split,
        reports_dir=tmp_path / "reports",
        current_dir=tiny_detector,
    )
    first = tiny_windows_experiment["exp"]["participants"]["lgbm"]
    second = again["participants"]["lgbm"]
    for part in ("val", "test"):
        diff = first[part]["macro_pr_auc_reliable"] - second[part]["macro_pr_auc_reliable"]
        assert abs(diff) <= 0.001
    assert first["threshold"] == second["threshold"]
    assert again["window_version"] == tiny_windows_experiment["exp"]["window_version"]


@pytest.mark.nn
def test_with_gru_on_cpu(synthetic_split, tiny_detector, tmp_path):
    pytest.importorskip("torch")
    cfg = parse_windows_config(small_windows_raw(tmp_path))
    exp = run_windows_experiment(
        cfg,
        device="cpu",
        mlflow_dir=tmp_path,
        data_dir=synthetic_split,
        reports_dir=tmp_path / "reports",
        current_dir=tiny_detector,
    )
    assert set(exp["participants"]) == {"lgbm", "gru", "current"}
    assert set(exp["mlflow_runs"]) == {"lgbm", "gru", "current"}
    assert exp["participants"]["gru"]["epochs"] <= 2
    assert not exp["selection"]["step1"]["skipped"]
    report = (tmp_path / "reports" / "windows_experiment.md").read_text(encoding="utf-8")
    assert "нейросеть окон" in report and "## Нейросеть" in report


def test_cli_without_torch_exit_1(monkeypatch, tmp_path, capsys):
    """contracts/cli.md: нет PyTorch и не указан --skip-nn → код 1 с подсказкой."""
    import yaml

    import mlsiem.detect.windows_nn as nn

    cfg = tmp_path / "windows.yaml"
    cfg.write_text(yaml.safe_dump(small_windows_raw(tmp_path)), encoding="utf-8")
    monkeypatch.setattr(nn, "torch_available", lambda: False)
    code = main(["detect", "windows", "--config", str(cfg)])
    assert code == 1
    assert not (tmp_path / "windows").exists()
