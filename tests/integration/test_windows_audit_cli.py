"""`detect windows-audit` целиком на синтетике (фича 007, US2, contracts/cli.md)."""

import json
import shutil

import pytest
import yaml

from fixtures.small_configs import small_windows_raw
from mlsiem.cli import main
from mlsiem.detect.windows import parse_windows_config
from mlsiem.detect.windows_audit import run_windows_audit


@pytest.fixture
def model_copy(tiny_windows, tmp_path):
    dst = tmp_path / "windows"
    shutil.copytree(tiny_windows, dst)
    return dst


def test_audit_report_and_card(model_copy, synthetic_split, tmp_path):
    cfg = parse_windows_config(small_windows_raw(tmp_path))
    before = json.loads((model_copy / "window_card.json").read_text(encoding="utf-8"))
    audit, card = run_windows_audit(
        cfg,
        model_dir=model_copy,
        data_dir=synthetic_split,
        reports_dir=tmp_path / "reports",
        mlflow_dir=None,
    )
    assert audit["verdict"] in ("clean", "relies_on_artifacts")
    assert audit["inputs"]["forbidden"] == []
    assert card["window_version"] == before["window_version"]
    d = card["decision"]
    assert d["audit_verdict"] == audit["verdict"]
    assert d["accepted"] is (d["passed_selection"] and audit["verdict"] == "clean")
    assert audit["transfer"]["split"] == "unsw_cross_day" and audit["transfer"]["n_windows"] > 0
    assert set(audit["per_attacker"]["winner"]) == {"val", "test"}
    report = (tmp_path / "reports" / "windows_audit.md").read_text(encoding="utf-8")
    for needle in (
        "## 1. Состав входов",
        "## 2. Важность признаков",
        "## 3. Одиночные признаки",
        "## 4. Повтор без подозрительных",
        "## 5. Перенос",
        "## 6. Полнота по атакующим адресам",
        "Вердикт",
        "оговорка 002",
    ):
        assert needle in report, needle


def test_audit_retrains_without_data_audit_fields(model_copy, synthetic_split, tmp_path):
    """Поле, помеченное аудитом 001, убирается из входа, и модель переобучается."""
    import polars as pl

    data = tmp_path / "data"
    shutil.copytree(synthetic_split, data)
    (data / "audit").mkdir(exist_ok=True)
    pl.DataFrame(
        {"field": ["bidirectional_bytes"], "variant": ["raw"], "status": ["suspicious"]}
    ).write_parquet(data / "audit" / "unsw_time.parquet")
    cfg = parse_windows_config(small_windows_raw(tmp_path))
    audit, _ = run_windows_audit(
        cfg, model_dir=model_copy, data_dir=data, reports_dir=tmp_path / "r", mlflow_dir=None
    )
    rt = audit["retrain"]
    assert rt["done"]
    assert {"f_bidirectional_bytes_mean", "f_bidirectional_bytes_max"} <= set(rt["removed"])
    assert rt["drop"] == pytest.approx(
        audit["base"]["macro_pr_auc_reliable_val"] - rt["macro_pr_auc_reliable_val"]
    )


def test_cli_audit(model_copy, synthetic_split, tmp_path, capsys):
    cfg = tmp_path / "windows.yaml"
    cfg.write_text(yaml.safe_dump(small_windows_raw(tmp_path)), encoding="utf-8")
    code = main(
        [
            "detect",
            "--data-dir",
            str(synthetic_split),
            "windows-audit",
            "--model",
            str(model_copy),
            "--config",
            str(cfg),
            "--reports-dir",
            str(tmp_path / "reports"),
            "--no-mlflow",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "Вердикт:" in out and "accepted =" in out
    assert (tmp_path / "reports" / "windows_audit.md").exists()


def test_cli_audit_without_experiment_exit_1(model_copy, synthetic_split, tmp_path):
    (model_copy / "experiment.json").unlink()
    cfg = tmp_path / "windows.yaml"
    cfg.write_text(yaml.safe_dump(small_windows_raw(tmp_path)), encoding="utf-8")
    code = main(
        [
            "detect",
            "--data-dir",
            str(synthetic_split),
            "windows-audit",
            "--model",
            str(model_copy),
            "--config",
            str(cfg),
            "--no-mlflow",
        ]
    )
    assert code == 1
