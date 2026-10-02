"""Оценка переноса модели на набор стенда (фича 006, US5, FR-022/FR-023, R16).

Порог берётся из артефакта (не подбирается на стенде), считаются PR-AUC macro и «атака/нет»,
поимка по сценариям, FPR и ложные инциденты на норме; для слабого сценария — причина из трёх.
Модель — настоящий крошечный детектор на синтетике; набор — синтетические потоки с метками
стенда.
"""

from pathlib import Path

import polars as pl
import pytest

from mlsiem.detect.ensemble import load_model
from mlsiem.lab.dataset import AMBIGUOUS, BENIGN
from mlsiem.lab.evaluate import (
    OUT_OF_DISTRIBUTION,
    OUT_OF_TAXONOMY,
    SENSOR_LOSSES,
    _explain,
    evaluate_dataset,
    write_report,
)

REPO = Path(__file__).parents[2]


@pytest.fixture
def model(tiny_detector):
    return load_model(tiny_detector)


@pytest.fixture
def labeled(synthetic_flows, model):
    """Синтетические потоки с метками стенда: benign + один класс-сценарий + немного ambiguous."""
    df = pl.concat(list(synthetic_flows.values()), how="diagonal_relaxed")
    cls = next(c for c in model.classes if c != BENIGN)
    label = (
        pl.when(pl.col("label") == BENIGN)
        .then(pl.lit(BENIGN))
        .otherwise(pl.lit(cls))
        .alias("label")
    )
    df = df.with_columns(label)
    # Пометим каждый 10-й поток как ambiguous — он должен выпасть из метрик
    idx = pl.int_range(pl.len()).alias("i")
    df = (
        df.with_columns(idx)
        .with_columns(
            pl.when((pl.col("i") % 10 == 0) & (pl.col("label") != BENIGN))
            .then(pl.lit(AMBIGUOUS))
            .otherwise(pl.col("label"))
            .alias("label")
        )
        .drop("i")
    )
    return df, cls


def _records(cls, catch_threshold=0.3):
    from mlsiem.lab import journal

    return [
        journal.make_record(
            name=cls,
            version="1",
            attacker_ip="10.88.0.30",
            targets=["10.88.0.20"],
            expected_class=cls,
            started_at="2026-10-01T12:00:00.000Z",
            ended_at="2026-10-01T12:01:00.000Z",
            outcome="completed",
        )
    ]


def test_threshold_from_artifact_and_structure(model, labeled):
    df, cls = labeled
    rep = evaluate_dataset(model, df, _records(cls))
    assert rep["threshold"] == pytest.approx(model.threshold)  # порог из артефакта
    assert rep["n_ambiguous"] > 0
    assert rep["n_scored"] == df.height - rep["n_ambiguous"]  # ambiguous вне метрик
    assert rep["pr_auc_attack"] is None or 0.0 <= rep["pr_auc_attack"] <= 1.0
    assert cls in rep["catch_by_scenario"]
    assert 0.0 <= rep["catch_by_scenario"][cls]["caught_share"] <= 1.0
    assert rep["fpr_normal"] is None or 0.0 <= rep["fpr_normal"] <= 1.0


def test_custom_threshold_overrides(model, labeled):
    df, cls = labeled
    # Очень высокий порог → никто не пойман, FPR = 0
    rep = evaluate_dataset(model, df, _records(cls), threshold=2.0)
    assert rep["catch_by_scenario"][cls]["caught_share"] == 0.0
    assert rep["fpr_normal"] == 0.0 and rep["false_incidents"] == 0


def test_unexplained_when_below_catch_threshold(model, labeled):
    df, cls = labeled
    # Задираем порог скора так, что сценарий не пойман (0 < catch_threshold) → разбор R16
    rep = evaluate_dataset(model, df, _records(cls), threshold=2.0, catch_thresholds={cls: 0.3})
    assert rep["catch_by_scenario"][cls]["caught_share"] == 0.0
    assert len(rep["unexplained"]) == 1
    assert rep["unexplained"][0]["scenario_class"] == cls
    assert rep["unexplained"][0]["reason"] in (OUT_OF_DISTRIBUTION, SENSOR_LOSSES, OUT_OF_TAXONOMY)


def test_lossy_reason_takes_over(model, labeled):
    df, cls = labeled
    rep = evaluate_dataset(
        model, df, _records(cls), threshold=2.0, catch_thresholds={cls: 0.3}, lossy=True
    )
    assert rep["unexplained"][0]["reason"] == SENSOR_LOSSES


def test_explain_three_reasons():
    empty = pl.DataFrame()
    # (а) класс вне таксономии модели
    assert _explain("ssh_bruteforce", ["benign", "dos"], empty, False, None) == OUT_OF_TAXONOMY
    # (в) потери сенсора
    assert _explain("dos", ["benign", "dos"], empty, True, None) == SENSOR_LOSSES
    # (б) по умолчанию — вне распределения train
    assert _explain("dos", ["benign", "dos"], empty, False, None) == OUT_OF_DISTRIBUTION


def test_write_report_files(model, labeled, tmp_path):
    df, cls = labeled
    rep = evaluate_dataset(model, df, _records(cls))
    md, js = write_report(rep, tmp_path, "v1")
    assert md.exists() and js.exists()
    import json

    saved = json.loads(js.read_text(encoding="utf-8"))
    assert saved["threshold"] == rep["threshold"]
    assert "Поимка по сценариям" in md.read_text(encoding="utf-8")
