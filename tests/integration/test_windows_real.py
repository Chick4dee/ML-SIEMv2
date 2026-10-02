"""Окна на настоящем `unsw_time` (фича 007, T029, SC-001, SC-004). Нужны данные 001 в data/.

Числа окон сверяются с замером research.md (2026-09-26): train ≈14.5 тыс., val ≈2.3 тыс.,
test ≈2.6 тыс. на основной сетке. Допуск 10%: ключ окна (атакующая сторона по правилу
направления) мог чуть сдвинуться с момента замера, а порядок величин — нет.
"""

import time
from pathlib import Path

import polars as pl
import pytest

from mlsiem.detect.windows import build_part_windows, load_windows_config

pytestmark = pytest.mark.slow

DATA = Path("data")
EXPECTED = {"train": 14_500, "val": 2_300, "test": 2_600}


@pytest.fixture(scope="module")
def cfg():
    if not (DATA / "splits" / "unsw_time.parquet").exists():
        pytest.skip("нет данных 001 (data/splits/unsw_time.parquet)")
    return load_windows_config("configs/windows.yaml")


@pytest.fixture(scope="module")
def parts(cfg):
    return {
        p: build_part_windows(cfg.split, p, cfg, data_dir=DATA, direction="auto") for p in EXPECTED
    }


@pytest.mark.parametrize("part", list(EXPECTED))
def test_window_counts_close_to_research(parts, part):
    n = parts[part].windows.height
    assert abs(n - EXPECTED[part]) <= 0.10 * EXPECTED[part], f"{part}: {n} окон"


def test_windows_do_not_cross_parts(parts):
    """SC-004: поток принадлежит окнам только своей части, и окна частей не пересекаются
    по потокам (у каждой части свои flow_uid)."""
    uids = {p: set(pw.assignment["flow_uid"].to_list()) for p, pw in parts.items()}
    assert not (uids["train"] & uids["val"])
    assert not (uids["train"] & uids["test"])
    assert not (uids["val"] & uids["test"])
    for p, pw in parts.items():
        assert uids[p] <= set(pw.flows["flow_uid"].to_list()), p
        assert pw.windows.filter(pl.col("part") != p).height == 0


def test_experiment_skip_nn_under_30_min(cfg, tmp_path):
    """Эксперимент без нейросети (бустинг + текущая модель) укладывается в 30 минут."""
    from mlsiem.detect.windows_experiment import run_windows_experiment

    started = time.perf_counter()
    exp = run_windows_experiment(
        cfg,
        skip_nn=True,
        output=tmp_path / "windows",
        mlflow_dir=None,
        data_dir=DATA,
        reports_dir=tmp_path / "reports",
    )
    assert time.perf_counter() - started <= 30 * 60
    assert exp["selection"]["winner"] == "lgbm"
