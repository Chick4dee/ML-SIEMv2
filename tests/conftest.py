"""Общие фикстуры тестов: синтетические PCAP (001) и синтетические потоки/разбиения (002)."""

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def synthetic_pcap() -> Path:
    return FIXTURES / "synthetic.pcap"


@pytest.fixture
def synthetic_pcapng() -> Path:
    return FIXTURES / "synthetic.pcapng"


@pytest.fixture
def truncated_pcap() -> Path:
    return FIXTURES / "truncated.pcap"


# ---------------------------------------------------------------- фича 002


@pytest.fixture(scope="session")
def synthetic_flows():
    """capture_id → таблица синтетических потоков со всеми колонками схемы 001."""
    from fixtures.make_synthetic_flows import make_synthetic_flows

    return make_synthetic_flows()


@pytest.fixture(scope="session")
def synthetic_split(tmp_path_factory) -> Path:
    """Каталог data/ в формате 001: потоки UNSW и разбиения unsw_time, unsw_cross_day.

    Один на всю сессию (строится ~секунду) — тесты его только читают, не меняют.
    """
    from fixtures.make_synthetic_flows import build_synthetic_split

    return build_synthetic_split(tmp_path_factory.mktemp("synthetic") / "data")


@pytest.fixture(scope="session")
def tiny_detector(synthetic_split, tmp_path_factory) -> Path:
    """Детектор, обученный настоящим `run_experiment` на синтетике, — для тестов US2–US5.

    Модели маленькие (секунды обучения), всё остальное — как в бою: те же кандидаты,
    порог по val, карточка, версия схемы.
    """
    from mlsiem.detect.config import parse_detect_config
    from mlsiem.detect.experiment import run_experiment

    root = tmp_path_factory.mktemp("tiny_detector")
    cfg = parse_detect_config(
        {
            "split": "unsw_time",
            "transfer_split": "unsw_cross_day",
            "seed": 42,
            "selection": {"metric": "macro_pr_auc_val", "min_gain": 0.01},
            "candidates": {
                "logreg": {"C": 1.0, "max_iter": 300, "class_weight": "balanced"},
                "lgbm": {
                    "n_estimators": 30,
                    "learning_rate": 0.1,
                    "num_leaves": 15,
                    "class_weight": "balanced",
                },
            },
            "output": str(root / "detector"),
        }
    )
    run_experiment(cfg, data_dir=synthetic_split, reports_dir=root / "reports", mlflow_dir=root)
    return root / "detector"
