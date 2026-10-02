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


# ---------------------------------------------------------------- фича 004


@pytest.fixture(scope="session")
def tiny_ensemble(synthetic_split, tiny_detector, tmp_path_factory) -> Path:
    """Ансамбль, собранный настоящим `run_ensemble_experiment` на синтетике, — для тестов
    цепочки, API и консоли (US3).

    Выбор подменён: `force_variant="stack_logreg"` — только ключевой аргумент функции, не
    ключ конфига и не флаг CLI. Нужен для тестов цепочки, а не для выводов: у цепочки всегда
    должны быть два эксперта и обучаемый мета-слой, что бы ни выбрал эксперимент на синтетике.
    """
    from fixtures.small_configs import small_ensemble_raw
    from mlsiem.detect.config import parse_ensemble_config
    from mlsiem.detect.ensemble import run_ensemble_experiment

    root = tmp_path_factory.mktemp("tiny_ensemble")
    cfg = parse_ensemble_config(small_ensemble_raw(tiny_detector, root))
    run_ensemble_experiment(
        cfg,
        data_dir=synthetic_split,
        reports_dir=root / "reports",
        mlflow_dir=root,
        force_variant="stack_logreg",
    )
    return root / "ensemble"


# ---------------------------------------------------------------- фича 007


@pytest.fixture(scope="session", autouse=True)
def _no_repo_window_model():
    """Тесты 002–005 берут configs/soc.yaml из репозитория, а там `windows.mode: auto` и
    `windows.model: models/windows` — рабочая модель окон владельца. Если её примет аудит, то
    старые тесты цепочки вдруг получили бы алерты окон. Поэтому в тестах режим auto
    не видит рабочую модель репозитория; тесты 007 указывают модель явно (tiny_windows).

    Уровень — вся сессия, а не функция: эталоны в тестах 005 — фикстуры уровня модуля, и
    функциональная подмена до них не доходила. Пока рабочая модель была не принята, этого не
    было видно; после аудита 2026-09-26 (accepted: true) эталон надёжности 005 молча получил
    алерты окон, а проверяемый прогон — нет."""
    import mlsiem.detect.windows_expert as we

    monkeypatch = pytest.MonkeyPatch()

    real = we.resolve_window_expert
    repo_model = (Path(__file__).parents[1] / "models" / "windows").resolve()

    def guarded(soc_cfg, mode=None, path=None):
        chosen_mode = mode or soc_cfg.windows.mode
        chosen_path = Path(path or soc_cfg.windows.model).resolve()
        if chosen_mode == "auto" and chosen_path == repo_model:
            return we.WindowsChoice("auto", None, "рабочая модель репозитория в тестах не видна")
        return real(soc_cfg, mode, path)

    monkeypatch.setattr(we, "resolve_window_expert", guarded)
    yield
    monkeypatch.undo()


@pytest.fixture(scope="session")
def tiny_windows_experiment(synthetic_split, tiny_detector, tmp_path_factory) -> dict:
    """Эксперимент окон настоящим `run_windows_experiment` на синтетике (быстрый путь
    --skip-nn: только бустинг и текущая модель) — модель, протокол, отчёт."""
    from fixtures.small_configs import small_windows_raw
    from mlsiem.detect.windows import parse_windows_config
    from mlsiem.detect.windows_experiment import run_windows_experiment

    root = tmp_path_factory.mktemp("tiny_windows")
    cfg = parse_windows_config(small_windows_raw(root))
    exp = run_windows_experiment(
        cfg,
        skip_nn=True,
        mlflow_dir=root,
        data_dir=synthetic_split,
        reports_dir=root / "reports",
        current_dir=tiny_detector,
    )
    return {"root": root, "model": root / "windows", "exp": exp, "cfg": cfg}


@pytest.fixture(scope="session")
def tiny_windows(tiny_windows_experiment) -> Path:
    """Модель окон lgbm на синтетике с `accepted: false` (на синтетике окна не лучше потоков:
    обе модели идеальны) — для тестов цепочки через `force`, как `force_variant` в 004."""
    return tiny_windows_experiment["model"]
