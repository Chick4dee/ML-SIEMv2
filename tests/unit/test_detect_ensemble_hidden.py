"""Эксперимент «скрытый класс» (FR-011, research R5): класс действительно спрятан.

Копия классификатора учится БЕЗ строк скрытого класса (не перемаркированных в benign), с
кандидатом и гиперпараметрами из experiment.json детектора 002; мета-слой скрытого
эксперимента тоже не видит этих строк. «Шпионы» записывают, на чём шло обучение.
"""

import json

import numpy as np
import pytest

from fixtures.small_configs import small_ensemble_raw
from mlsiem.detect import candidates as cand_mod
from mlsiem.detect import meta as meta_mod
from mlsiem.detect.config import parse_ensemble_config
from mlsiem.detect.ensemble import run_ensemble_experiment


@pytest.fixture(scope="module")
def spied(synthetic_split, tiny_detector, tmp_path_factory):
    root = tmp_path_factory.mktemp("hidden")
    fits: list[dict] = []
    stack_fits: list[dict] = []
    real_build = cand_mod.build_candidate
    real_stack_fit = meta_mod.StackModel.fit

    def spy_build(name, params, seed):
        pipe = real_build(name, params, seed)
        real_fit = pipe.fit

        def fit(X, y, **kw):
            fits.append({"name": name, "params": dict(params), "labels": set(np.unique(y))})
            return real_fit(X, y, **kw)

        pipe.fit = fit
        return pipe

    def spy_stack_fit(self, X, y):
        stack_fits.append({"classes": list(self.classes), "labels": set(np.unique(y))})
        return real_stack_fit(self, X, y)

    mp = pytest.MonkeyPatch()
    mp.setattr(cand_mod, "build_candidate", spy_build)
    mp.setattr(meta_mod.StackModel, "fit", spy_stack_fit)
    try:
        cfg = parse_ensemble_config(small_ensemble_raw(tiny_detector, root))
        exp = run_ensemble_experiment(
            cfg, data_dir=synthetic_split, reports_dir=root / "reports", mlflow_dir=root
        )
    finally:
        mp.undo()
    return exp, fits, stack_fits, tiny_detector


def test_classifier_copy_trained_without_class(spied):
    exp, fits, _, detector_dir = spied
    det_exp = json.loads((detector_dir / "experiment.json").read_text(encoding="utf-8"))
    winner = det_exp["winner"]
    assert [f["name"] for f in fits] == [winner, winner]  # по одной копии на скрытый класс
    for f, h in zip(fits, ("exploits", "dos"), strict=True):
        assert h not in f["labels"], f"копия классификатора видела скрытый класс {h}"
        assert "benign" in f["labels"]
        assert f["params"] == det_exp["config"]["candidates"][winner]
    # строки удалены, а не перемаркированы: остальные классы на месте
    assert fits[0]["labels"] == {"benign", "dos", "reconnaissance", "fuzzers"}


def test_meta_of_hidden_does_not_see_class(spied):
    _, _, stack_fits, _ = spied
    hidden_fits = [s for s in stack_fits if len(s["classes"]) == 4]
    assert hidden_fits, "мета-слой скрытых экспериментов не обучался"
    for s in hidden_fits:
        missing = {"benign", "dos", "exploits", "reconnaissance", "fuzzers"} - set(s["classes"])
        (h,) = missing
        assert h not in s["labels"]


def test_catch_recorded(spied):
    exp, *_ = spied
    assert [h["class"] for h in exp["hidden_class"]] == ["exploits", "dos"]
    for h in exp["hidden_class"]:
        for who in ("classifier_without_class", "anomaly"):
            for part in ("val", "test"):
                v = h["catch"][who][part]
                assert v is None or 0 <= v <= 1
        for v in exp["config"]["meta"]["candidates"]:
            row = h["variants"][v]
            assert set(row) >= {"threshold", "val", "test", "gain_val"}
    # SC-002: доля нормы test, ставшей алертом только из-за аномалий, записана у мета-вариантов
    for v in exp["variants"][1:]:
        assert v["test"]["benign_alert_only_anomaly"] is not None


def test_hidden_class_not_in_classifier(synthetic_split, tiny_detector, tmp_path):
    raw = small_ensemble_raw(tiny_detector, tmp_path, hidden_classes=["worms"])
    with pytest.raises(ValueError, match="hidden_classes"):
        run_ensemble_experiment(
            parse_ensemble_config(raw),
            data_dir=synthetic_split,
            reports_dir=tmp_path,
            mlflow_dir=tmp_path,
        )
