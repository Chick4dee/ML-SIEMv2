"""Нейросеть окон (фича 007, R5): маска, обучение, ранняя остановка, сохранение, сид.
Всё на CPU и на крошечных данных; без PyTorch тесты пропускаются."""

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from mlsiem.detect.windows_nn import (  # noqa: E402
    SeqData,
    build_gru,
    class_weights,
    load_state,
    predict_gru,
    save_state,
    train_gru,
)

pytestmark = pytest.mark.nn
PARAMS = {
    "proj": 8,
    "hidden": 8,
    "dropout": 0.0,
    "lr": 0.01,
    "weight_decay": 0.0,
    "batch": 32,
    "max_epochs": 2,
    "patience": 1,
    "class_weight_cap": 50,
    "amp": False,
}


def _data(n=200, t=6, f=5, seed=0) -> SeqData:
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n, t, f)).astype(np.float32)
    y = (rng.random(n) < 0.4).astype(np.int64)
    X[y == 1, :, 0] += 2.0  # класс 1 заметен по первому каналу
    lengths = rng.integers(1, t + 1, size=n)
    mask = np.arange(t)[None, :] < lengths[:, None]
    X[~mask] = 0.0
    scalars = rng.normal(size=(n, 4)).astype(np.float32)
    return SeqData(X, mask, scalars, y)


def test_padding_does_not_change_output():
    torch.manual_seed(0)
    model = build_gru(5, 2, PARAMS).eval()
    d = _data(n=4)
    garbage = d.X.copy()
    garbage[~d.mask] = 123.0
    a = predict_gru(model, d)
    b = predict_gru(model, SeqData(garbage, d.mask, d.scalars))
    np.testing.assert_allclose(a, b, atol=1e-6)


def test_training_reduces_loss_and_early_stops():
    d = _data()
    params = {**PARAMS, "max_epochs": 30, "patience": 2}
    model, hist = train_gru(
        d.take(np.arange(160)), d.take(np.arange(160, 200)), 2, params, seed=1, device="cpu"
    )
    assert hist.train_loss[-1] < hist.train_loss[0]
    assert hist.epochs < 30  # хвост перестал улучшаться — остановились раньше
    assert hist.best_epoch == int(np.argmin(hist.holdout_loss)) + 1


def test_save_load_same_probabilities(tmp_path):
    d = _data()
    model, _ = train_gru(d, None, 2, PARAMS, seed=3, device="cpu")
    save_state(model, tmp_path / "m.pt")
    again = load_state(tmp_path / "m.pt", 5, 2, PARAMS)
    np.testing.assert_allclose(predict_gru(model, d), predict_gru(again, d), atol=1e-7)


def test_same_seed_same_result_on_cpu():
    d = _data()
    m1, _ = train_gru(d, None, 2, PARAMS, seed=5, device="cpu")
    m2, _ = train_gru(d, None, 2, PARAMS, seed=5, device="cpu")
    np.testing.assert_allclose(predict_gru(m1, d), predict_gru(m2, d), atol=1e-6)


def test_class_weights_capped():
    w = class_weights(np.array([0] * 1000 + [1]), 3, cap=50)
    assert w[1] == 50 and w[2] == 0 and w[0] < 1
