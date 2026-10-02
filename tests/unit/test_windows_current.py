"""Текущая модель на окнах (фича 007, R7): оценка окна по классу — максимум по потокам,
скор — максимум attack_score, столбцы — в порядке классов модели."""

import numpy as np
import polars as pl

from mlsiem.detect import windows as W
from mlsiem.detect.ensemble import load_model
from mlsiem.detect.windows_experiment import current_on_windows
from mlsiem.soc.direction import sides


def test_max_over_window_flows(tiny_detector, synthetic_flows):
    model = load_model(tiny_detector)
    flows = next(iter(synthetic_flows.values())).head(600)
    side = sides(flows, "auto").select(W.SIDE_COLUMNS)
    a = W.assign_windows(flows, side, length_ms=60_000)
    w = W.build_windows(flows, side, length_ms=60_000, seq_max=128, assignment=a)
    proba, score = current_on_windows(model, flows, a, w)
    assert proba.shape == (w.height, len(model.classes))
    v = model.verdict_frame(flows).join(a.select("flow_uid", "window_id"), on="flow_uid")
    for i in (0, w.height // 2, w.height - 1):
        mine = v.filter(pl.col("window_id") == w["window_id"][i])
        for j, c in enumerate(model.classes):
            assert proba[i, j] == mine[f"p_{c}"].max()
        assert score[i] == mine["attack_score"].max()
    assert np.all(score >= 0)
