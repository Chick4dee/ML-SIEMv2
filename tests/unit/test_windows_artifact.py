"""Артефакт модели окон (фича 007, R11): круговая запись, поля карточки, строгие отказы."""

import json
import shutil

import pytest

from mlsiem.detect import windows_expert as WE


def _copy(src, tmp_path):
    dst = tmp_path / "windows"
    shutil.copytree(src, dst)
    return dst


def _edit_card(d, fn):
    card = json.loads((d / WE.CARD_FILE).read_text(encoding="utf-8"))
    fn(card)
    (d / WE.CARD_FILE).write_text(json.dumps(card), encoding="utf-8")


def test_card_fields(tiny_windows):
    card = json.loads((tiny_windows / WE.CARD_FILE).read_text(encoding="utf-8"))
    for key in (*WE.REQUIRED_CARD_FIELDS, "current_model", "data", "seed", "device", "libraries"):
        assert key in card
    assert card["kind"] == "lgbm"
    assert card["window"] == {
        "length_ms": 60000,
        "key": "attacker_ip",
        "direction": "auto",
        "seq_max": 32,
    }
    d = card["decision"]
    assert d["accepted"] is False and d["audit_verdict"] == "not_run"
    assert set(d["values"]) >= {"lgbm", "current"}
    assert (tiny_windows / WE.EXPERIMENT_FILE).exists()


def test_roundtrip_with_force(tiny_windows):
    ex = WE.load_window_expert(tiny_windows, force=True)
    assert ex.kind == "lgbm" and ex.classes == [str(c) for c in ex.model.classes_]
    assert ex.length_ms == 60000 and not ex.accepted


def test_not_accepted_without_force(tiny_windows):
    with pytest.raises(WE.WindowExpertNotAccepted, match="не принята"):
        WE.load_window_expert(tiny_windows)


def test_missing_files(tmp_path, tiny_windows):
    with pytest.raises(WE.WindowExpertLoadError, match="detect windows"):
        WE.load_window_expert(tmp_path / "nothing", force=True)
    d = _copy(tiny_windows, tmp_path)
    (d / WE.LGBM_FILE).unlink()
    with pytest.raises(WE.WindowExpertLoadError, match="нет файла модели"):
        WE.load_window_expert(d, force=True)


def test_broken_card(tmp_path, tiny_windows):
    d = _copy(tiny_windows, tmp_path)
    (d / WE.CARD_FILE).write_text("{не json", encoding="utf-8")
    with pytest.raises(WE.WindowExpertLoadError, match="повреждён"):
        WE.load_window_expert(d, force=True)


@pytest.mark.parametrize("field", ["classes", "threshold", "decision", "window"])
def test_missing_card_field(tmp_path, tiny_windows, field):
    d = _copy(tiny_windows, tmp_path)
    _edit_card(d, lambda c: c.pop(field))
    with pytest.raises(WE.WindowExpertLoadError, match=field):
        WE.load_window_expert(d, force=True)


def test_foreign_schema_major(tmp_path, tiny_windows):
    d = _copy(tiny_windows, tmp_path)
    _edit_card(d, lambda c: c.update(schema_version="9.0.0"))
    with pytest.raises(WE.WindowExpertLoadError, match="мажорные"):
        WE.load_window_expert(d, force=True)


def test_classes_mismatch(tmp_path, tiny_windows):
    d = _copy(tiny_windows, tmp_path)
    _edit_card(d, lambda c: c.update(classes=c["classes"][::-1]))
    with pytest.raises(WE.WindowExpertLoadError, match="не совпадают"):
        WE.load_window_expert(d, force=True)


def test_gru_without_torch_explains(tmp_path, tiny_windows, monkeypatch):
    import mlsiem.detect.windows_nn as nn

    d = _copy(tiny_windows, tmp_path)
    _edit_card(
        d, lambda c: c.update(kind="gru", gru_params={"proj": 4, "hidden": 4, "dropout": 0.0})
    )
    (d / WE.GRU_FILE).write_bytes(b"x")

    def no_torch():
        raise nn.NNUnavailable(f"нет PyTorch — {nn.INSTALL_HINT}")

    monkeypatch.setattr(nn, "require_torch", no_torch)
    with pytest.raises(WE.WindowExpertLoadError, match="uv sync --extra nn"):
        WE.load_window_expert(d, force=True)


@pytest.mark.nn
def test_gru_roundtrip(tmp_path, tiny_windows, synthetic_flows):
    """Модель вида gru: сохранение весов и предобработки, загрузка, вердикты на CPU."""
    pytest.importorskip("torch")
    import polars as pl

    from mlsiem.detect import windows as W
    from mlsiem.detect.windows_nn import build_gru
    from mlsiem.soc.direction import sides

    src = WE.load_window_expert(tiny_windows, force=True)
    params = {"proj": 8, "hidden": 8, "dropout": 0.0}
    flows = pl.concat(list(synthetic_flows.values())).head(800)
    card = {**src.card, "kind": "gru", "gru_params": params}
    net = build_gru(len(card["seq_features"]), len(card["classes"]), params).eval()
    scaler = W.fit_seq_scaler(flows, 60000)
    WE.save_window_expert(
        tmp_path / "g", kind="gru", model=net, preprocess={"scaler": scaler}, card=card
    )
    assert not (tmp_path / "g" / WE.LGBM_FILE).exists()
    ex = WE.load_window_expert(tmp_path / "g", force=True)
    res = ex.verdicts(flows, sides(flows, "auto"))
    assert res.verdicts.height == res.windows.height > 0
    assert res.top_features == {}
