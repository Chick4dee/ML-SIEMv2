"""Эксперт аномалий: учится только на норме, шкала-перцентиль, порог по норме val, артефакт.

Главное здесь — правила честности (принцип III): в обучении и калибровке нет ни одного
потока атаки, выборки не пересекаются, метки атак в выборе порога не участвуют.
"""

import json

import numpy as np
import polars as pl
import pytest

from fixtures.small_configs import small_ensemble_raw
from mlsiem.data.schema import SCHEMA
from mlsiem.detect.anomaly import (
    AutoencoderModel,
    anomaly_features,
    build_anomaly_candidate,
    choose_anomaly_threshold,
    fit_anomaly_expert,
    load_anomaly_expert,
    load_benign_sample,
    percentile,
    save_anomaly_expert,
    select_anomaly_candidate,
)
from mlsiem.detect.artifact import DetectorLoadError
from mlsiem.detect.config import parse_ensemble_config
from mlsiem.detect.dataset import data_hashes, load_part


def _cfg(tmp_path, **anomaly):
    raw = small_ensemble_raw(tmp_path / "detector", tmp_path)
    raw["anomaly"].update(anomaly)
    return parse_ensemble_config(raw)


def _fit(cfg, data_dir, y_val=None):
    feats = anomaly_features(cfg.anomaly.exclude_features)
    val = load_part(cfg.split, "val", data_dir=data_dir)
    test = load_part(cfg.split, "test", data_dir=data_dir)
    return fit_anomaly_expert(
        cfg,
        data_dir=data_dir,
        X_val=val.X.select(feats).to_numpy(),
        y_val=val.y if y_val is None else y_val,
        X_test=test.X.select(feats).to_numpy(),
        y_test=test.y,
        data=data_hashes(cfg.split, data_dir),
    )


@pytest.fixture(scope="module")
def fitted(synthetic_split, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("anomaly")
    cfg = _cfg(tmp)
    expert, section = _fit(cfg, synthetic_split)
    return cfg, expert, section


# ---------------------------------------------------------------- (а) только норма


def test_trained_on_benign_only(fitted, synthetic_split):
    _, _, section = fitted
    labels = dict(
        pl.concat(
            [
                pl.read_parquet(p, columns=["flow_uid", "label"])
                for p in (synthetic_split / "flows" / "unsw").glob("*.parquet")
            ]
        ).iter_rows()
    )
    train_uids = section["benign_uids"]["train"]
    cal_uids = section["benign_uids"]["calibration"]
    assert len(train_uids) and len(cal_uids)
    assert all(labels[u] == "benign" for u in train_uids)
    assert all(labels[u] == "benign" for u in cal_uids)
    assert not set(train_uids) & set(cal_uids)
    # и всё это — из train-части разбиения
    split = pl.read_parquet(synthetic_split / "splits" / "unsw_time.parquet")
    train_part = set(split.filter(pl.col("part") == "train")["flow_uid"])
    assert set(train_uids) | set(cal_uids) <= train_part


def test_benign_sample_respects_share(synthetic_split):
    s = load_benign_sample(
        "unsw_time",
        anomaly_features(),
        data_dir=synthetic_split,
        train_sample=1000,
        calibration_share=0.2,
        seed=1,
    )
    assert abs(len(s.uid_cal) / s.n_benign_total - 0.2) < 0.02
    assert abs(len(s.uid_train) - 1000) <= 5


# ---------------------------------------------------------------- (б) перцентиль


def test_percentile_range_and_monotonic():
    cal = np.sort(np.random.default_rng(0).normal(size=500))
    raw = np.linspace(-5, 5, 200)
    p = percentile(raw, cal)
    assert p.min() >= 0 and p.max() <= 1
    assert (np.diff(p) >= 0).all()
    assert p[0] == 0 and p[-1] == 1


# ---------------------------------------------------------------- (в) порог


def test_threshold_is_smallest_within_budget():
    rng = np.random.default_rng(0)
    pct = rng.random(2000)
    fpr = 0.01
    t = choose_anomaly_threshold(pct, fpr)
    assert (pct >= t).mean() <= fpr
    # чуть ниже порога бюджет уже превышен — значит, порог наименьший
    below = pct[pct < t].max()
    assert (pct >= below).mean() > fpr


def test_threshold_with_ties_goes_above():
    pct = np.ones(100)
    t = choose_anomaly_threshold(pct, 0.005)
    assert t > 1 and (pct >= t).mean() == 0


def test_threshold_ignores_attack_labels(fitted, synthetic_split, tmp_path):
    cfg, expert, _ = fitted
    val = load_part(cfg.split, "val", data_dir=synthetic_split)
    y = val.y.copy()
    attack = y != "benign"
    # Метки атак перемешаны и заменены на случайные классы атак; норма та же
    rng = np.random.default_rng(3)
    y[attack] = rng.choice(["dos", "exploits", "fuzzers"], size=int(attack.sum()))
    expert2, _ = _fit(cfg, synthetic_split, y_val=y)
    assert expert2.threshold == expert.threshold


def test_val_benign_budget(fitted, synthetic_split):
    cfg, expert, _ = fitted
    val = load_part(cfg.split, "val", data_dir=synthetic_split)
    pct = expert.score(val.X)
    benign = val.y == "benign"
    assert (pct[benign] >= expert.threshold).mean() <= cfg.anomaly.anomaly_fpr


# ---------------------------------------------------------------- (г) детерминизм


def test_reproducible(fitted, synthetic_split):
    cfg, expert, _ = fitted
    expert2, _ = _fit(cfg, synthetic_split)
    val = load_part(cfg.split, "val", data_dir=synthetic_split)
    assert np.array_equal(expert.score(val.X), expert2.score(val.X))
    assert expert.version == expert2.version


# ---------------------------------------------------------------- (д) карточка


def test_card_fields(fitted):
    _, expert, _ = fitted
    card = expert.card
    for f in (
        "expert_version",
        "name",
        "kind",
        "candidate",
        "features",
        "schema_version",
        "threshold",
        "anomaly_fpr",
        "train",
        "metrics",
    ):
        assert f in card
    assert card["name"] == "anomaly" and card["kind"] == "anomaly"
    assert card["train"]["benign_only"] is True
    assert set(card["features"]) <= set(SCHEMA.feature_columns())
    assert card["schema_version"] == SCHEMA.version
    assert card["candidate"] in ("iforest", "autoencoder")


# ---------------------------------------------------------------- (е) загрузка


def test_save_load_roundtrip(fitted, tmp_path, synthetic_split):
    cfg, expert, _ = fitted
    save_anomaly_expert(expert, tmp_path / "a")
    loaded = load_anomaly_expert(tmp_path / "a")
    val = load_part(cfg.split, "val", data_dir=synthetic_split)
    assert np.array_equal(loaded.score(val.X), expert.score(val.X))
    assert loaded.version == expert.version


@pytest.mark.parametrize("victim", ["model.joblib", "calibration.npy", "expert_card.json"])
def test_load_refuses_missing(fitted, tmp_path, victim):
    save_anomaly_expert(fitted[1], tmp_path / "a")
    (tmp_path / "a" / victim).unlink()
    with pytest.raises(DetectorLoadError, match=victim):
        load_anomaly_expert(tmp_path / "a")


def test_load_refuses_broken_json(fitted, tmp_path):
    save_anomaly_expert(fitted[1], tmp_path / "a")
    (tmp_path / "a" / "expert_card.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(DetectorLoadError, match="повреждён"):
        load_anomaly_expert(tmp_path / "a")


def test_check_input_names_expert(fitted):
    _, expert, _ = fitted
    from mlsiem.detect.artifact import DetectorInputError

    with pytest.raises(DetectorInputError, match="эксперт аномалий"):
        expert.check_input(SCHEMA.version, ["flow_uid"])
    with pytest.raises(DetectorInputError, match="несовместимая"):
        expert.check_input("9.0.0", expert.features)


def test_exclude_features_removed(synthetic_split, tmp_path):
    victim = anomaly_features()[3]
    cfg = _cfg(tmp_path, exclude_features=[victim])
    expert, _ = _fit(cfg, synthetic_split)
    assert victim not in expert.features
    assert len(expert.features) == len(anomaly_features()) - 1


# ---------------------------------------------------------------- US2: автокодировщик и выбор


def test_autoencoder_learns_benign_and_is_deterministic():
    rng = np.random.default_rng(0)
    X = np.expm1(rng.normal(3, 0.3, size=(800, 6)).clip(0))
    odd = np.expm1(rng.normal(6, 0.3, size=(50, 6)).clip(0))
    params = {"hidden": [8, 3, 8], "max_iter": 200}
    m1 = build_anomaly_candidate("autoencoder", params, 7).fit(X)
    m2 = build_anomaly_candidate("autoencoder", params, 7).fit(X)
    assert isinstance(m1, AutoencoderModel)
    assert np.array_equal(m1.raw_score(odd), m2.raw_score(odd))
    # Непохожее на норму восстанавливается хуже
    assert np.median(m1.raw_score(odd)) > np.median(m1.raw_score(X))
    mlp = m1.model
    assert mlp.hidden_layer_sizes == (8, 3, 8) and mlp.early_stopping


def test_select_candidate_rule():
    assert select_anomaly_candidate({"iforest": 0.80, "autoencoder": 0.85}, min_gain=0.01)[0] == (
        "autoencoder"
    )
    assert select_anomaly_candidate({"iforest": 0.80, "autoencoder": 0.805}, min_gain=0.01)[0] == (
        "iforest"
    )
    assert select_anomaly_candidate({"iforest": 0.90, "autoencoder": 0.85}, min_gain=0.01)[0] == (
        "iforest"
    )
    assert select_anomaly_candidate({"iforest": None, "autoencoder": None}, min_gain=0.01)[0] == (
        "iforest"
    )


def test_selection_uses_val_only(fitted):
    _, expert, section = fitted
    vals = {c["name"]: c["val"]["pr_auc_binary"] for c in section["candidates"]}
    winner, _ = select_anomaly_candidate(vals, min_gain=0.01)
    assert winner == section["winner"] == expert.card["candidate"]
    for c in section["candidates"]:
        assert "test" in c and "val" in c
    assert json.dumps(expert.card, ensure_ascii=False)
