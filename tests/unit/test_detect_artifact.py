"""Артефакт детектора: сохранение/загрузка, проверка схемы входа, битые файлы, версия."""

import re
from datetime import UTC, datetime

import numpy as np
import polars as pl
import pytest

from mlsiem.data.extract import write_flows_parquet
from mlsiem.data.schema import SCHEMA
from mlsiem.detect.artifact import (
    CARD_FILE,
    MODEL_FILE,
    DetectorInputError,
    DetectorLoadError,
    detector_version,
    load_detector,
    save_detector,
)
from mlsiem.detect.candidates import build_candidate

FEATURES = SCHEMA.feature_columns()


@pytest.fixture
def trained(tmp_path):
    rng = np.random.default_rng(0)
    X = rng.gamma(2.0, 10.0, size=(200, len(FEATURES))).astype(np.float32)
    y = np.where(X[:, 0] > 25, "dos", "benign")
    pipe = build_candidate("logreg", {"max_iter": 200}, seed=0).fit(X, y)
    card = {
        "detector_version": "20260924-abcdef12",
        "candidate": "logreg",
        "classes": [str(c) for c in pipe.classes_],
        "threshold": 0.5,
        "features": FEATURES,
        "schema_version": SCHEMA.version,
    }
    out = tmp_path / "detector"
    save_detector(pipe, card, out)
    return pipe, card, out, X


def test_roundtrip(trained):
    pipe, card, out, X = trained
    det = load_detector(out)
    assert det.card == card
    assert det.classes == card["classes"]
    assert det.threshold == 0.5
    assert det.features == FEATURES
    df = pl.DataFrame(X, schema=FEATURES)
    # Допуск — на порядок суммирования: polars отдаёт массив в другом порядке памяти
    np.testing.assert_allclose(det.predict_proba(df), pipe.predict_proba(X), rtol=1e-5)


def test_predict_uses_only_features_in_card_order(trained):
    pipe, _, out, X = trained
    det = load_detector(out)
    df = pl.DataFrame(X, schema=FEATURES)
    # Лишние колонки и другой порядок не должны влиять на результат
    shuffled = df.select(list(reversed(FEATURES))).with_columns(
        pl.lit("10.0.0.1").alias("src_ip"), pl.lit(123).alias("bidirectional_first_seen_ms")
    )
    np.testing.assert_allclose(det.predict_proba(shuffled), pipe.predict_proba(X), rtol=1e-5)


def _parquet(tmp_path, schema_version, drop=()):
    cols = [c for c in FEATURES if c not in drop]
    df = pl.DataFrame({c: [1.0] for c in cols})
    path = tmp_path / "in.parquet"
    write_flows_parquet(df, path, {})
    if schema_version != SCHEMA.version:
        import pyarrow.parquet as pq

        table = pq.read_table(path)
        meta = dict(table.schema.metadata)
        meta[b"mlsiem.schema_version"] = schema_version.encode()
        pq.write_table(table.replace_schema_metadata(meta), path)
    return path


def test_check_parquet_ok(tmp_path, trained):
    det = load_detector(trained[2])
    det.check_parquet(_parquet(tmp_path, SCHEMA.version))
    det.check_parquet(_parquet(tmp_path, "1.7.3"))  # та же мажорная версия — можно


def test_check_parquet_wrong_major(tmp_path, trained):
    det = load_detector(trained[2])
    with pytest.raises(DetectorInputError, match=r"ожидалась схема 1\.x.*получена 2\.0\.0"):
        det.check_parquet(_parquet(tmp_path, "2.0.0"))


def test_check_missing_feature(tmp_path, trained):
    det = load_detector(trained[2])
    with pytest.raises(DetectorInputError, match="bidirectional_packets"):
        det.check_parquet(_parquet(tmp_path, SCHEMA.version, drop=["bidirectional_packets"]))


def test_missing_files(tmp_path):
    with pytest.raises(DetectorLoadError, match="detect train"):
        load_detector(tmp_path / "nothing")


def test_corrupted_card(trained):
    out = trained[2]
    (out / CARD_FILE).write_text("{не json", encoding="utf-8")
    with pytest.raises(DetectorLoadError, match="повреждён"):
        load_detector(out)


def test_corrupted_model(trained):
    out = trained[2]
    (out / MODEL_FILE).write_bytes(b"not a pickle at all")
    with pytest.raises(DetectorLoadError, match="не загружается"):
        load_detector(out)


def test_detector_version_format_and_inputs():
    day = datetime(2026, 9, 24, tzinfo=UTC)
    v1 = detector_version({"seed": 42}, {"a": "h1"}, today=day)
    assert re.fullmatch(r"20260924-[0-9a-f]{8}", v1)
    assert detector_version({"seed": 42}, {"a": "h1"}, today=day) == v1
    assert detector_version({"seed": 43}, {"a": "h1"}, today=day) != v1
    assert detector_version({"seed": 42}, {"a": "h2"}, today=day) != v1
    # Путь сохранения на версию не влияет
    assert detector_version({"seed": 42, "output": "x"}, {"a": "h1"}, today=day) == v1
