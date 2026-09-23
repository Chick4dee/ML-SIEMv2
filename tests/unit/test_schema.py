"""Тесты схемы признаков."""

from mlsiem.data.schema import GROUPS, SCHEMA, FeatureSchema


def test_version():
    assert SCHEMA.version == "1.0.0"


def test_every_column_in_exactly_one_known_group():
    names = SCHEMA.names()
    assert len(names) == len(set(names)), "имена колонок не должны повторяться"
    for c in SCHEMA.columns:
        assert c.group in GROUPS


def test_feature_group_has_58_columns():
    assert len(SCHEMA.columns_of("feature")) == 58


def test_id_is_dropped():
    assert "id" not in SCHEMA.names()


def test_feature_columns_exclude_identity_and_time():
    features = set(SCHEMA.feature_columns())
    assert not features & set(SCHEMA.columns_of("identity"))
    assert not features & set(SCHEMA.columns_of("time"))
    assert "protocol" in features


def test_json_roundtrip(tmp_path):
    path = tmp_path / "schema.json"
    SCHEMA.to_json(path)
    assert FeatureSchema.from_json(path) == SCHEMA
