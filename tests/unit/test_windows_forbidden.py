"""Запрещённые входы моделей окон (фича 007, FR-004, SC-004): ни адресов, ни значений
портов, ни идентификаторов, ни абсолютного времени, ни DPI-полей.

Списки запрещённого берутся из групп схемы 001 (key, identity, time, dpi), а не пишутся
руками: если схема получит новое поле-идентичность, тест сам начнёт его проверять.
"""

import re

from mlsiem.data.schema import SCHEMA
from mlsiem.detect.windows import seq_feature_names, summary_feature_names

FORBIDDEN = sorted(
    {
        *SCHEMA.columns_of("key"),
        *SCHEMA.columns_of("identity"),
        *SCHEMA.columns_of("time"),
        *SCHEMA.columns_of("dpi"),
        *SCHEMA.columns_of("label"),
        "id",
    }
)
PATTERNS = [re.compile(p) for p in (r"_ip$", r"_ip_", r"first_seen_ms", r"last_seen_ms")]


def _base(name: str) -> str:
    """f_<признак>_mean → <признак>: сводный признак — статистика признака схемы."""
    for suffix in ("_mean", "_max", "_std"):
        if name.startswith("f_") and name.endswith(suffix):
            return name[2 : -len(suffix)]
    return name


def test_no_forbidden_names():
    names = summary_feature_names() + seq_feature_names()
    for name in names:
        base = _base(name)
        assert base not in FORBIDDEN, f"{name}: поле {base} запрещено во входе (FR-004)"
        for p in PATTERNS:
            assert not p.search(name), f"{name}: похоже на адрес или абсолютное время"


def test_ports_only_as_counts():
    names = summary_feature_names() + seq_feature_names()
    port_like = [n for n in names if "port" in n]
    # Порты входят только счётчиками и долями, а не значениями
    assert set(port_like) <= {"w_n_dst_ports", "w_n_src_ports", "w_share_low_port", "new_dst_port"}


def test_features_come_from_schema():
    feats = SCHEMA.feature_columns()
    assert {_base(n) for n in summary_feature_names() if n.startswith("f_")} == set(feats)
    assert seq_feature_names()[: len(feats)] == feats
