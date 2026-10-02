"""Сенсор видит только трафик сети стенда (фича 006, US2, FR-006).

Зеркало `mlsiem-lab` несёт только трафик стенда, но сенсор ещё раз страхуется: поток, у
которого ни один конец не в сети стенда, в потоки не попадает (служебная сеть — другой
коммутатор).
"""

from pathlib import Path

import pytest

from mlsiem.stream.config import load_stream_config
from mlsiem.stream.messages import FEATURE_FIELDS
from mlsiem.stream.sensor import in_scope

REPO = Path(__file__).parents[2]


@pytest.fixture(scope="module")
def subnet():
    return load_stream_config(REPO / "configs" / "stream.yaml").lab.subnet


def _row(src, dst):
    row = dict.fromkeys(FEATURE_FIELDS, 0)
    row.update(src_ip=src, dst_ip=dst)
    return row


def test_lab_flow_in_scope(subnet):
    assert in_scope(_row("10.88.0.30", "10.88.0.20"), subnet)
    assert in_scope(_row("10.88.0.31", "10.88.0.20"), subnet)


def test_service_network_flow_excluded(subnet):
    # Служебная сеть 10.77.0.0/24 — не стенд
    assert not in_scope(_row("10.77.0.1", "10.77.0.10"), subnet)
    assert not in_scope(_row("8.8.8.8", "1.1.1.1"), subnet)


def test_half_lab_is_in_scope(subnet):
    # Трафик между стендом и внешним адресом (одна сторона в стенде) считаем трафиком стенда
    assert in_scope(_row("10.88.0.20", "8.8.8.8"), subnet)


def test_missing_or_bad_ip(subnet):
    assert not in_scope(_row(None, None), subnet)
    assert not in_scope(_row("мусор", "ещё мусор"), subnet)
    assert in_scope(_row("мусор", "10.88.0.20"), subnet)
