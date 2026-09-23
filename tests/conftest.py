"""Общие фикстуры тестов: пути к синтетическим PCAP."""

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
