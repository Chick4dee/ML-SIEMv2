"""Тесты таксономии классов."""

import pytest

from mlsiem.data.taxonomy import CANONICAL, UnknownLabelError, to_canonical

UNSW_CATEGORIES = [
    "dos",
    "exploits",
    "fuzzers",
    "generic",
    "reconnaissance",
    "analysis",
    "shellcode",
    "worms",
]


def test_backdoor_variants():
    assert to_canonical("unsw", " Backdoors ") == "backdoor"
    assert to_canonical("unsw", "backdoor") == "backdoor"


@pytest.mark.parametrize("cat", UNSW_CATEGORIES)
def test_unsw_categories_map_to_same_name(cat):
    assert to_canonical("unsw", cat.upper()) == cat
    assert cat in CANONICAL


def test_ctu13_classes():
    assert to_canonical("ctu13", "normal") == "benign"
    assert to_canonical("ctu13", "Background") == "background"
    assert to_canonical("ctu13", "botnet") == "botnet"


def test_unknown_label_mentions_value():
    with pytest.raises(UnknownLabelError, match="Teleport"):
        to_canonical("unsw", "Teleport")
