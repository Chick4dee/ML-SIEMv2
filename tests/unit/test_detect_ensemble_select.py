"""Правило выбора FR-010: только val, два условия, честный отрицательный результат."""

import inspect

from mlsiem.detect.ensemble import select_variant

ORDER = ("any_fired", "mean_score", "stack_logreg")


def sel(val, unknown, **kw):
    return select_variant(
        val, unknown, min_gain=0.01, min_unknown_gain=0.10, order=kw.get("order", ORDER)
    )


def test_macro_gain():
    r = sel({"classifier": 0.70, "stack_logreg": 0.715, "any_fired": 0.69}, {"stack_logreg": 0.0})
    assert r["selected"] == "ensemble:stack_logreg"
    assert r["condition"] == "macro_gain"


def test_unknown_gain_with_small_macro_gain():
    r = sel({"classifier": 0.70, "any_fired": 0.705}, {"any_fired": 0.12})
    assert r["selected"] == "ensemble:any_fired"
    assert r["condition"] == "unknown_gain"


def test_unknown_gain_blocked_by_macro_drop():
    r = sel({"classifier": 0.70, "any_fired": 0.68}, {"any_fired": 0.12})
    assert r["selected"] == "single:classifier"
    assert r["condition"] == "none"


def test_negative_result():
    r = sel(
        {"classifier": 0.70, "any_fired": 0.695, "mean_score": 0.70, "stack_logreg": 0.705},
        {"any_fired": 0.05, "mean_score": 0.0, "stack_logreg": None},
    )
    assert r["selected"] == "single:classifier"
    assert r["condition"] == "none"
    assert "отрицательный результат" in r["text"]


def test_test_metrics_do_not_matter():
    assert "test" not in inspect.signature(select_variant).parameters
    val = {"classifier": 0.70, "stack_logreg": 0.72}
    a = sel(val, {"stack_logreg": 0.0})
    # «лишние» ключи test в словарях результата выбор не меняют: функция их не видит
    b = sel({**val, "stack_logreg_test": 0.10, "classifier_test": 0.99}, {"stack_logreg": 0.0})
    assert a["selected"] == b["selected"] == "ensemble:stack_logreg"


def test_tie_prefers_simpler():
    r = sel(
        {"classifier": 0.70, "any_fired": 0.72, "mean_score": 0.72, "stack_logreg": 0.72},
        {},
    )
    assert r["selected"] == "ensemble:any_fired"
    r = sel(
        {"classifier": 0.70, "mean_score": 0.70, "stack_logreg": 0.70},
        {"mean_score": 0.2, "stack_logreg": 0.2},
    )
    assert r["selected"] == "ensemble:mean_score"


def test_macro_condition_beats_unknown_condition():
    r = sel(
        {"classifier": 0.70, "any_fired": 0.70, "stack_logreg": 0.72},
        {"any_fired": 0.9, "stack_logreg": 0.0},
    )
    assert r["selected"] == "ensemble:stack_logreg" and r["condition"] == "macro_gain"
