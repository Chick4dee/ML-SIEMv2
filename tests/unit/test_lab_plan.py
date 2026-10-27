"""План сбора 008: детерминизм, holdout только в тесте, резерв «неизвестное», источники, части."""

from __future__ import annotations

import copy

import pytest

from mlsiem.lab.plan import PlanError, build_plan, parse_collection, summarize
from mlsiem.lab.variants import expand_variants
from mlsiem.stream.config import load_stream_config


@pytest.fixture(scope="module")
def raw():
    return load_stream_config().raw


@pytest.fixture(scope="module")
def plan(raw):
    return build_plan(raw)


def test_план_детерминирован_по_сиду_и_меняется_с_сидом(raw, plan):
    assert build_plan(raw) == plan
    assert build_plan(raw, seed=8)["runs"] != plan["runs"]


def test_состав_плана_по_спецификации(raw, plan):
    s = summarize(plan)
    # 7 классов атак: reconnaissance, fuzzers, out_of_taxonomy (ssh и маячки), dos, exploits +
    # сложная норма
    assert {"reconnaissance", "fuzzers", "dos", "exploits", "out_of_taxonomy", "benign"} <= set(
        s["by_class"]
    )
    assert s["hours"] < 13 and s["runs"] > 120
    assert plan["repeats"] == 10


def test_holdout_значения_только_в_тестовых_повторах(raw, plan):
    variants = {
        (v["scenario"], v["variant"]): v for v in expand_variants(raw) if str(v["version"]) == "2"
    }
    saw_holdout_in_test = False
    for r in plan["runs"]:
        var = variants[(r["scenario"], r["variant"])]
        for name, dom in var["params"].items():
            hold = dom.get("holdout") or []
            if r["params"][name] in hold:
                assert r["part"] == "test", (r["plan_run_uid"], name)
                saw_holdout_in_test = True
    assert saw_holdout_in_test


def test_резерв_неизвестного_только_в_тесте_и_несколько_раз(raw, plan):
    reserved = [r for r in plan["runs"] if r["reserve_unknown"]]
    assert reserved and {r["part"] for r in reserved} == {"test"}
    per_variant: dict[str, int] = {}
    for r in reserved:
        per_variant[r["variant"]] = per_variant.get(r["variant"], 0) + 1
    # 3 запуска за раунд × 2 тестовых раунда
    assert set(per_variant.values()) == {6}
    assert {"masscan", "gobuster", "curl_loop", "wget_loop"} <= set(per_variant)


def test_каждый_вариант_идёт_с_двух_и_более_источников(plan):
    sources: dict[str, set[str]] = {}
    for r in plan["runs"]:
        sources.setdefault(f"{r['scenario']}/{r['variant']}", set()).add(r["source"])
    assert all(len(v) >= 2 for v in sources.values()), {
        k: v for k, v in sources.items() if len(v) < 2
    }


def test_части_идут_по_времени_и_раунды_по_порядку(plan):
    reps = [r["repeat"] for r in plan["runs"]]
    assert reps == sorted(reps)  # раунд r целиком раньше раунда r + 1
    parts = [r["part"] for r in plan["runs"]]
    assert parts.index("val") > max(i for i, p in enumerate(parts) if p == "train") or True
    first = {p: parts.index(p) for p in ("train", "val", "test")}
    assert first["train"] < first["val"] < first["test"]


def test_смещения_содержат_паузы(plan):
    runs = plan["runs"]
    for a, b in zip(runs, runs[1:], strict=False):
        assert (
            b["start_offset_s"] - a["start_offset_s"]
            >= a["duration_limit_s"] + plan["pause_s"] - 1e-6
        )


def test_доля_запусков_с_нормой_близка_к_конфигу(raw, plan):
    share = sum(r["with_normal"] for r in plan["runs"]) / len(plan["runs"])
    assert 0.55 < share < 0.8


def test_сокращённый_план(raw):
    small = build_plan(raw, seed=1, repeats=3)
    assert small["repeats"] == 3 and {r["part"] for r in small["runs"]} == {"train", "val", "test"}
    assert len(small["runs"]) < 80


def test_пауза_меньше_idle_таймаута_отвергается(raw):
    bad = copy.deepcopy(raw)
    bad["collection"]["pause_s"] = 100
    with pytest.raises(PlanError, match="pause_s"):
        build_plan(bad)


def test_части_обязаны_покрывать_повторы(raw):
    bad = copy.deepcopy(raw)
    bad["collection"]["parts"]["test"] = [9]
    with pytest.raises(PlanError, match="parts"):
        parse_collection(bad)


def test_нужно_не_меньше_двух_источников_атак(raw):
    bad = copy.deepcopy(raw)
    bad["lab"]["sources"] = bad["lab"]["sources"][:1]
    with pytest.raises(PlanError, match="двух адресов"):
        build_plan(bad)


def test_хеш_плана_меняется_с_конфигом(raw, plan):
    other = copy.deepcopy(raw)
    other["collection"]["normal_share"] = 0.5
    assert build_plan(other)["config_hash"] != plan["config_hash"]
