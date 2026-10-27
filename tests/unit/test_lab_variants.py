"""Варианты сценариев 008: раскрытие, параметры, привязка источника, запуск с журналом версии 2."""

from __future__ import annotations

import pytest

from mlsiem.lab import journal
from mlsiem.lab.normal import NormalRunner
from mlsiem.lab.scenarios import ScenarioError, _Lock
from mlsiem.lab.variants import (
    ACTIVE_SOURCES,
    VariantRunner,
    expand_variants,
    find_variant,
    list_variants,
    render_variant_args,
    resolve_params,
    source_name_of,
    variant_plan,
)
from mlsiem.stream.config import load_stream_config


@pytest.fixture(scope="module")
def raw():
    return load_stream_config().raw


def test_версия_2_раскрывается_в_варианты_с_инструментами(raw):
    v2 = [v for v in expand_variants(raw) if str(v["version"]) == "2"]
    by_class: dict[str, set[str]] = {}
    for v in v2:
        if not v["hard"]:
            by_class.setdefault(v["expected_class"], set()).add(v["variant"])
    # FR-001: у каждого класса атаки не меньше двух вариантов-инструментов
    assert all(len(s) >= 2 for s in by_class.values()), by_class
    assert {"reconnaissance", "fuzzers", "dos", "exploits", "out_of_taxonomy"} <= set(by_class)
    assert any(v["hard"] and v["expected_class"] == "benign" for v in v2)


def test_сценарий_версии_1_остаётся_одним_вариантом_default(raw):
    v = find_variant(raw, "port_scan", version="1")
    assert v["variant"] == "default" and v["tool"] == "nmap"


def test_список_вариантов_показывает_holdout_и_резерв(raw):
    items = {(v["scenario"], v["variant"]): v for v in list_variants(raw)}
    assert items[("scan", "masscan")]["reserve_unknown"] is True
    assert items[("scan", "nmap_syn")]["holdout"]["timing"] == [2]
    assert (
        items[("beacon", "curl_loop")]["binary"] == "bash"
        and items[("beacon", "curl_loop")]["tool"] == "curl_loop"
    )


def test_параметры_по_умолчанию_и_вне_домена(raw):
    var = find_variant(raw, "scan", "nmap_syn")
    assert resolve_params(var, {}) == {"ports": "1-1024", "timing": 3}
    assert resolve_params(var, {"timing": 2})["timing"] == 2
    with pytest.raises(ScenarioError, match="вне домена"):
        resolve_params(var, {"timing": 9})
    with pytest.raises(ScenarioError, match="неизвестные параметры"):
        resolve_params(var, {"nope": 1})


def test_аргументы_подставляют_источник_и_параметры(raw):
    var = find_variant(raw, "scan", "nmap_syn")
    args = render_variant_args(raw, var, {"ports": "22,80", "timing": 4}, "10.88.0.32")
    assert args == ["-sS", "-Pn", "-p", "22,80", "-T4", "10.88.0.20"]


def test_привязка_flag_и_route_и_алиас(raw):
    syn = find_variant(raw, "scan", "nmap_syn")
    plan = variant_plan(raw, syn, resolve_params(syn, {}), "10.88.0.32")
    assert plan["pre"] == [["ip", "addr", "add", "10.88.0.32/24", "dev", "lab0"]]
    assert plan["main"][:5] == ["nmap", "-S", "10.88.0.32", "-e", "lab0"]
    assert plan["post"] == []
    ffuf = find_variant(raw, "fuzz", "ffuf")
    plan = variant_plan(raw, ffuf, resolve_params(ffuf, {}), "10.88.0.33")
    assert ["ip", "route", "replace", "10.88.0.0/24", "dev", "lab0", "src", "10.88.0.33"] in plan[
        "pre"
    ]
    assert plan["post"] == [
        ["ip", "route", "replace", "10.88.0.0/24", "dev", "lab0", "src", "10.88.0.30"]
    ]
    # основной адрес: ни алиаса, ни маршрута
    plan = variant_plan(raw, ffuf, resolve_params(ffuf, {}), "10.88.0.30")
    assert plan["pre"] == [] and plan["post"] == []


def test_hping_задаёт_источник_флагом_а_не_маршрутом(raw):
    # hping3 (сырые сокеты) не берёт src из маршрута и для адреса-алиаса сваливается в 127.0.0.1 —
    # тогда флуд не привязывается к окну атаки и утекает в benign. Поэтому источник задаётся флагом
    # -a.
    for vn in ("hping_syn", "hping_udp"):
        var = find_variant(raw, "flood", vn)
        plan = variant_plan(raw, var, resolve_params(var, {}), "10.88.0.32")
        assert plan["main"][:3] == ["hping3", "-a", "10.88.0.32"], vn
        assert not any(cmd[:2] == ["ip", "route"] for cmd in plan["pre"] + plan["post"]), vn


class Spy:
    """Исполнитель-подмена: запоминает команды и состояние занятых источников в момент запуска."""

    def __init__(self, fail_on: str | None = None):
        self.calls, self.active_during = [], []
        self.fail_on = fail_on

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        self.active_during.append(set(ACTIVE_SOURCES))
        if self.fail_on and argv[0] == self.fail_on:
            raise FileNotFoundError(argv[0])
        return 0


def _runner(raw, tmp_path, spy):
    return VariantRunner(raw, tmp_path / "j.jsonl", executor=spy, clock=iter_clock())


def iter_clock():
    n = {"i": 0}

    def clock():
        n["i"] += 1
        return f"2026-10-17T10:{n['i'] // 60:02d}:{n['i'] % 60:02d}.000Z"

    return clock


def test_запуск_пишет_запись_версии_2_и_закрывает_маркер(raw, tmp_path):
    spy = Spy()
    rec = _runner(raw, tmp_path, spy).run(
        "scan",
        "nmap_syn",
        {"timing": 4},
        source_ip="10.88.0.32",
        meta={"plan_run_uid": "r01-scan-nmap_syn", "repeat": 1, "part": "train"},
    )
    assert (
        rec["outcome"] == "completed"
        and rec["variant"] == "nmap_syn"
        and rec["source_ip"] == "10.88.0.32"
    )
    assert rec["source"] == "attacker_a2" and rec["params"]["timing"] == 4 and rec["repeat"] == 1
    assert journal.pending_markers(tmp_path / "j.jsonl") == []
    assert "10.88.0.32" in spy.active_during[-1]  # во время запуска источник занят
    assert set() == ACTIVE_SOURCES


def test_цель_вне_стенда_отклоняется_до_запуска(raw, tmp_path):
    spy = Spy()
    bad = {**raw, "lab": {**raw["lab"], "victim": {**raw["lab"]["victim"], "ip": "8.8.8.8"}}}
    rec = VariantRunner(bad, tmp_path / "j.jsonl", executor=spy).run("scan", "nmap_syn")
    assert rec["outcome"] == "rejected" and "вне сети стенда" in rec["reject_reason"]
    assert spy.calls == []


def test_параллельный_запуск_с_одного_адреса_отклоняется_с_другого_нет(raw, tmp_path):
    spy = Spy()
    runner = _runner(raw, tmp_path, spy)
    held = runner._lock_for("10.88.0.32")
    assert held.acquire("другой")
    rec = runner.run("scan", "nmap_syn", source_ip="10.88.0.32")
    assert rec["outcome"] == "rejected" and "параллельный" in rec["reject_reason"]
    ok = runner.run("scan", "nmap_syn", source_ip="10.88.0.33")
    assert ok["outcome"] == "completed"
    held.release()


def test_нет_инструмента_значит_aborted(raw, tmp_path):
    rec = _runner(raw, tmp_path, Spy(fail_on="masscan")).run("scan", "masscan")
    assert rec["outcome"] == "aborted"


def test_маршрут_возвращается_даже_при_сбое_инструмента(raw, tmp_path):
    spy = Spy(fail_on="ffuf")
    _runner(raw, tmp_path, spy).run("fuzz", "ffuf", source_ip="10.88.0.33")
    assert (
        spy.calls[-1][:4] == ["ip", "route", "replace", "10.88.0.0/24"]
        and spy.calls[-1][-1] == "10.88.0.30"
    )


def test_норма_обходит_занятый_источник(raw, tmp_path):
    seen = []

    def executor(argv, timeout):
        seen.append(argv)
        return 0

    normal = NormalRunner(raw, tmp_path / "j.jsonl", executor=executor, seed=1)
    ACTIVE_SOURCES.update({"10.88.0.30", "10.88.0.32"})
    try:
        normal.run_steps(30)
    finally:
        ACTIVE_SOURCES.clear()
    used = {a[a.index("--interface") + 1] for a in seen if "--interface" in a}
    assert used <= {"10.88.0.33"} and used  # свободен только один источник
    # все источники заняты — шаги пропускаются
    ACTIVE_SOURCES.update({"10.88.0.30", "10.88.0.32", "10.88.0.33"})
    seen.clear()
    try:
        normal.run_steps(5)
    finally:
        ACTIVE_SOURCES.clear()
    assert seen == []


def test_имя_источника_по_адресу(raw):
    assert source_name_of(raw, "10.88.0.33") == "attacker_a3"
    assert source_name_of(raw, "1.2.3.4") == "1.2.3.4"


def test_замок_освобождается(tmp_path):
    lock = _Lock(tmp_path / "x.lock")
    assert lock.acquire("a") and not _Lock(tmp_path / "x.lock").acquire("b")
    lock.release()
    assert _Lock(tmp_path / "x.lock").acquire("c")
