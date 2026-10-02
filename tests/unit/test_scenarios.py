"""Реестр и запуск сценариев на атакующей машине (фича 006, US3, FR-012/FR-013).

Цель вне сети стенда отклоняется ДО запуска инструмента; параллельный запуск отклоняется.
Инструменты не вызываются по-настоящему — исполнитель подменяется.
"""

import json
from pathlib import Path

import pytest
import yaml

from mlsiem.lab import journal
from mlsiem.lab.scenarios import (
    ScenarioError,
    ScenarioRunner,
    check_targets,
    commands,
    find_scenario,
    render_args,
)

REPO = Path(__file__).parents[2]


@pytest.fixture(scope="module")
def raw():
    return yaml.safe_load((REPO / "configs" / "stream.yaml").read_text(encoding="utf-8"))


class FakeExec:
    """Запоминает запущенные команды; по желанию «роняет» подготовительный шаг."""

    def __init__(self, fail_first=False):
        self.calls = []
        self.fail_first = fail_first

    def __call__(self, argv, timeout_s):
        self.calls.append((argv, timeout_s))
        return 1 if (self.fail_first and len(self.calls) == 1) else 0


def _runner(raw, tmp_path, **kw):
    clock = kw.pop("clock", None)
    ex = kw.pop("executor", FakeExec())
    r = ScenarioRunner(
        raw,
        tmp_path / "journal.jsonl",
        executor=ex,
        workdir=tmp_path,
        clock=clock or journal.now_iso,
    )
    return r, ex


def test_find_and_list(raw):
    sc = find_scenario(raw, "port_scan")
    assert sc["tool"] == "nmap"
    with pytest.raises(ScenarioError, match="не найден"):
        find_scenario(raw, "нет")


def test_render_args_substitutes_target_and_port(raw):
    argv = render_args(raw, find_scenario(raw, "web_fuzz"))
    joined = " ".join(argv)
    assert "10.88.0.20" in joined and ":80/" in joined


def test_render_args_unknown_placeholder(raw):
    sc = dict(find_scenario(raw, "port_scan"))
    sc["args"] = "-p {wat} {target}"
    with pytest.raises(ScenarioError, match="подстановка"):
        render_args(raw, sc)


def test_control_replay_rewrites_then_replays(raw, tmp_path):
    cmds = commands(raw, find_scenario(raw, "control_replay"), tmp_path)
    assert cmds[0][0] == "tcprewrite"
    assert any(a.startswith("--pnat=") for a in cmds[0])
    assert "--fixcsum" in cmds[0]
    assert cmds[1][0] == "tcpreplay"


def test_target_outside_lab_rejected_before_run(raw, tmp_path):
    bad = dict(raw)
    # Подменяем жертву на адрес вне стенда
    bad = json.loads(json.dumps(raw))
    bad["lab"]["victim"]["ip"] = "8.8.8.8"
    r, ex = _runner(bad, tmp_path)
    rec = r.run("port_scan")
    assert rec["outcome"] == "rejected" and "вне сети стенда" in rec["reject_reason"]
    assert ex.calls == []  # инструмент не запускался
    assert journal.read(tmp_path / "journal.jsonl")[0]["outcome"] == "rejected"


def test_successful_run_is_journaled(raw, tmp_path):
    r, ex = _runner(raw, tmp_path)
    rec = r.run("port_scan")
    assert rec["outcome"] == "completed"
    assert rec["attacker_ip"] == "10.88.0.30" and rec["targets"] == ["10.88.0.20"]
    assert len(ex.calls) == 1 and ex.calls[0][0][0] == "nmap"
    assert ex.calls[0][1] == float(find_scenario(raw, "port_scan")["duration_limit_s"])


def test_parallel_run_rejected(raw, tmp_path):
    r, _ = _runner(raw, tmp_path)
    # Держим блокировку, как будто идёт другой сценарий
    assert r.lock.acquire("sc-other")
    rec = r.run("port_scan")
    assert rec["outcome"] == "rejected" and "параллельный" in rec["reject_reason"]


def test_control_replay_rewrite_failure_aborts(raw, tmp_path):
    r, ex = _runner(raw, tmp_path, executor=FakeExec(fail_first=True))
    rec = r.run("control_replay")
    assert rec["outcome"] == "aborted"
    assert len(ex.calls) == 1  # до tcpreplay не дошли


def test_missing_tool_aborts(raw, tmp_path):
    def boom(argv, timeout_s):
        raise FileNotFoundError(argv[0])

    r, _ = _runner(raw, tmp_path, executor=boom)
    rec = r.run("port_scan")
    assert rec["outcome"] == "aborted"


def test_targets_check_accepts_lab(raw):
    check_targets(raw, ["10.88.0.20", "10.88.0.30"])
    from mlsiem.lab.scenarios import ScenarioRejected

    with pytest.raises(ScenarioRejected):
        check_targets(raw, ["10.88.0.20", "10.0.0.1"])


def test_control_maps_must_be_in_lab(raw):
    from mlsiem.lab.scenarios import ScenarioRejected, check_control_maps, control_rewrite_command

    sc = find_scenario(raw, "control_replay")
    check_control_maps(raw, sc)  # адреса подмены в 10.88.0.0/24 — ок
    cmd = control_rewrite_command(sc, "/tmp/out.pcap")
    assert cmd[0] == "tcprewrite" and any(a.startswith("--pnat=") for a in cmd)
    assert "--fixcsum" in cmd
    # Подмена на адрес вне стенда — отклоняется до сборки артефакта
    bad = dict(sc)
    bad["dst_map"] = "149.171.126.10:8.8.8.8"
    with pytest.raises(ScenarioRejected):
        check_control_maps(raw, bad)
