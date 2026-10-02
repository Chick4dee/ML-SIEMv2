"""Фоновая норма стенда (фича 006, US4, FR-019, R14).

Состав (web/ssh/ftp/dns) и интенсивность — из конфига; команды используют ПРАВИЛЬНЫЙ пароль
тестовой учётки (это норма, а не перебор); интервал нормы пишется в журнал как benign.
Инструменты по-настоящему не вызываются — исполнитель подменяется.
"""

from pathlib import Path

import pytest
import yaml

from mlsiem.lab import journal
from mlsiem.lab.normal import NormalRunner, step_command, weighted_services

REPO = Path(__file__).parents[2]


@pytest.fixture(scope="module")
def raw():
    return yaml.safe_load((REPO / "configs" / "stream.yaml").read_text(encoding="utf-8"))


class FakeExec:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, timeout_s):
        self.calls.append(argv)
        return 0


def test_step_commands_use_services_and_password(raw):
    victim = raw["lab"]["victim"]
    web = step_command(raw, "web")
    assert web[0] == "curl" and victim["ip"] in web[-1]
    ssh = step_command(raw, "ssh")
    assert ssh[0] == "sshpass"
    # Правильный пароль тестовой учётки — это норма (не перебор)
    assert victim["ssh_password"] in ssh
    assert victim["ssh_user"] in " ".join(ssh)
    assert step_command(raw, "dns")[0] == "dig"
    assert step_command(raw, "ftp")[0] == "curl"


def test_only_configured_services_are_used(raw):
    services, weights = weighted_services(raw)
    assert set(services) <= set(raw["lab"]["victim"]["services"])
    assert all(w > 0 for w in weights)


def test_mix_follows_weights(raw, tmp_path):
    ex = FakeExec()
    r = NormalRunner(raw, tmp_path / "j.jsonl", executor=ex, seed=42)
    r.run_steps(400)
    done = r.steps_done
    # web имеет наибольший вес в конфиге → шагов web больше, чем у любой другой службы
    assert done["web"] == max(done.values())
    assert sum(done.values()) == 400 == len(ex.calls)


def test_finish_writes_benign_record(raw, tmp_path):
    path = tmp_path / "j.jsonl"
    times = iter(["2026-10-02T12:00:00.000Z", "2026-10-02T12:05:00.000Z"])
    r = NormalRunner(raw, path, executor=FakeExec(), clock=lambda: next(times), seed=1)
    rec = r.finish()
    assert rec["name"] == "background_normal"
    assert rec["expected_class"] == journal.BENIGN
    assert rec["outcome"] == "completed"
    saved = journal.read(path)
    assert len(saved) == 1 and saved[0]["expected_class"] == "benign"


def test_tool_missing_does_not_crash(raw, tmp_path):
    def boom(argv, timeout_s):
        raise FileNotFoundError(argv[0])

    r = NormalRunner(raw, tmp_path / "j.jsonl", executor=boom, seed=1)
    services = r.run_steps(3)  # раннер не падает, хотя инструмента нет
    assert len(services) == 3
    # Шаги не засчитаны (инструмент не отработал)
    assert sum(r.steps_done.values()) == 0


def test_start_twice_rejected(raw, tmp_path):
    r = NormalRunner(raw, tmp_path / "j.jsonl", executor=FakeExec())
    r.start()
    try:
        with pytest.raises(RuntimeError, match="уже запущена"):
            r.start()
    finally:
        r.stop()
    assert journal.read(tmp_path / "j.jsonl")[0]["expected_class"] == "benign"
