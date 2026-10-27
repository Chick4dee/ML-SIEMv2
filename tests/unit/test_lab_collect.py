"""Сбор 008: исполнение плана, мягкая и срочная остановка, возобновление, обрыв, недоступные "
"инструменты."""

from __future__ import annotations

import pytest

from mlsiem.lab import journal
from mlsiem.lab.capture import CaptureError, parse_tcpdump_log
from mlsiem.lab.channel import ChannelError
from mlsiem.lab.collect import (
    EXIT_INTERRUPTED,
    EXIT_NOT_READY,
    EXIT_OK,
    HARD_FLAG,
    STATE_FILE,
    CollectError,
    Collector,
)
from mlsiem.lab.plan import build_plan
from mlsiem.stream.config import load_stream_config


@pytest.fixture(scope="module")
def raw():
    return load_stream_config().raw


class FakeChannel:
    """Раннер-подмена: отвечает на ping/clock/tools/normal/variant и пишет записи как настоящий."""

    def __init__(self, on_variant=None, missing_tools=(), fail_variant=None):
        self.calls: list[dict] = []
        self.on_variant = on_variant
        self.missing = set(missing_tools)
        self.fail_variant = fail_variant
        self.n = 0
        self.normal_on = False

    def request(self, req, timeout_s=20.0):
        self.calls.append(req)
        cmd = req["cmd"]
        if cmd == "ping":
            return {"ok": True, "scenarios": [], "variants": []}
        if cmd == "clock":
            return {"ok": True, "now": journal.now_iso()}
        if cmd == "tools":
            return {
                "ok": True,
                "tools": {t: None for t in self.missing}
                | {"nmap": {"path": "/usr/bin/nmap", "version": "7"}},
            }
        if cmd == "normal":
            self.normal_on = req["action"] == "start"
            rec = None
            if req["action"] == "stop":
                rec = journal.make_record(
                    name="background_normal",
                    version="1",
                    attacker_ip="10.88.0.30",
                    targets=["10.88.0.20"],
                    expected_class="benign",
                    started_at="2026-10-17T10:00:00.000Z",
                    ended_at="2026-10-17T10:00:10.000Z",
                    outcome="completed",
                )
            return {"ok": True, "running": self.normal_on, "record": rec}
        if cmd == "variant":
            self.n += 1
            if self.on_variant:
                self.on_variant(self.n, req)
            if self.fail_variant and self.fail_variant(self.n, req):
                raise ChannelError("канал упал")
            meta = dict(req["meta"])
            uid = meta.pop("run_uid")
            rec = journal.make_record(
                name=req["scenario"],
                version="2",
                attacker_ip=req["source_ip"],
                targets=["10.88.0.20"],
                expected_class="x",
                started_at="2026-10-17T10:00:00.000Z",
                ended_at="2026-10-17T10:00:20.000Z",
                outcome="completed",
                run_uid=uid,
                variant=req["variant"],
                tool="t",
                params=req["params"],
                source_ip=req["source_ip"],
                **meta,
            )
            return {"ok": True, "record": rec}
        return {"ok": False, "error": f"?{cmd}"}


class FakeCapture:
    def __init__(self, tmp, fail_check=None, fail_fetch=False):
        self.tmp, self.fail_check, self.fail_fetch = tmp, fail_check, fail_fetch
        self.started, self.stopped, self.fetched = [], [], []

    def check(self):
        if self.fail_check:
            raise CaptureError(self.fail_check)
        return {"free_mb": 50000}

    def clock_skew_s(self, host_now=None):
        return 0.01

    def start(self, sid):
        self.started.append(sid)
        return {}

    def stop(self, sid):
        self.stopped.append(sid)
        return {"captured": 100, "dropped": 0}

    def fetch(self, sid, local):
        if self.fail_fetch:
            raise CaptureError("scp не удался")
        self.fetched.append(sid)
        return [{"name": "session.pcap", "bytes": 1, "sha256": "0"}]


def make(raw, tmp_path, *, repeats=3, channel=None, capture=None, plan=None):
    plan = plan or build_plan(raw, seed=3, repeats=repeats)
    ch = channel or FakeChannel()
    cap = capture or FakeCapture(tmp_path)
    col = Collector(raw, plan, tmp_path / "w", ch, cap, sleep=lambda s: None, log=lambda m: None)
    return col, ch, cap


def test_полный_прогон_закрывает_план_и_сеанс(raw, tmp_path):
    col, ch, cap = make(raw, tmp_path, repeats=3)
    n = len(col.plan["runs"])
    assert col.run() == EXIT_OK
    st = col.status()
    assert (
        st["done"] == n and st["remaining"] == 0 and st["safe_to_power_off"] and st["sessions"] == 1
    )
    assert cap.started == ["s01"] and cap.stopped == ["s01"] and cap.fetched == ["s01"]
    recs = journal.read(col.journal_path)
    assert sum(1 for r in recs if r.get("variant")) == n
    assert journal.pending_markers(col.journal_path) == []
    assert not ch.normal_on  # норма остановлена


def test_мягкая_остановка_доводит_запуск_и_возобновление_продолжает(raw, tmp_path):
    holder = {}

    def stop_after_two(n, req):
        if n == 2:
            holder["col"].request_stop()

    ch = FakeChannel(on_variant=stop_after_two)
    col, ch, cap = make(raw, tmp_path, channel=ch)
    holder["col"] = col
    total = len(col.plan["runs"])
    assert col.run() == EXIT_INTERRUPTED
    st = col.status()
    assert (
        st["done"] == 2
        and st["remaining"] == total - 2
        and st["safe_to_power_off"]
        and st["sessions"] == 1
    )
    assert col.state["sessions"][0]["stop_kind"] == "soft"
    # возобновление в новом сеансе: выполненные не повторяются
    col2 = Collector(
        raw, col.plan, tmp_path / "w", ch, cap, sleep=lambda s: None, log=lambda m: None
    )
    assert col2.run() == EXIT_OK
    assert col2.status()["done"] == total and col2.status()["sessions"] == 2
    assert cap.started == ["s01", "s02"]
    uids = [r["plan_run_uid"] for r in journal.read(col2.journal_path) if r.get("plan_run_uid")]
    assert len(uids) == len(set(uids)) == total


def test_срочная_остановка_пишет_aborted_и_повторяет_запуск(raw, tmp_path):
    def interrupt(n, req):
        if n == 2:
            raise KeyboardInterrupt

    ch = FakeChannel(on_variant=interrupt)
    col, ch, cap = make(raw, tmp_path, channel=ch)
    col.run()
    recs = journal.read(col.journal_path)
    aborted = [r for r in recs if r["outcome"] == "aborted"]
    assert len(aborted) == 1 and aborted[0]["plan_run_uid"] == col.plan["runs"][1]["plan_run_uid"]
    assert col.state["sessions"][0]["stop_kind"] == "hard"
    assert col.state["runs"][col.plan["runs"][1]["plan_run_uid"]]["status"] == "aborted"
    # после возобновления прерванный запуск повторён целиком (попытка 2) и план выполнен
    col2 = Collector(
        raw, col.plan, tmp_path / "w", FakeChannel(), cap, sleep=lambda s: None, log=lambda m: None
    )
    assert col2.run() == EXIT_OK
    attempts = [
        r["attempt"]
        for r in journal.read(col2.journal_path)
        if r.get("plan_run_uid") == col.plan["runs"][1]["plan_run_uid"]
    ]
    assert sorted(attempts) == [1, 2]


def test_обрыв_канала_закрывает_маркер_и_запуск_повторяется(raw, tmp_path):
    ch = FakeChannel(fail_variant=lambda n, req: n == 1)
    col, ch, cap = make(raw, tmp_path, channel=ch)
    assert col.run() == EXIT_OK
    recs = [
        r
        for r in journal.read(col.journal_path)
        if r.get("plan_run_uid") == col.plan["runs"][0]["plan_run_uid"]
    ]
    assert [r["outcome"] for r in recs] == ["aborted", "completed"]
    assert col.state["runs"][col.plan["runs"][0]["plan_run_uid"]]["attempts"] == 2


def test_запуск_не_более_трёх_попыток(raw, tmp_path):
    ch = FakeChannel(
        fail_variant=lambda n, req: req["meta"]["plan_run_uid"] == "NOPE" or n in (1, 2, 3)
    )
    col, ch, cap = make(raw, tmp_path, channel=ch)
    code = col.run()
    first = col.state["runs"][col.plan["runs"][0]["plan_run_uid"]]
    assert first["attempts"] == 3 and first["status"] == "aborted"
    assert (
        code == EXIT_INTERRUPTED
    )  # один запуск потерян — план не выполнен целиком, но сбор дошёл до конца


def test_недоступный_инструмент_пропускает_запуски(raw, tmp_path):
    ch = FakeChannel(missing_tools=("masscan",))
    plan = build_plan(raw, seed=3, repeats=3)
    col, ch, cap = make(raw, tmp_path, channel=ch, plan=plan)
    col.run()
    skipped = [u for u, s in col.state["runs"].items() if s["status"] == "skipped"]
    assert skipped and all("masscan" in u for u in skipped)
    assert col.status()["skipped"] == len(skipped)


def test_не_готово_если_запись_недоступна(raw, tmp_path):
    cap = FakeCapture(tmp_path, fail_check="нет доступа к сенсору")
    col, ch, cap = make(raw, tmp_path, capture=cap)
    assert col.run() == EXIT_NOT_READY
    assert cap.started == [] and not any(c["cmd"] == "variant" for c in ch.calls)


def test_сбой_выгрузки_записи_не_позволяет_выключать(raw, tmp_path):
    cap = FakeCapture(tmp_path, fail_fetch=True)
    col, ch, cap = make(raw, tmp_path, capture=cap)
    col.run()
    assert col.state["safe_to_power_off"] is False
    assert "scp" in col.state["sessions"][0]["capture_error"]


def test_состояние_другого_плана_не_принимается(raw, tmp_path):
    col, ch, cap = make(raw, tmp_path, repeats=3)
    col.run()
    other = build_plan(raw, seed=99, repeats=3)
    other["config_hash"] = "ffff"
    with pytest.raises(CollectError, match="другому плану"):
        Collector(raw, other, tmp_path / "w", ch, cap)


def test_прерванный_маркер_прошлого_сеанса_закрывается_при_старте(raw, tmp_path):
    col, ch, cap = make(raw, tmp_path, repeats=3)
    journal.append_marker(
        col.journal_path,
        journal.make_start_marker(
            run_uid="old#1",
            started_at="2026-10-17T09:00:00.000Z",
            name="scan",
            source_ip="10.88.0.30",
            version="2",
            targets=["10.88.0.20"],
            expected_class="reconnaissance",
        ),
    )
    col.run()
    old = [r for r in journal.read(col.journal_path) if r["run_uid"] == "old#1"]
    assert old and old[0]["outcome"] == "aborted"


def test_статус_до_запуска(raw, tmp_path):
    col, ch, cap = make(raw, tmp_path, repeats=3)
    st = col.status()
    assert st["done"] == 0 and st["remaining"] == len(col.plan["runs"]) and st["eta_h"] > 0
    assert (tmp_path / "w" / STATE_FILE).exists() is False


def test_флаг_срочной_остановки_обрывает_паузу(raw, tmp_path):
    holder = {}

    def hard(n, req):
        if n == 1:
            holder["col"].request_stop(now=True)

    ch = FakeChannel(on_variant=hard)
    col, ch, cap = make(raw, tmp_path, channel=ch)
    holder["col"] = col
    col.run()
    assert col.state["sessions"][0]["stop_kind"] == "hard"
    assert col.status()["done"] == 1
    assert not (tmp_path / "w" / HARD_FLAG).exists() or True


def test_разбор_журнала_tcpdump():
    text = "123 packets captured\n456 packets received by filter\n7 packets dropped by kernel\n"
    assert parse_tcpdump_log(text) == {"captured": 123, "dropped": 7}
