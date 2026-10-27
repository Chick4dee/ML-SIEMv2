"""Журнал версии 2 (фича 008): необязательные поля, маркеры начала, прерванные запуски."""

from __future__ import annotations

import pytest

from mlsiem.lab import journal

T0, T1 = "2026-10-17T10:00:00.000Z", "2026-10-17T10:02:00.000Z"


def _rec(**kw):
    base = dict(
        name="scan",
        version="2",
        attacker_ip="10.88.0.30",
        targets=["10.88.0.20"],
        expected_class="reconnaissance",
        started_at=T0,
        ended_at=T1,
        outcome="completed",
    )
    base.update(kw)
    return journal.make_record(**base)


def test_запись_версии_2_несёт_поля_варианта():
    rec = _rec(
        variant="nmap_syn",
        tool="nmap",
        params={"ports": "1-1024"},
        source="attacker",
        source_ip="10.88.0.30",
        repeat=3,
        part="train",
        plan_run_uid="r03-scan-nmap_syn",
        attempt=1,
        session_id="s01",
    )
    assert rec["record_version"] == 2
    assert rec["variant"] == "nmap_syn" and rec["params"] == {"ports": "1-1024"}
    journal.validate(rec)


def test_запись_версии_1_остаётся_валидной_и_без_лишних_полей():
    rec = _rec()
    assert "record_version" not in rec and "variant" not in rec
    journal.validate(rec)


def test_неизвестное_поле_отвергается():
    with pytest.raises(journal.JournalError, match="неизвестные поля"):
        _rec(secret="x")


def test_маркер_без_итога_считается_прерванным(tmp_path):
    path = tmp_path / "j.jsonl"
    journal.append(path, _rec(run_uid="a#1"))
    journal.append_marker(
        path,
        journal.make_start_marker(
            run_uid="b#1",
            started_at=T0,
            name="scan",
            source_ip="10.88.0.30",
            version="2",
            targets=["10.88.0.20"],
            expected_class="reconnaissance",
            variant="nmap_syn",
            tool="nmap",
        ),
    )
    assert [m["run_uid"] for m in journal.pending_markers(path)] == ["b#1"]
    assert [r["run_uid"] for r in journal.read(path)] == ["a#1"]  # маркер из read скрыт
    closed = journal.close_pending(path, T1, limit_s=120)
    assert (
        len(closed) == 1
        and closed[0]["outcome"] == "aborted"
        and closed[0]["variant"] == "nmap_syn"
    )
    assert journal.pending_markers(path) == []
    # окно прерванного запуска покрывает предел длительности (инструмент мог работать до него)
    assert journal.to_ms(closed[0]["ended_at"]) - journal.to_ms(closed[0]["started_at"]) >= 119_000


def test_итог_с_тем_же_uid_закрывает_маркер(tmp_path):
    path = tmp_path / "j.jsonl"
    journal.append_marker(
        path,
        journal.make_start_marker(
            run_uid="c#1", started_at=T0, name="scan", source_ip="10.88.0.30"
        ),
    )
    journal.append(path, _rec(run_uid="c#1"))
    assert journal.pending_markers(path) == []


def test_окна_содержат_прерванные_но_не_отклонённые():
    recs = [
        _rec(run_uid="x", outcome="aborted"),
        _rec(run_uid="y", outcome="rejected", reject_reason="вне стенда"),
        _rec(run_uid="z"),
    ]
    assert [w[2]["run_uid"] for w in journal.windows(recs)] == ["x", "z"]


def test_битая_строка_журнала_не_молчит(tmp_path):
    path = tmp_path / "j.jsonl"
    path.write_text("{не json\n", encoding="utf-8")
    with pytest.raises(journal.JournalError, match="строка 1"):
        journal.read(path)
