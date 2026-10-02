"""Журнал сценариев стенда (фича 006, US3, FR-014): запись/чтение JSONL, проверка формы.

Журнал — вход для разметки набора, поэтому битая строка должна падать, а не тихо теряться.
"""

import pytest

from mlsiem.lab import journal


def _rec(**over):
    base = dict(
        name="port_scan",
        version="1",
        attacker_ip="10.88.0.30",
        targets=["10.88.0.20"],
        expected_class="reconnaissance",
        started_at="2026-10-01T12:00:00.000Z",
        ended_at="2026-10-01T12:01:00.000Z",
        outcome="completed",
    )
    base.update(over)
    return journal.make_record(**base)


def test_round_trip(tmp_path):
    path = tmp_path / "journal.jsonl"
    r1 = _rec()
    r2 = _rec(name="web_dos", expected_class="dos")
    journal.append(path, r1)
    journal.append(path, r2)
    got = journal.read(path)
    assert [r["name"] for r in got] == ["port_scan", "web_dos"]
    assert got[0]["run_uid"] == r1["run_uid"]
    assert all(set(journal.FIELDS) <= set(r) for r in got)


def test_rejected_needs_reason():
    with pytest.raises(journal.JournalError, match="reject_reason"):
        _rec(outcome="rejected")
    rec = _rec(outcome="rejected", reject_reason="цель вне стенда")
    assert rec["reject_reason"]


def test_end_before_start_rejected(tmp_path):
    with pytest.raises(journal.JournalError, match="конец раньше начала"):
        _rec(ended_at="2026-10-01T11:00:00.000Z")


def test_benign_record_for_normal():
    rec = _rec(name="background_normal", expected_class=journal.BENIGN)
    assert rec["expected_class"] == "benign"


def test_missing_file_is_empty(tmp_path):
    assert journal.read(tmp_path / "nope.jsonl") == []


def test_corrupt_line_raises(tmp_path):
    path = tmp_path / "journal.jsonl"
    journal.append(path, _rec())
    with open(path, "a", encoding="utf-8") as f:
        f.write("{не json}\n")
    with pytest.raises(journal.JournalError, match="строка 2"):
        journal.read(path)


def test_windows_sorted_and_skip_rejected():
    recs = [
        _rec(started_at="2026-10-01T12:05:00.000Z", ended_at="2026-10-01T12:06:00.000Z"),
        _rec(started_at="2026-10-01T12:00:00.000Z", ended_at="2026-10-01T12:01:00.000Z"),
        _rec(outcome="rejected", reject_reason="x"),
    ]
    wins = journal.windows(recs)
    assert len(wins) == 2  # отклонённый выброшен
    assert wins[0][0] < wins[1][0]  # отсортированы по началу
    assert wins[0][1] - wins[0][0] == 60_000  # минута в мс


def test_to_ms_utc():
    assert journal.to_ms("2026-10-01T12:00:00.000Z") == journal.to_ms(
        "2026-10-01T15:00:00.000+03:00"
    )
