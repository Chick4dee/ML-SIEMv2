"""Разметка набора стенда по журналу (фича 006, US4, FR-020, SC-007).

Поток атакующего на цель в окне → класс сценария; пересекающий границу окна → ambiguous
(исключается из метрик, но считается); остальное → benign. Схема признаков — 001.
"""

from pathlib import Path

import polars as pl
import pytest

from mlsiem.lab import journal
from mlsiem.lab.dataset import build_dataset, dataset_report, label_flow, label_flows

REPO = Path(__file__).parents[2]
FIRST = "bidirectional_first_seen_ms"
LAST = "bidirectional_last_seen_ms"
# Окно сценария: 12:00:00–12:01:00
W_START = journal.to_ms("2026-10-01T12:00:00.000Z")
W_END = journal.to_ms("2026-10-01T12:01:00.000Z")


def _scan_record():
    return journal.make_record(
        name="port_scan",
        version="1",
        attacker_ip="10.88.0.30",
        targets=["10.88.0.20"],
        expected_class="reconnaissance",
        started_at="2026-10-01T12:00:00.000Z",
        ended_at="2026-10-01T12:01:00.000Z",
        outcome="completed",
    )


def _flow(src, dst, first, last):
    return {FIRST: first, LAST: last, "src_ip": src, "dst_ip": dst}


def test_flow_inside_window_gets_class():
    wins = journal.windows([_scan_record()])
    lbl = label_flow(W_START + 1000, W_START + 2000, "10.88.0.30", "10.88.0.20", wins, margin_ms=0)
    assert lbl == "reconnaissance"


def test_flow_crossing_boundary_is_ambiguous():
    wins = journal.windows([_scan_record()])
    # Начался до начала окна, кончился внутри — пересекает границу
    lbl = label_flow(W_START - 5000, W_START + 1000, "10.88.0.30", "10.88.0.20", wins, margin_ms=0)
    assert lbl == "ambiguous"


def test_benign_when_not_attacker_or_target():
    wins = journal.windows([_scan_record()])
    # Обычный клиент .31 — не атакующий
    assert label_flow(W_START + 1, W_START + 2, "10.88.0.31", "10.88.0.20", wins, 0) == "benign"
    # Атакующий, но не в окне по времени
    assert (
        label_flow(W_END + 10_000, W_END + 20_000, "10.88.0.30", "10.88.0.20", wins, 0) == "benign"
    )


def test_margin_keeps_late_finish_in_class():
    wins = journal.windows([_scan_record()])
    # Кончился на 30 с позже конца окна, но в пределах допуска idle-таймаута
    lbl = label_flow(
        W_START + 1000, W_END + 30_000, "10.88.0.30", "10.88.0.20", wins, margin_ms=120_000
    )
    assert lbl == "reconnaissance"


def test_label_flows_dataframe_and_report():
    records = [_scan_record()]
    flows = pl.DataFrame(
        [
            _flow("10.88.0.30", "10.88.0.20", W_START + 1000, W_START + 2000),  # класс
            _flow("10.88.0.30", "10.88.0.20", W_START - 5000, W_START + 1000),  # ambiguous
            _flow("10.88.0.31", "10.88.0.20", W_START + 1000, W_START + 2000),  # benign
            _flow("10.88.0.31", "10.88.0.20", W_END + 10_000, W_END + 11_000),  # benign
        ]
    )
    labeled = label_flows(flows, records, margin_ms=0)
    assert labeled["label"].to_list() == ["reconnaissance", "ambiguous", "benign", "benign"]
    rep = dataset_report(labeled, records)
    assert rep["total_flows"] == 4 and rep["ambiguous"] == 1
    assert rep["by_class"]["benign"] == 2
    assert rep["scenarios"] == [("port_scan", "1")]
    # ambiguous среди потоков сценариев: 1 из (1 класс + 1 ambiguous) = 0.5
    assert rep["ambiguous_share_of_scenarios"] == pytest.approx(0.5)


def test_build_dataset_writes_artifacts(tmp_path):
    records = [_scan_record()]
    flows = pl.DataFrame([_flow("10.88.0.30", "10.88.0.20", W_START + 1000, W_START + 2000)])
    out = tmp_path / "v1"
    build_dataset(flows, records, out, "v1", margin_ms=0, sources=["sess-1"])
    assert (out / "flows.parquet").exists()
    assert (out / "manifest.json").exists() and (out / "report.md").exists()
    import json

    man = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert man["n_flows"] == 1 and man["schema_version"]
    assert man["sources"] == ["sess-1"]
    saved = pl.read_parquet(out / "flows.parquet")
    assert "label" in saved.columns and saved["label"][0] == "reconnaissance"
