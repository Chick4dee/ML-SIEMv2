"""Тесты чтения файлов разметки UNSW-NB15 и CTU-13."""

from datetime import UTC, datetime

import pytest

from mlsiem.data.sources.ctu13 import find_binetflow, load_binetflow
from mlsiem.data.sources.unsw import load_gt
from mlsiem.data.taxonomy import UnknownLabelError


def _ms(*args) -> int:
    return int(datetime(*args, tzinfo=UTC).timestamp() * 1000)


def test_unsw_gt(fixtures_dir):
    gt = load_gt(fixtures_dir / "mini_gt.csv")
    assert gt.height == 3
    first = gt.row(0, named=True)
    # epoch-секунды UTC → миллисекунды, без часовых поясов
    assert first["gt_start_ms"] == 1421920805 * 1000 == _ms(2015, 1, 22, 10, 0, 5)
    assert first["protocol"] == 6
    assert first["label"] == "exploits"
    assert first["label_detail"].startswith("FTP anonymous")
    backdoor = gt.row(1, named=True)
    assert backdoor["label_raw"] == " Backdoors "  # исходная подпись сохраняется как есть
    assert backdoor["label"] == "backdoor"
    assert backdoor["label_detail"] == "Backdoor, with comma in name"
    assert gt.row(2, named=True)["protocol"] == 1


def test_ctu13_binetflow_timezone_and_labels(fixtures_dir):
    gt = load_binetflow(fixtures_dir / "mini.binetflow", "Europe/Prague")
    rows = gt.rows(named=True)
    # январь: Прага = UTC+1
    assert rows[0]["gt_start_ms"] == _ms(2015, 1, 22, 10, 0, 0)
    assert rows[0]["gt_end_ms"] == rows[0]["gt_start_ms"] + 80
    # август: летнее время, Прага = UTC+2
    assert rows[3]["gt_start_ms"] == _ms(2011, 8, 16, 11, 52, 3) + 78
    assert [r["label_raw"] for r in rows] == ["botnet", "normal", "background", "background"]
    assert [r["label"] for r in rows] == ["botnet", "benign", "background", "background"]
    assert rows[0]["label_detail"].startswith("flow=From-Botnet")
    # ICMP-«порты» в hex читаются, но для сопоставления не используются
    assert rows[2]["protocol"] == 1 and rows[2]["dst_port"] == 1


def test_ctu13_unknown_label(tmp_path, fixtures_dir):
    text = (fixtures_dir / "mini.binetflow").read_text(encoding="utf-8")
    bad = tmp_path / "bad.binetflow"
    bad.write_text(text.replace("flow=Background-TCP-Attempt", "flow=Mystery"), encoding="utf-8")
    with pytest.raises(UnknownLabelError, match="Mystery"):
        load_binetflow(bad, "Europe/Prague")


def test_find_binetflow_only_by_pattern(tmp_path):
    (tmp_path / "capture.binetflow").write_text("x")
    (tmp_path / "bot.exe").write_text("не трогать")
    assert find_binetflow(tmp_path).name == "capture.binetflow"
