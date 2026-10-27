"""Набор стенда версии 2 и отчёт качества (фича 008, US3): разметка по журналу, края записи, части,
сегменты.

Потоки синтетические (время и адреса заданы руками), запись журнала — словарь тех же полей, что
пишет раннер.
"""

from __future__ import annotations

import polars as pl

from mlsiem.lab import dataset_v2 as ds
from mlsiem.lab import journal, quality
from mlsiem.lab.dataset import AMBIGUOUS, BENIGN, FIRST, LAST

T0 = journal.to_ms("2026-10-24T10:00:00.000Z")
ATT, VIC = "10.88.0.32", "10.88.0.20"


def _iso(offset_s: float) -> str:
    from datetime import UTC, datetime

    return (
        datetime.fromtimestamp((T0 + offset_s * 1000) / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[
            :-3
        ]
        + "Z"
    )


def _rec(
    start_s, end_s, *, cls="dos", outcome="completed", hard=False, repeat=1, part="train", **kw
):
    r = {
        "run_uid": f"r{repeat}-{start_s}",
        "plan_run_uid": f"p{repeat}-{start_s}",
        "name": "flood",
        "version": "2",
        "attacker_ip": "10.88.0.30",
        "source_ip": ATT,
        "targets": [VIC],
        "expected_class": cls,
        "started_at": _iso(start_s),
        "ended_at": _iso(end_s),
        "outcome": outcome,
        "reject_reason": None,
        "variant": "hping_syn",
        "tool": "hping3",
        "source": "attacker_a2",
        "repeat": repeat,
        "part": part,
        "reserve_unknown": False,
        "hard_normal": hard,
    }
    r.update(kw)
    return r


def _flow(first_s, last_s, src=ATT, dst=VIC):
    return {
        FIRST: T0 + int(first_s * 1000),
        LAST: T0 + int(last_s * 1000),
        "src_ip": src,
        "dst_ip": dst,
    }


def _frame(*flows):
    return pl.DataFrame(
        list(flows),
        schema={FIRST: pl.Int64, LAST: pl.Int64, "src_ip": pl.String, "dst_ip": pl.String},
    )


def test_поток_в_окне_получает_класс_и_метаданные_а_остальные_норму():
    flows = _frame(
        _flow(10, 20),
        _flow(-50, -40),
        _flow(10, 20, src="10.88.0.77"),
        _flow(10, 20, dst="10.88.0.99"),
    )
    out = ds.label_flows_v2(flows, [_rec(5, 60)])
    assert out["label"].to_list() == ["dos", BENIGN, BENIGN, BENIGN]
    row = out.row(0, named=True)
    assert (row["variant"], row["tool"], row["source"], row["repeat"], row["part"]) == (
        "hping_syn",
        "hping3",
        "attacker_a2",
        1,
        "train",
    )
    assert out["variant"].to_list()[1:] == [None, None, None]


def test_поток_вылезший_за_окно_неоднозначен():
    # начался внутри окна, а закончился позже конца + запас (idle-таймаут) — не знаем, чей он
    flows = _frame(_flow(10, 60 + 500), _flow(10, 60 + 5))
    out = ds.label_flows_v2(flows, [_rec(5, 60)])
    assert out["label"].to_list() == [AMBIGUOUS, "dos"]


def test_прерванный_запуск_даёт_неоднозначные_потоки_а_не_норму_и_не_класс():
    out = ds.label_flows_v2(_frame(_flow(10, 20)), [_rec(5, 60, outcome="aborted")])
    assert out["label"].to_list() == [AMBIGUOUS]


def test_сложная_норма_внутри_окна_остаётся_нормой_с_метаданными():
    out = ds.label_flows_v2(
        _frame(_flow(10, 20)),
        [_rec(5, 60, cls=BENIGN, hard=True, variant="ab_loadtest", tool="ab")],
    )
    row = out.row(0, named=True)
    assert row["label"] == BENIGN and row["hard_normal"] is True and row["variant"] == "ab_loadtest"


def test_фоновая_норма_рамок_не_навязывает():
    out = ds.label_flows_v2(_frame(_flow(10, 20)), [_rec(0, 600, cls=BENIGN)])
    row = out.row(0, named=True)
    assert row["label"] == BENIGN and row["variant"] is None and row["hard_normal"] is False


def test_запуск_в_отказе_окон_не_даёт():
    out = ds.label_flows_v2(_frame(_flow(10, 20)), [_rec(5, 60, outcome="rejected")])
    assert out["label"].to_list() == [BENIGN]


def test_края_записи_сеанса_неоднозначны():
    flows = _frame(_flow(0.5, 1.0), _flow(50, 55), _flow(98.5, 99.5)).with_columns(
        pl.lit(BENIGN).alias("label")
    )
    out = ds.mark_segment_edges(flows, T0, T0 + 100_000)
    assert out["label"].to_list() == [AMBIGUOUS, BENIGN, AMBIGUOUS]


def test_части_по_раундам_и_зазор_на_границе():
    recs = [_rec(0, 60, repeat=1, part="train"), _rec(2000, 2060, repeat=2, part="val")]
    flows = _frame(
        _flow(500, 510), _flow(1990, 1995), _flow(2010, 2020), _flow(2500, 2510)
    ).with_columns(pl.lit(BENIGN).alias("label"), pl.lit(None, dtype=pl.String).alias("part"))
    out = ds.finalize_parts(flows, recs)
    # 500 с — глубоко в раунде 1; 1990 и 2010 — в зазоре вокруг границы раундов (30 с); 2500 с —
    # раунд 2
    assert out["part"].to_list() == ["train", "gap", "gap", "val"]


def test_потоки_запуска_берут_часть_из_записи_а_не_по_времени():
    recs = [_rec(0, 60, repeat=1, part="train"), _rec(2000, 2060, repeat=2, part="test")]
    out = ds.label_flows_v2(_frame(_flow(10, 20), _flow(2010, 2020)), recs)
    out = ds.finalize_parts(out, recs)
    assert out["part"].to_list() == ["train", "test"]


def test_несколько_сегментов_одного_плана(tmp_path):
    recs = [
        _rec(5, 60, repeat=1, part="train"),
        _rec(500, 560, repeat=2, part="test", variant="hping_syn"),
    ]
    seg1 = _frame(
        _flow(0, 0.5, src="10.88.0.1"),
        _flow(10, 20),
        _flow(30, 40, src="10.88.0.1"),
        _flow(100, 100.5, src="10.88.0.1"),
    )
    seg2 = _frame(
        _flow(450, 450.2, src="10.88.0.1"),
        _flow(510, 520),
        _flow(580, 580.5, src="10.88.0.1"),
        _flow(600, 601, src="10.88.0.1"),
    )
    frames = {"s1.pcap": seg1, "s2.pcap": seg2}
    segments = [
        {"session_id": "s1", "pcaps": [tmp_path / "s1.pcap"]},
        {"session_id": "s2", "pcaps": [tmp_path / "s2.pcap"]},
    ]
    man = ds.build_dataset_v2(
        segments, recs, tmp_path / "out", "t1", plan_hash="h", extract=lambda p, cid: frames[p.name]
    )
    df = pl.read_parquet(tmp_path / "out" / "flows.parquet")
    assert man["n_flows"] == 8 and man["format"] == 2 and man["plan_hash"] == "h"
    assert set(df["session_id"].to_list()) == {"s1", "s2"}
    dos = df.filter(pl.col("label") == "dos")
    assert dos.height == 2 and set(dos["part"].to_list()) == {"train", "test"}
    assert set(dos["session_id"].to_list()) == {
        "s1",
        "s2",
    }  # окна двух запусков — в разных сегментах
    # края каждого сегмента неоднозначны независимо
    assert df.filter(pl.col("label") == AMBIGUOUS).height >= 2
    assert (tmp_path / "out" / "manifest.json").exists()


# ----------------------------------------------------------------------------------- качество


def _quality_frame(
    *, by_source=False, one_tool=False, ambiguous_share=0.0, benign_one_addr=False, test_flows=200
):
    rows = []
    sources = ["attacker", "attacker_a2", "attacker_a3"]
    classes = {"dos": ["A", "B"], "recon": ["C", "D"], "fuzz": ["E", "F"]}
    for ci, (cls, tools) in enumerate(classes.items()):
        for ti, tool in enumerate(tools[:1] if one_tool and cls == "fuzz" else tools):
            for rep in range(1, 11):
                part = "train" if rep <= 6 else ("val" if rep <= 8 else "test")
                src = sources[ci] if by_source else sources[(ti + rep) % 3]
                n = test_flows if part == "test" else 50
                rows += [
                    {
                        "label": cls,
                        "tool": tool,
                        "source": src,
                        "repeat": rep,
                        "part": part,
                        "reserve_unknown": False,
                        "src_ip": "10.88.0.30",
                    }
                ] * n
    for rep in range(1, 11):
        part = "train" if rep <= 6 else ("val" if rep <= 8 else "test")
        for ip, share in (
            ("10.88.0.30", 1.0 if benign_one_addr else 0.4),
            ("10.88.0.32", 0.0 if benign_one_addr else 0.3),
            ("10.88.0.33", 0.0 if benign_one_addr else 0.3),
        ):
            rows += [
                {
                    "label": BENIGN,
                    "tool": None,
                    "source": None,
                    "repeat": rep,
                    "part": part,
                    "reserve_unknown": False,
                    "src_ip": ip,
                }
            ] * int(300 * share)
    amb = int(len(rows) * ambiguous_share)
    rows += [
        {
            "label": AMBIGUOUS,
            "tool": "A",
            "source": "attacker",
            "repeat": 1,
            "part": "train",
            "reserve_unknown": False,
            "src_ip": "10.88.0.30",
        }
    ] * amb
    return pl.DataFrame(
        rows,
        schema={
            "label": pl.String,
            "tool": pl.String,
            "source": pl.String,
            "repeat": pl.Int64,
            "part": pl.String,
            "reserve_unknown": pl.Boolean,
            "src_ip": pl.String,
        },
    )


def _rep(df, **kw):
    kw.setdefault("min_test_benign", 100)
    return quality.quality_report(df, source_names={"10.88.0.30": "attacker"}, **kw)


def test_качество_чистый_набор():
    rep = _rep(_quality_frame())
    assert rep["verdict"] == "clean", rep["reasons"]
    assert rep["nmi"]["class_source"] < 0.3 and rep["nmi"]["class_repeat"] < 0.3
    assert set(rep["tools_by_class"]) == {"dos", "recon", "fuzz"}


def test_качество_класс_определяется_источником():
    rep = _rep(_quality_frame(by_source=True))
    assert rep["verdict"] == "suspect" and rep["nmi"]["class_source"] > 0.9
    assert any(r["type"] == "nmi_class_source" for r in rep["reasons"])


def test_качество_у_класса_один_инструмент():
    rep = _rep(_quality_frame(one_tool=True))
    assert any(r["type"] == "single_tool" and r["class"] == "fuzz" for r in rep["reasons"])


def test_качество_много_неоднозначных():
    rep = _rep(_quality_frame(ambiguous_share=0.2))
    assert any(r["type"] == "ambiguous" for r in rep["reasons"]) and rep["verdict"] == "suspect"


def test_качество_норма_с_одного_адреса():
    rep = _rep(_quality_frame(benign_one_addr=True))
    assert any(r["type"] == "benign_source" for r in rep["reasons"])


def test_качество_мало_потоков_в_тесте_это_предупреждение_а_не_вердикт():
    rep = _rep(_quality_frame(test_flows=10), min_test_flows=100)
    assert rep["verdict"] == "clean" and any(w["type"] == "few_test_flows" for w in rep["warnings"])
    assert {u["class"] for u in rep["unreliable_classes"]} == {"dos", "recon", "fuzz"}


def test_отчёт_качества_пишется(tmp_path):
    rep = _rep(_quality_frame())
    md, js = quality.write_report(rep, tmp_path / "ds", "v1")
    assert "Вердикт: clean" in md.read_text(encoding="utf-8") and js.exists()
