"""Проигрыватель PCAP (US2 п. 3): потоки — тем же экстрактором 001, что `soc run --pcap`."""

import polars as pl

from fixtures.stream_helpers import make_cluster, make_soc_cfg, make_stream_cfg, run_consumer
from mlsiem.soc import store
from mlsiem.soc.run import run_chain
from mlsiem.stream.broker import MemoryBroker
from mlsiem.stream.compare import compare
from mlsiem.stream.messages import FEATURE_FIELDS, decode_flows
from mlsiem.stream.replay import load_pcap_source, replay

SRC = "replay:synthetic.pcap:20260925T170000"


def test_pcap_replay_matches_soc_run(tmp_path, synthetic_pcap, tiny_detector):
    stream_cfg, soc_cfg = make_stream_cfg(), make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    source = load_pcap_source(synthetic_pcap, tmp_path / "work")
    assert source.total > 0 and source.label == "synthetic.pcap"
    replay(source, MemoryBroker(cluster), stream_cfg.topics.flows, source_id=SRC, speed=None)

    frame, rejected, ends = decode_flows(MemoryBroker(cluster).messages(stream_cfg.topics.flows))
    assert rejected == [] and len(ends) == 1
    assert frame["label"].null_count() == frame.height  # неразмеченный вход

    batch = run_chain(f"pcap:{synthetic_pcap}", soc_cfg, model_dir=tiny_detector)
    flows = pl.read_parquet(soc_cfg.runs_dir / batch.run_id / "flows.parquet")
    got = frame.select(FEATURE_FIELDS).sort("flow_uid")
    want = flows.select(FEATURE_FIELDS).sort("flow_uid")
    assert got.equals(want, null_equal=True)

    run_consumer(cluster, stream_cfg, soc_cfg, tiny_detector)
    conn = store.connect(soc_cfg.db)
    rep = compare(conn, soc_cfg.runs_dir, store.session_run_id(SRC), batch.run_id)
    assert rep["equivalent"], rep["divergences"][:3]
    assert rep["verdicts"]["matched"] == source.total
