"""Живой сенсор в цепочке 005 (фича 006, US2): сенсор → брокер → потребитель → показатели.

Без ВМ: вместо живого захвата — запись `lab_sample.pcap`, брокер — MemoryBroker 005. Проверяем,
что сенсор шлёт потоки как источник `sensor:live`, потребитель заводит из них обычный сеанс, а
показатели сенсора (packets/с, потоки/с, живость) видны в `stream status`.
"""

from pathlib import Path

from fixtures.stream_helpers import make_cluster, make_soc_cfg, make_stream_cfg, run_consumer
from mlsiem.soc import store
from mlsiem.stream.broker import MemoryBroker
from mlsiem.stream.sensor import flows_from_pcap, run_sensor
from mlsiem.stream.stats import status_report

REPO = Path(__file__).parents[2]
LAB_PCAP = REPO / "tests" / "fixtures" / "lab_sample.pcap"


def test_sensor_feeds_chain_and_reports(synthetic_split, tiny_detector, tmp_path):
    stream_cfg = make_stream_cfg(batch_max_messages=500)
    soc_cfg = make_soc_cfg(tmp_path)
    source_id = stream_cfg.lab.sensor.source_id
    cluster = make_cluster(stream_cfg)

    # Часы сенсора двигаем вручную (по +1 с на вызов), чтобы сработал интервал показателей
    now = {"t": 1000.0}

    def clock() -> float:
        now["t"] += 1.0
        return now["t"]

    conn = store.connect(soc_cfg.db)
    store.init_db(conn)
    flows = list(flows_from_pcap(LAB_PCAP, workdir=tmp_path / "s"))
    summary = run_sensor(stream_cfg, conn, MemoryBroker(cluster), iter(flows), clock=clock)
    conn.close()
    assert summary.source_id == source_id
    assert summary.counters.flows_sent == len(flows) > 0
    assert summary.remaining == 0 and not summary.lossy

    # Потребитель заводит обычный сеанс из sensor:live и доводит до конца
    csum = run_consumer(cluster, stream_cfg, soc_cfg, tiny_detector)
    assert csum.processed == len(flows)

    conn = store.connect(soc_cfg.db)
    try:
        run = store.session_by_source(conn, source_id)
        assert run is not None and run["mode"] == "stream"
        assert run["run_id"] == store.session_run_id(source_id)
        rep = status_report(conn, stream_cfg)
        sess = next(s for s in rep["sessions"] if s["source_id"] == source_id)
        assert sess["is_sensor"] is True
        assert sess["packets_per_s"] is not None and sess["packets_per_s"] > 0
        assert sess["flows_per_s"] is not None
        assert sess["liveness"] in (0, 1)
        assert sess["drops"] == 0
    finally:
        conn.close()
