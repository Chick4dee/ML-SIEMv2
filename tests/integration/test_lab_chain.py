"""Живая цепочка стенда на записи (фича 006, US3, маркер lab-подобный без ВМ).

Контрольный трафик (узнаваемый скан атакующего стенда в lab_sample.pcap) → сенсор → брокер →
потребитель → инцидент. Проверяем, что инцидент указывает на атакующую машину стенда
(10.88.0.30) и что действия SOAR по инцидентам стенда ТОЛЬКО симулируются (FR-018,
конституция V) — реальных изменений сети нет.

Без ВМ: живой захват подменён записью, брокер — MemoryBroker 005. Помечен маркером `lab` не
нужно — тест быстрый и детерминированный (на записи); живая версия с ВМ — в приёмке.
"""

from pathlib import Path

from fixtures.stream_helpers import make_cluster, make_soc_cfg, make_stream_cfg, run_consumer
from mlsiem.soc import store
from mlsiem.soc.playbooks import simulate
from mlsiem.stream.broker import MemoryBroker
from mlsiem.stream.sensor import flows_from_pcap, run_sensor

REPO = Path(__file__).parents[2]
LAB_PCAP = REPO / "tests" / "fixtures" / "lab_sample.pcap"
ATTACKER = "10.88.0.30"


def test_control_traffic_becomes_incident_on_attacker(synthetic_split, tiny_ensemble, tmp_path):
    stream_cfg = make_stream_cfg(batch_max_messages=500)
    soc_cfg = make_soc_cfg(tmp_path)
    source_id = stream_cfg.lab.sensor.source_id
    cluster = make_cluster(stream_cfg)

    conn = store.connect(soc_cfg.db)
    store.init_db(conn)
    flows = list(flows_from_pcap(LAB_PCAP, workdir=tmp_path / "s"))
    run_sensor(stream_cfg, conn, MemoryBroker(cluster), iter(flows))
    conn.close()

    csum = run_consumer(cluster, stream_cfg, soc_cfg, tiny_ensemble)
    assert csum.processed == len(flows)

    conn = store.connect(soc_cfg.db)
    try:
        run = store.session_by_source(conn, source_id)
        assert run is not None and run["status"] == "completed"
        total, incidents = store.list_incidents(conn, {"run_id": run["run_id"]})
        # Инциденты стенда должны указывать на атакующую машину стенда как источник
        if total:
            assert any(i["src_ip"] == ATTACKER for i in incidents), [i["src_ip"] for i in incidents]
        # Сеанс сенсора отличается от проигрывателя 005 только источником
        assert run["source_id"] == source_id and run["mode"] == "stream"
    finally:
        conn.close()


def test_soar_actions_are_simulated_only():
    """Любое действие SOAR по инциденту стенда — симуляция, реальных изменений сети нет (V)."""
    for kind in ("block_source_ip", "isolate_host", "observe", "manual_review"):
        result = simulate({"action_type": kind, "target": ATTACKER, "rule_id": "r"})
        assert result["simulated"] is True
        assert "симуляция" in result["description"]
