"""train = serve для живого сенсора (фича 006, US2, FR-007, SC-003, конституция II).

Живой захват в тестах не поднять, поэтому проверяем эквивалентность на записи: один и тот же
`tests/fixtures/lab_sample.pcap` проходит путь сенсора (экстрактор → encode_flow → брокер →
разбор сообщения) и офлайн-путь экстрактора 001; признаки сверяются по ключу потока. Так
подтверждается, что путь отправки сенсора не искажает признаки и не теряет колонки — именно
то, что могло бы разойтись с обучением. (Эквивалентность самого живого nfstream и pcap —
свойство nfstream и проверяется живой приёмкой, маркер `lab`.)

nfstream на Windows требует запуска под __main__ (CLI это обеспечивает) и порождает процессы,
поэтому тест небыстрый, но не требует ВМ и прав админа.
"""

from pathlib import Path

import orjson
import pytest

from mlsiem.data.extract import extract_flows
from mlsiem.stream.broker import MemoryBroker, MemoryCluster, topic_specs
from mlsiem.stream.config import load_stream_config
from mlsiem.stream.messages import FEATURE_FIELDS, H_KIND, KIND_FLOW
from mlsiem.stream.sensor import SensorSink, flows_from_pcap

REPO = Path(__file__).parents[2]
LAB_PCAP = REPO / "tests" / "fixtures" / "lab_sample.pcap"
# Числовые признаки сверяем с допуском на округление JSON (round-trip float64 точен, но
# сверхосторожно оставляем маленький допуск); остальные — точно
RTOL = 1e-9


@pytest.fixture(scope="module")
def cfg():
    return load_stream_config(REPO / "configs" / "stream.yaml")


def _key(row: dict) -> tuple:
    return (
        row["src_ip"],
        row["src_port"],
        row["dst_ip"],
        row["dst_port"],
        row["protocol"],
        row["bidirectional_first_seen_ms"],
    )


def test_sensor_fields_match_offline_extractor(cfg, tmp_path):
    # Офлайн-путь 001
    offline = extract_flows(LAB_PCAP, "offline", workdir=tmp_path / "off")
    by_key = {_key(r): r for r in offline.df.iter_rows(named=True)}
    assert len(by_key) == offline.df.height  # ключ однозначен

    # Путь сенсора: те же потоки → encode_flow → брокер → разбор
    cluster = MemoryCluster()
    for s in topic_specs(cfg):
        cluster.add_topic(s.name, s.partitions, s.retention_ms)
    sink = SensorSink(MemoryBroker(cluster), cfg.topics.flows)
    n = 0
    for row in flows_from_pcap(LAB_PCAP, workdir=tmp_path / "sensor"):
        sink.feed(row)
        n += 1
    sink.end()
    assert n == len(by_key)

    flows = [
        orjson.loads(m.value)
        for m in MemoryBroker(cluster).messages(cfg.topics.flows)
        if m.headers[H_KIND] == KIND_FLOW
    ]
    assert len(flows) == n

    matched = 0
    for msg in flows:
        f = msg["fields"]
        want = by_key[_key(f)]
        # Ключевые колонки (flow_uid, capture_id) в живом режиме свои — сверяем признаки
        for name in [c for c in FEATURE_FIELDS if c not in ("flow_uid", "capture_id")]:
            got, exp = f[name], want[name]
            if isinstance(exp, float) or isinstance(got, float):
                if exp is None or got is None:
                    assert got == exp, name
                else:
                    assert got == pytest.approx(exp, rel=RTOL, abs=1e-6), name
            else:
                assert got == exp, name
        matched += 1
    assert matched == n
    # В записи есть узнаваемый скан атакующего — проверяем, что он дошёл как потоки стенда
    assert sum(1 for m in flows if m["fields"]["src_ip"] == "10.88.0.30") >= 20
