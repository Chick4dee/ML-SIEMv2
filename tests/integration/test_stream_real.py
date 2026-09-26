"""Полная часть test `unsw_time` через настоящий брокер (SC-002, SC-004): `slow` + `stand`.

Нужны данные 001 в data/ (разбиение unsw_time), обученная модель и поднятый стенд. Запуск:
`uv run pytest -m "slow and stand" tests/integration/test_stream_real.py`.
"""

import dataclasses
import threading
import time
import uuid
from pathlib import Path

import pytest

from mlsiem.soc import store
from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.soc.run import run_chain
from mlsiem.stream.broker import BrokerUnavailable, TopicSpec, make_broker
from mlsiem.stream.compare import compare
from mlsiem.stream.config import load_stream_config
from mlsiem.stream.consumer import consume
from mlsiem.stream.replay import load_split_source, replay

pytestmark = [pytest.mark.slow, pytest.mark.stand]
REPO = Path(__file__).parents[2]
DATA = REPO / "data"
MODEL = REPO / "models" / "ensemble"


def test_unsw_time_test_full(tmp_path):
    if not (DATA / "splits" / "unsw_time.parquet").exists():
        pytest.skip("нет разбиения unsw_time в data/ (фича 001)")
    model = MODEL if (MODEL / "ensemble_card.json").exists() else REPO / "models" / "detector"
    if not model.exists():
        pytest.skip("нет обученной модели в models/")
    base = load_stream_config(REPO / "configs" / "stream.yaml")
    probe = make_broker(base, "test")
    try:
        probe.ping()
    except BrokerUnavailable as exc:
        pytest.skip(f"стенд не поднят: {exc}")
    tag = uuid.uuid4().hex[:8]
    cfg = dataclasses.replace(
        base,
        topics=dataclasses.replace(
            base.topics, flows=f"mlsiem.test.{tag}", rejected=f"mlsiem.test.{tag}.rej"
        ),
        consumer=dataclasses.replace(base.consumer, group=f"mlsiem-test-{tag}"),
    )
    probe.ensure_topics(
        [TopicSpec(cfg.topics.flows, 1, 86_400_000), TopicSpec(cfg.topics.rejected, 1, 86_400_000)]
    )
    probe.close()
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    soc = parse_soc_config({**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "r")})

    source = load_split_source("unsw_time", "test", data_dir=DATA)
    src = f"replay:unsw_time/test:{tag}"
    done = threading.Event()
    stats: dict = {}

    def consumer_thread():
        b = make_broker(cfg, "consumer")
        try:
            stats["summary"] = consume(cfg, soc, broker=b, model_dir=model, stop=done.is_set)
        finally:
            b.close()

    t0 = time.monotonic()
    th = threading.Thread(target=consumer_thread)
    th.start()
    producer = make_broker(cfg, "replay")
    replay(source, producer, cfg.topics.flows, source_id=src, speed=None)
    producer.close()
    replay_end = time.monotonic()
    # Ждём завершения сеанса (получен end, всё обработано): всё — не дольше 10 минут, а
    # «хвост» после конца проигрывания (отставание потребителя) — не дольше 30 с (SC-002)
    conn = store.connect(soc.db)
    run = None
    while time.monotonic() - t0 < 600:
        run = store.session_by_source(conn, src)
        if run and run["status"] == "completed":
            break
        time.sleep(0.5)
    finished = time.monotonic()
    done.set()
    th.join(60)
    # Цифры для журнала (видны с `pytest -s`)
    print(
        f"\n[SC-002] потоков {source.total}: проигрывание {replay_end - t0:.1f} с, всё "
        f"{finished - t0:.1f} с, хвост после конца проигрывания {finished - replay_end:.1f} с"
    )
    assert run is not None and run["status"] == "completed"
    assert finished - t0 <= 600
    assert finished - replay_end <= 30, (
        f"отставание к концу проигрывания {finished - replay_end:.0f} с"
    )
    assert run["n_flows"] == source.total

    batch = run_chain("split:unsw_time/test", soc, model_dir=model, data_dir=DATA)
    rep = compare(conn, soc.runs_dir, run["run_id"], batch.run_id)
    assert rep["equivalent"], rep["divergences"][:5]
    print(
        f"[SC-004] вердикты {rep['verdicts']['matched']}/{rep['verdicts']['both']}, инциденты "
        f"{rep['incidents']['matched']}/{rep['incidents']['batch']}, действия "
        f"{rep['actions']['matched']}/{rep['actions']['compared']}"
    )
