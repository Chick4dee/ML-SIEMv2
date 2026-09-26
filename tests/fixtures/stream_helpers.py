"""Общие помощники тестов потока (фича 005): конфиги во временном каталоге, брокер-заглушка,
проигрывание синтетики и запуск потребителя — всё без машины стенда."""

from __future__ import annotations

import copy
from pathlib import Path

import yaml

from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.stream.broker import MemoryBroker, MemoryCluster, topic_specs
from mlsiem.stream.config import parse_stream_config
from mlsiem.stream.consumer import consume
from mlsiem.stream.replay import load_split_source, replay

REPO = Path(__file__).parents[2]


def make_stream_cfg(**consumer):
    raw = copy.deepcopy(
        yaml.safe_load((REPO / "configs" / "stream.yaml").read_text(encoding="utf-8"))
    )
    raw["consumer"].update(consumer)
    return parse_stream_config(raw)


def make_soc_cfg(tmp_path: Path, **over):
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    return parse_soc_config(
        {**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "runs"), **over}
    )


def make_cluster(cfg) -> MemoryCluster:
    c = MemoryCluster()
    for s in topic_specs(cfg):
        c.add_topic(s.name, s.partitions, s.retention_ms)
    return c


def replay_split(
    cluster: MemoryCluster,
    cfg,
    data_dir: Path,
    source_id: str,
    *,
    part: str = "test",
    limit: int | None = None,
):
    source = load_split_source("unsw_time", part, data_dir=data_dir, limit=limit)
    return replay(source, MemoryBroker(cluster), cfg.topics.flows, source_id=source_id, speed=None)


def run_consumer(cluster, stream_cfg, soc_cfg, model_dir, **kw):
    broker = kw.pop("broker", None) or MemoryBroker(cluster, group=stream_cfg.consumer.group)
    return consume(stream_cfg, soc_cfg, broker=broker, model_dir=model_dir, once=True, **kw)


def replay_with_inserts(
    cluster: MemoryCluster, cfg, data_dir: Path, source_id: str, extra, *, limit=None
) -> int:
    """Проиграть часть test во временный кластер и переложить в `cluster`, вставив перед
    отметкой end дополнительные сообщения `extra` — [(ключ, тело, заголовки)]. Возвращает
    число потоков источника."""
    tmp = make_cluster(cfg)
    sent = replay_split(tmp, cfg, data_dir, source_id, limit=limit)
    msgs = MemoryBroker(tmp).messages(cfg.topics.flows)
    out = MemoryBroker(cluster)
    for m in msgs[:-1]:
        out.produce(m.topic, m.key, m.value, m.headers)
    for key, value, headers in extra:
        out.produce(cfg.topics.flows, key, value, headers)
    end = msgs[-1]
    out.produce(end.topic, end.key, end.value, end.headers)
    return sent.total
