"""CLI потока на брокере-заглушке: replay → consume → compare → close (contracts/cli.md)."""

import re

import pytest
import yaml

from fixtures.stream_helpers import make_cluster, make_soc_cfg, make_stream_cfg
from mlsiem import cli
from mlsiem.soc import store
from mlsiem.stream import broker as broker_mod
from mlsiem.stream.broker import MemoryBroker


@pytest.fixture
def env(tmp_path, monkeypatch):
    stream_cfg, soc_cfg = make_stream_cfg(), make_soc_cfg(tmp_path)
    cluster = make_cluster(stream_cfg)
    monkeypatch.setattr(
        broker_mod,
        "make_broker",
        lambda cfg, role="x": MemoryBroker(
            cluster, group=cfg.consumer.group, vm_name=cfg.stand.vm_name
        ),
    )
    soc_yaml = tmp_path / "soc.yaml"
    soc_yaml.write_text(yaml.safe_dump(soc_cfg.raw, allow_unicode=True), encoding="utf-8")
    return stream_cfg, soc_cfg, cluster, soc_yaml


def test_replay_consume_compare_cli(env, synthetic_split, tiny_detector, tmp_path, capsys):
    stream_cfg, soc_cfg, cluster, soc_yaml = env
    args = ["stream", "--soc-config", str(soc_yaml)]
    code = cli.main(
        [
            *args,
            "replay",
            "--split",
            "unsw_time",
            "--part",
            "test",
            "--speed",
            "max",
            "--data-dir",
            str(synthetic_split),
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    source_id = re.search(r"source_id: (\S+)", out).group(1)
    assert source_id.startswith("replay:unsw_time/test:")
    assert "отправлено" in out and "потоков/с" in out

    assert cli.main([*args, "consume", "--model", str(tiny_detector), "--once"]) == 0
    out = capsys.readouterr().out
    run_id = store.session_run_id(source_id)
    assert "Потребитель остановлен" in out and run_id in out

    assert (
        cli.main(
            [
                "soc",
                "--config",
                str(soc_yaml),
                "run",
                "--split",
                "unsw_time",
                "--part",
                "test",
                "--model",
                str(tiny_detector),
                "--data-dir",
                str(synthetic_split),
            ]
        )
        == 0
    )
    batch_id = re.search(r"Прогон (\S+)", capsys.readouterr().out).group(1)
    reports = tmp_path / "reports"
    code = cli.main(
        [*args, "compare", "--session", run_id, "--batch", batch_id, "--reports-dir", str(reports)]
    )
    assert code == 0
    assert "эквивалентно" in capsys.readouterr().out
    assert (reports / f"stream_compare_{run_id}.md").exists()

    # Сеанс уже завершён отметкой end — close сообщает об этом и не падает
    assert cli.main([*args, "close", "--session", run_id]) == 0
    assert "уже завершён" in capsys.readouterr().out
    assert cli.main([*args, "close", "--session", batch_id]) == 1


def test_replay_broker_unavailable(env, synthetic_split, capsys):
    stream_cfg, soc_cfg, cluster, soc_yaml = env
    cluster.down = True
    code = cli.main(
        [
            "stream",
            "replay",
            "--split",
            "unsw_time",
            "--part",
            "test",
            "--data-dir",
            str(synthetic_split),
        ]
    )
    assert code == 1
    assert "Start-VM" in capsys.readouterr().err


def test_replay_bad_input(env, capsys):
    assert cli.main(["stream", "replay", "--part", "test"]) == 1
    assert "нужен вход" in capsys.readouterr().err
    assert cli.main(["stream", "replay", "--pcap", "x.pcap", "--split", "unsw_time"]) == 1


def test_close_running_session(env, capsys):
    stream_cfg, soc_cfg, cluster, soc_yaml = env
    conn = store.connect(soc_cfg.db)
    store.init_db(conn)
    run = store.create_session(conn, "sensor:lab", model_version="m", summary={})
    assert (
        cli.main(["stream", "--soc-config", str(soc_yaml), "close", "--session", run["run_id"]])
        == 0
    )
    assert "running → completed" in capsys.readouterr().out
    assert store.get_run(conn, run["run_id"])["status"] == "completed"
    ev = store.list_audit(conn, {"event": "session_status_changed"})[1]
    assert ev[-1]["details"]["new"] == "completed"
