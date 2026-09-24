"""Скорость списка инцидентов (SC-006): ~1000 инцидентов и ~100 тыс. алертов — ответ < 1 с."""

import json
import time

from fastapi.testclient import TestClient

from api.conftest import API
from mlsiem.soc import store
from mlsiem.soc.api import create_app

SEVERITIES = ("low", "medium", "high", "critical")


def test_list_is_fast(soc_cfg, tmp_path):
    conn = store.connect(soc_cfg.db)
    store.init_db(conn)
    n_inc, per_inc = 1000, 100
    incidents, alerts, actions = [], [], []
    for i in range(n_inc):
        iid = f"inc-{i:012d}"
        incidents.append(
            {
                "incident_id": iid,
                "src_ip": f"175.45.176.{i % 4}",
                "attack_class": "dos",
                "targets": json.dumps(["10.0.0.1"]),
                "first_seen_ms": i * 10_000,
                "last_seen_ms": i * 10_000 + 5_000,
                "n_alerts": per_inc,
                "max_score": 0.99,
                "mean_score": 0.9,
                "severity": SEVERITIES[i % 4],
                "severity_reason": "…",
            }
        )
        actions.append(
            {
                "action_id": f"act-{iid}",
                "incident_id": iid,
                "action_type": "block_source_ip",
                "target": f"175.45.176.{i % 4}",
                "rule_id": "noisy_attack",
                "rule_text": "…",
            }
        )
        for j in range(per_inc):
            alerts.append(
                {
                    "incident_id": iid,
                    "flow_uid": f"cap/{i}/{j}",
                    "capture_id": "cap",
                    "src_ip": f"175.45.176.{i % 4}",
                    "src_port": 1000,
                    "dst_ip": "10.0.0.1",
                    "dst_port": 80,
                    "protocol": 6,
                    "first_seen_ms": i * 10_000 + j,
                    "last_seen_ms": i * 10_000 + j + 1,
                    "predicted_class": "dos",
                    "attack_score": 0.9,
                }
            )
    run = {
        "run_id": "perf",
        "source": "split:x/test",
        "input_hash": "abc",
        "detector_version": "v",
        "started_at": store.now_iso(),
        "n_flows": len(alerts),
    }
    store.write_run(conn, run, alerts, incidents, actions)
    conn.close()

    with TestClient(create_app(soc_cfg)) as client:
        client.get(f"{API}/health")  # прогрев: первое соединение, импорт схем
        started = time.perf_counter()
        r = client.get(f"{API}/incidents", params={"severity": "critical,high"})
        elapsed = time.perf_counter() - started
    assert r.status_code == 200
    assert r.json()["total"] == n_inc // 2
    assert elapsed < 1.0, f"список ответил за {elapsed:.2f} с"
