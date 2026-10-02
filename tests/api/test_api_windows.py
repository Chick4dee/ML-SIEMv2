"""API: только добавления фичи 007 (contracts/api-ui-additions.md, FR-016, FR-017).

В базе два прогона одной синтетики: с экспертом окон (`force`, модель tiny_windows) и «до
007» — без эксперта окон и без раздела `windows` в сводке. Новые поля у старого прогона —
значения по умолчанию (`kind = "flow"`, `window = null`, 0 алертов окон, `windows = null`).
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mlsiem.soc import store
from mlsiem.soc.api import create_app
from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.soc.run import run_chain

REPO = Path(__file__).parents[2]
API = "/api/v1"
# Строгие наборы ключей 007 (дополняют *_KEYS_002…005 из test_api_experts.py)
ALERT_KEYS_007 = {"kind", "window"}
INCIDENT_KEYS_007 = {"n_window_alerts"}
RUN_KEYS_007 = {"windows"}
WINDOW_INFO_KEYS = {
    "window_id",
    "start_ms",
    "end_ms",
    "n_flows",
    "truncated",
    "seq_max",
    "targets",
    "n_dst_ports",
    "top_flows",
    "top_features",
    "expert_version",
    "kind",
}


@pytest.fixture(scope="module")
def win_client(tmp_path_factory, tiny_detector, tiny_windows, synthetic_split):
    tmp = tmp_path_factory.mktemp("api_windows")
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    cfg = parse_soc_config({**raw, "db": str(tmp / "soc.db"), "runs_dir": str(tmp / "runs")})
    common = {"model_dir": tiny_detector, "data_dir": synthetic_split}
    new = run_chain(
        "split:unsw_time/test", cfg, windows_mode="force", windows_model=tiny_windows, **common
    )
    old = run_chain("split:unsw_time/val", cfg, windows_mode="off", **common)
    conn = store.connect(cfg.db)
    with store.transaction(conn):
        # «Прогон до 007»: в сводке нет раздела windows (так писали 002–005)
        conn.execute(
            "UPDATE runs SET summary = json_remove(summary, '$.windows') WHERE run_id = ?",
            (old.run_id,),
        )
    conn.close()
    with TestClient(create_app(cfg, detector_dir=tiny_detector)) as c:
        yield c, new, old


def _window_incident(client, run_id):
    items = client.get(
        f"{API}/incidents", params={"run_id": run_id, "has_window_alerts": "true", "limit": 500}
    ).json()["items"]
    assert items, "в прогоне с force должны быть инциденты с алертами окон"
    return items[0]


def test_incident_list_fields_and_filter(win_client):
    client, new, old = win_client
    all_ = client.get(f"{API}/incidents", params={"run_id": new.run_id, "limit": 500}).json()
    with_w = client.get(
        f"{API}/incidents", params={"run_id": new.run_id, "has_window_alerts": "true", "limit": 500}
    ).json()
    without = client.get(
        f"{API}/incidents",
        params={"run_id": new.run_id, "has_window_alerts": "false", "limit": 500},
    ).json()
    assert with_w["total"] + without["total"] == all_["total"]
    assert all(i["n_window_alerts"] > 0 for i in with_w["items"])
    assert all(i["n_window_alerts"] == 0 for i in without["items"])
    for i in all_["items"]:
        assert set(i) >= INCIDENT_KEYS_007
    olds = client.get(f"{API}/incidents", params={"run_id": old.run_id, "limit": 500}).json()
    assert olds["total"] > 0 and all(i["n_window_alerts"] == 0 for i in olds["items"])


def test_window_alert_fields_and_kind_filter(win_client):
    client, new, _ = win_client
    inc = _window_incident(client, new.run_id)
    url = f"{API}/incidents/{inc['incident_id']}/alerts"
    everything = client.get(url, params={"limit": 500}).json()
    windows = client.get(url, params={"kind": "window", "limit": 500}).json()
    flows = client.get(url, params={"kind": "flow", "limit": 500}).json()
    assert windows["total"] == inc["n_window_alerts"]
    assert windows["total"] + flows["total"] == everything["total"]
    for a in windows["items"]:
        assert set(a) >= ALERT_KEYS_007
        assert a["kind"] == "window"
        assert (a["src_port"], a["dst_port"], a["protocol"]) == (None, None, None)
        assert a["flow_uid"] == a["window"]["window_id"]
        assert set(a["window"]) == WINDOW_INFO_KEYS
        assert a["window"]["start_ms"] <= a["first_seen_ms"] <= a["last_seen_ms"]
    for a in flows["items"]:
        assert a["kind"] == "flow" and a["window"] is None
    assert client.get(url, params={"kind": "packet"}).status_code == 422


def test_card_counts_window_alerts(win_client):
    client, new, _ = win_client
    inc = _window_incident(client, new.run_id)
    card = client.get(f"{API}/incidents/{inc['incident_id']}").json()
    assert card["n_window_alerts"] == inc["n_window_alerts"]


def test_runs_windows_section(win_client):
    client, new, old = win_client
    runs = {r["run_id"]: r for r in client.get(f"{API}/runs").json()["items"]}
    for r in runs.values():
        assert set(r) >= RUN_KEYS_007
    w = runs[new.run_id]["windows"]
    assert w["mode"] == "force" and w["enabled"] is True and w["kind"] == "lgbm"
    assert runs[old.run_id]["windows"] is None


def test_old_run_alerts_are_flows(win_client):
    client, _, old = win_client
    inc = client.get(f"{API}/incidents", params={"run_id": old.run_id}).json()["items"][0]
    items = client.get(f"{API}/incidents/{inc['incident_id']}/alerts").json()["items"]
    assert all(a["kind"] == "flow" and a["window"] is None for a in items)
    assert json.loads(json.dumps(items))  # сериализуется как прежде
