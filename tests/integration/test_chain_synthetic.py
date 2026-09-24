"""Вся цепочка на синтетике (quickstart §1): обучение → прогон → API → решения аналитика.

Через CLI, как это делал бы пользователь: `detect train`, `soc run`, затем API поверх той же
базы. Повторный прогон должен дать те же инциденты, серьёзности и предложения (SC-002).
"""

from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from mlsiem import cli
from mlsiem.soc.api import create_app
from mlsiem.soc.config import load_soc_config

REPO = Path(__file__).parents[2]
API = "/api/v1"
ANALYST = {"X-Analyst": "vlad"}


def _configs(tmp_path) -> tuple[Path, Path, Path]:
    detect = yaml.safe_load((REPO / "configs" / "detect.yaml").read_text(encoding="utf-8"))
    # Маленькие модели, чтобы тест шёл секунды; всё остальное — как в репозитории
    detect["candidates"]["logreg"]["max_iter"] = 300
    detect["candidates"]["lgbm"].update(
        {"n_estimators": 30, "num_leaves": 15, "learning_rate": 0.1}
    )
    detect["output"] = str(tmp_path / "models" / "detector")
    soc = yaml.safe_load((REPO / "configs" / "soc.yaml").read_text(encoding="utf-8"))
    soc["db"] = str(tmp_path / "var" / "soc.db")
    soc["runs_dir"] = str(tmp_path / "var" / "runs")
    detect_path, soc_path = tmp_path / "detect.yaml", tmp_path / "soc.yaml"
    detect_path.write_text(yaml.safe_dump(detect), encoding="utf-8")
    soc_path.write_text(yaml.safe_dump(soc), encoding="utf-8")
    return detect_path, soc_path, Path(detect["output"])


def _incident_view(client, run_id):
    items = client.get(f"{API}/incidents", params={"run_id": run_id, "limit": 500}).json()["items"]
    return sorted(
        (
            i["src_ip"],
            i["attack_class"],
            i["first_seen_ms"],
            i["n_alerts"],
            i["severity"],
            i["action"]["action_type"],
            i["action"]["target"],
        )
        for i in items
    )


def test_chain_synthetic(tmp_path, synthetic_split, capsys):
    detect_cfg, soc_cfg, detector = _configs(tmp_path)

    assert (
        cli.main(
            [
                "detect",
                "--data-dir",
                str(synthetic_split),
                "train",
                "--config",
                str(detect_cfg),
                "--reports-dir",
                str(tmp_path / "reports"),
                "--mlflow-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "Победитель" in out and "Перенос" in out

    run_args = [
        "soc",
        "--config",
        str(soc_cfg),
        "run",
        "--split",
        "unsw_time",
        "--part",
        "test",
        "--data-dir",
        str(synthetic_split),
        "--detector",
        str(detector),
    ]
    assert cli.main(run_args) == 0
    assert cli.main(run_args) == 0
    out = capsys.readouterr().out
    assert "инциденты по серьёзности" in out and "верных алертов" in out

    assert cli.main(["soc", "--config", str(soc_cfg), "status"]) == 0
    assert "Прогонов" in capsys.readouterr().out

    cfg = load_soc_config(soc_cfg)
    with TestClient(create_app(cfg, detector_dir=detector)) as client:
        runs = client.get(f"{API}/runs").json()["items"]
        assert len(runs) == 2
        new_run, old_run = runs[0]["run_id"], runs[1]["run_id"]
        # SC-002: тот же вход — те же инциденты, серьёзности и предложения
        assert _incident_view(client, new_run) == _incident_view(client, old_run)
        assert _incident_view(client, new_run)

        # Аналитик: открыл самый серьёзный инцидент, подтвердил действие, закрыл инцидент
        inc = client.get(f"{API}/incidents", params={"run_id": new_run, "limit": 1}).json()[
            "items"
        ][0]
        card = client.get(f"{API}/incidents/{inc['incident_id']}").json()
        alerts = client.get(f"{API}/incidents/{inc['incident_id']}/alerts").json()
        assert alerts["total"] == card["n_alerts"]

        action = card["action"]
        r = client.post(
            f"{API}/actions/{action['action_id']}/confirm",
            json={"expected_version": action["version"]},
            headers=ANALYST,
        )
        assert r.status_code == 200 and r.json()["simulation"]["simulated"] is True

        url = f"{API}/incidents/{inc['incident_id']}/status"
        r = client.post(url, json={"status": "in_progress", "expected_version": 1}, headers=ANALYST)
        assert r.status_code == 200
        r = client.post(
            url,
            json={"status": "closed", "resolution": "confirmed", "expected_version": 2},
            headers=ANALYST,
        )
        assert r.status_code == 200 and r.json()["status"] == "closed"

        audit = client.get(f"{API}/audit", params={"incident_id": inc["incident_id"]}).json()[
            "items"
        ]
        assert [e["event"] for e in audit] == [
            "action_proposed",
            "action_executed",
            "incident_status_changed",
            "incident_status_changed",
        ]
        assert client.get(f"{API}/health").json()["detector_version"]
