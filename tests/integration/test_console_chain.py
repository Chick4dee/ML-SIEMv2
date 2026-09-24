"""Сквозной путь консоли (фича 003): синтетика → детектор → прогон → консоль в браузере.

Аналитик ходит только по страницам консоли (без /api/v1): панель → счётчик → список →
карточка → «взять себе» → «в работу» → подтверждение действия после вопроса → закрытие →
журнал показывает все его решения. Второй прогон — баннер на открытой панели.
"""

from fastapi.testclient import TestClient

from mlsiem.soc.api import create_app
from mlsiem.soc.config import load_soc_config, parse_soc_config
from mlsiem.soc.run import run_chain
from ui.conftest import BASE, REPO, htmx, incident_ids, post_form, soup


def test_console_chain(tmp_path, synthetic_split, tiny_detector):
    raw = load_soc_config(REPO / "configs" / "soc.yaml").raw
    cfg = parse_soc_config({**raw, "db": str(tmp_path / "soc.db"), "runs_dir": str(tmp_path / "r")})
    first = run_chain(
        "split:unsw_time/test", cfg, detector_dir=tiny_detector, data_dir=synthetic_split
    )
    app = create_app(cfg, detector_dir=tiny_detector)
    requests: list[str] = []

    with TestClient(app, base_url=BASE) as c:
        c.event_hooks["request"].append(lambda req: requests.append(req.url.path))

        # панель → счётчик «ждут решения» → список
        dash = soup(c.get("/"))
        pending = dash.select_one("a[data-counter=actions_pending]")
        assert int(pending["data-count"]) == first.n_incidents
        listing = c.get(pending["href"])
        ids = incident_ids(listing)
        assert len(ids) == first.n_incidents

        # представиться и открыть самый серьёзный инцидент
        r = post_form(c, "/analyst", {"name": "Влад", "next": "/incidents"}, htmx_request=False)
        assert r.status_code == 303
        card = soup(c.get(f"/incidents/{ids[0]}"))
        take = card.select_one("#panel-assign input[name=take]").find_parent("form")
        r = post_form(c, take["action"], {"take": "1", "expected_version": "1"})
        assert r.status_code == 200 and "Влад" in soup(r).select_one(".assignee").get_text()

        r = post_form(
            c, f"/incidents/{ids[0]}/status", {"status": "in_progress", "expected_version": "2"}
        )
        assert "в работе" in soup(r).select_one(".state-line").get_text()

        confirm = soup(r).select_one("#panel-action form")
        action_url = confirm["action"]
        r = post_form(c, action_url, {"expected_version": "1", "comment": "блокируем"})
        dialog = soup(r).select_one("dialog[data-modal]")
        assert "Подтвердить" in dialog.get_text()
        again = {i["name"]: i["value"] for i in dialog.select("input[type=hidden]")}
        r = post_form(c, action_url, {k: v for k, v in again.items() if k != "csrf_token"})
        assert "Реальных изменений в сети и на хостах не было" in r.text

        r = post_form(
            c,
            f"/incidents/{ids[0]}/status",
            {
                "status": "closed",
                "resolution": "confirmed",
                "comment": "готово",
                "expected_version": "3",
            },
        )
        assert "закрыт" in soup(r).select_one(".state-line").get_text()
        assert r.headers["HX-Trigger"] == "incident-changed"

        # журнал: все решения Влада, новые сверху
        audit = soup(c.get("/audit?actor=Влад"))
        events = [tr["data-event"] for tr in audit.select("tr[data-entry]")]
        assert events == [
            "incident_status_changed",
            "action_executed",
            "incident_status_changed",
            "incident_assigned",
        ]

        # второй прогон — баннер на открытой панели первого
        second = run_chain(
            "split:unsw_time/test",
            cfg,
            detector_dir=tiny_detector,
            data_dir=synthetic_split,
            limit=300,
        )
        banner = c.get(f"/fragments/runs-banner?run={first.run_id}", headers=htmx())
        assert second.run_id in soup(banner).select_one(".banner").get_text()

    assert not [p for p in requests if p.startswith("/api/")]
