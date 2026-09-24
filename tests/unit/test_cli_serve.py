"""`mlsiem soc serve` (фича 003): миграция базы при старте, адреса консоли и API, «база новее»."""

from pathlib import Path

import yaml

from mlsiem import cli
from mlsiem.soc import store

REPO = Path(__file__).parents[2]
FIXTURES = REPO / "tests" / "fixtures"


def _config(tmp_path) -> Path:
    raw = yaml.safe_load((REPO / "configs" / "soc.yaml").read_text(encoding="utf-8"))
    raw.update(db=str(tmp_path / "soc.db"), runs_dir=str(tmp_path / "runs"))
    path = tmp_path / "soc.yaml"
    path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    return path


def _serve(tmp_path, monkeypatch):
    started = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: started.update(kw))
    code = cli.main(["soc", "--config", str(_config(tmp_path)), "serve", "--detector", "none"])
    return code, started


def test_serve_migrates_002_database(tmp_path, monkeypatch, capfd):
    conn = store.connect(tmp_path / "soc.db")
    conn.executescript((FIXTURES / "soc_schema_002.sql").read_text(encoding="utf-8"))
    conn.close()
    code, started = _serve(tmp_path, monkeypatch)
    assert code == 0 and started["host"] == "127.0.0.1"
    text = capfd.readouterr().err
    assert "обновлена до версии 2" in text
    assert "http://127.0.0.1:8000/" in text and "http://127.0.0.1:8000/api/v1" in text


def test_serve_new_database_no_migration_message(tmp_path, monkeypatch, capfd):
    code, _ = _serve(tmp_path, monkeypatch)
    assert code == 0 and "обновлена" not in capfd.readouterr().err


def test_serve_refuses_newer_database(tmp_path, monkeypatch, capfd):
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    conn.execute("PRAGMA user_version = 3")
    conn.close()
    code, started = _serve(tmp_path, monkeypatch)
    assert code == 1 and started == {}
    assert "новее" in capfd.readouterr().err
