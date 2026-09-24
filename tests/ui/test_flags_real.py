"""Метки на реальном прогоне 002 (SC-003) — медленный тест, нужен var/soc.db.

Проверяем на копии базы (миграция схемы не должна трогать рабочий файл): все инциденты
с источниками из сетей жертв и фона UNSW-NB15 помечены, и не помечен ни один инцидент,
у которого источник вне этих сетей и не встречается среди целей прогона.

Спека (SC-003) и журнал 002 называют «17 из 66», но пересчёт по данным прогона даёт 14:
8 инцидентов с 149.171.126.x и 6 с 59.166.0.x. Тест сверяется с данными, а не с числом
из журнала, и печатает фактические числа для журнала 003.
"""

import ipaddress
import shutil
from pathlib import Path

import pytest

from mlsiem.soc import flags, store
from mlsiem.soc.config import load_soc_config

REPO = Path(__file__).parents[2]
REAL_DB = REPO / "var" / "soc.db"
NETS = [ipaddress.ip_network("149.171.126.0/24"), ipaddress.ip_network("59.166.0.0/24")]

pytestmark = pytest.mark.slow


@pytest.fixture
def real_conn(tmp_path):
    if not REAL_DB.exists():
        pytest.skip("нет var/soc.db с прогоном 002")
    shutil.copy(REAL_DB, tmp_path / "soc.db")
    conn = store.connect(tmp_path / "soc.db")
    store.init_db(conn)
    yield conn
    conn.close()


def test_real_run_flags(real_conn):
    cfg = load_soc_config(REPO / "configs" / "soc.yaml")
    runs = [r for r in store.list_runs(real_conn) if r["source"].startswith("split:unsw_time/")]
    if not runs:
        pytest.skip("в var/soc.db нет прогона split:unsw_time/test")
    run = max(runs, key=lambda r: r["n_incidents"])
    incidents = store.run_sources(real_conn, run["run_id"])
    result = flags.run_flags(real_conn, run["run_id"], cfg.networks)

    in_nets = {
        i["incident_id"]
        for i in incidents
        if any(ipaddress.ip_address(i["src_ip"]) in n for n in NETS)
    }
    net_flagged = {k for k, v in result.items() if any(f.kind == "network" for f in v)}
    te_flagged = {k for k, v in result.items() if any(f.kind == "target_elsewhere" for f in v)}
    all_targets = {t for i in incidents for t in i["targets"]}

    assert net_flagged == in_nets  # 100% источников из сетей помечены, и только они
    for i in incidents:
        if i["incident_id"] not in in_nets and i["src_ip"] not in all_targets:
            assert i["incident_id"] not in result, i

    print(
        f"\nпрогон {run['run_id']}: инцидентов {len(incidents)}, "
        f"метка сети {len(net_flagged)}, target_elsewhere {len(te_flagged)}, "
        f"помечено всего {len(result)}"
    )
    assert len(incidents) == 66 and len(net_flagged) == 14
