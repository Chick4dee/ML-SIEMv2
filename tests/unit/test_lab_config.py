"""Раздел `lab`/`normal`/`scenarios` конфига потока (фича 006, data-model «Машины стенда»).

Как тесты конфигов 001–005: ошибка называет полный ключ; конфиг без раздела `lab` работает как
до 006 (команды стенда 005 не ломаются).
"""

import copy
from pathlib import Path

import pytest
import yaml

from mlsiem.data.config import ConfigError
from mlsiem.stream.config import load_stream_config, parse_stream_config

REPO = Path(__file__).parents[2]


def _raw() -> dict:
    return copy.deepcopy(
        yaml.safe_load((REPO / "configs" / "stream.yaml").read_text(encoding="utf-8"))
    )


def test_repo_config_has_lab():
    cfg = load_stream_config(REPO / "configs" / "stream.yaml")
    lab = cfg.lab
    assert lab is not None
    assert str(lab.subnet) == "10.88.0.0/24"
    assert lab.victim.ip == "10.88.0.20" and lab.attacker.ip == "10.88.0.30"
    assert lab.in_lab("10.88.0.20") and not lab.in_lab("10.77.0.10") and not lab.in_lab("мусор")
    # Дефолты из data-model: буфер, предел записи, допустимое расхождение часов
    assert lab.sensor.buffer_flows == 3000
    assert lab.sensor.pcap_limit_gb == 5
    assert lab.clock_skew_max_s == 1
    assert {"victim", "attacker", "sensor"} <= set(lab.lab_mac)
    assert lab.lab_mac["victim"] == "00:15:5d:4d:00:20"  # строчные через двоеточие
    names = [s.name for s in cfg.scenarios]
    assert "control_replay" in names and "port_scan" in names
    ctl = cfg.scenario("control_replay")
    assert ctl.pcap and ctl.src_map and ctl.dst_map
    assert cfg.normal is not None and set(cfg.normal.mix) <= set(lab.victim.services)


def test_config_without_lab_is_fine():
    raw = _raw()
    for key in ("lab", "normal", "scenarios"):
        raw.pop(key)
    cfg = parse_stream_config(raw)
    assert cfg.lab is None and cfg.normal is None and cfg.scenarios == ()


@pytest.mark.parametrize(
    ("edit", "key"),
    [
        (lambda r: r["lab"].pop("subnet"), "lab.subnet"),
        (lambda r: r["lab"].update(subnet="не сеть"), "lab.subnet"),
        (
            lambda r: (
                r["lab"].update(subnet="10.77.0.0/24"),
                r["lab"]["victim"].update(ip="10.77.0.20"),
                r["lab"]["attacker"].update(ip="10.77.0.30"),
            ),
            "пересекается",
        ),
        (lambda r: r["lab"]["victim"].update(ip="192.168.1.5"), "lab.victim.ip"),
        (lambda r: r["lab"]["attacker"].update(ip="10.88.0.20"), "совпадают"),
        (lambda r: r["lab"]["victim"].update(services=["web", "gopher"]), "lab.victim.services"),
        (lambda r: r["lab"]["attacker"].update(mgmt="ssh"), "lab.attacker.mgmt"),
        (lambda r: r["lab"]["sensor"].update(placement="cloud"), "lab.sensor.placement"),
        (lambda r: r["lab"]["sensor"].update(buffer_flows=0), "lab.sensor.buffer_flows"),
        (lambda r: r["lab"]["sensor"].update(pcap_limit_gb=-1), "lab.sensor.pcap_limit_gb"),
        (lambda r: r["lab"].update(clock_skew_max_s=0), "lab.clock_skew_max_s"),
        (lambda r: r["lab"]["lab_mac"].update(sensor="zz"), "lab.lab_mac.sensor"),
        (lambda r: r["lab"]["lab_mac"].pop("attacker"), "lab.lab_mac.attacker"),
        (lambda r: r["lab"]["lab_mac"].update(sensor="00:15:5D:4D:00:20"), "различаться"),
    ],
)
def test_lab_errors_name_the_key(edit, key):
    raw = _raw()
    edit(raw)
    with pytest.raises(ConfigError, match=key):
        parse_stream_config(raw)


@pytest.mark.parametrize(
    ("edit", "key"),
    [
        (lambda r: r["scenarios"][1].update(target="gopher"), r"scenarios\[1\].target"),
        (lambda r: r["scenarios"][1].update(expected_class="ufo"), "expected_class"),
        (lambda r: r["scenarios"][1].update(catch_threshold=0), "catch_threshold"),
        (lambda r: r["scenarios"][1].pop("tool"), r"scenarios\[1\].tool"),
        (lambda r: r["scenarios"][0].pop("pcap"), r"scenarios\[0\].pcap"),
        (lambda r: r["scenarios"].append(dict(r["scenarios"][1])), "записан дважды"),
        (lambda r: r["normal"]["mix"].update(gopher=1), "normal.mix.gopher"),
        (lambda r: r["normal"].update(mix={"web": 0}), "нужна хотя бы одна"),
    ],
)
def test_scenario_and_normal_errors(edit, key):
    raw = _raw()
    edit(raw)
    with pytest.raises(ConfigError, match=key):
        parse_stream_config(raw)


def test_unknown_scenario_lists_known():
    cfg = load_stream_config(REPO / "configs" / "stream.yaml")
    with pytest.raises(ConfigError, match="control_replay@1"):
        cfg.scenario("нет_такого")
