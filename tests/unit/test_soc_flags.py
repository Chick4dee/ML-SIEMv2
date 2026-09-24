"""Метки подозрительного источника (US3, research R8): только подсказка, ничего не меняют."""

import copy
import ipaddress

from mlsiem.soc.config import NetworkConfig
from mlsiem.soc.flags import source_flags


def net(name, role, *cidrs):
    return NetworkConfig(name, role, tuple(ipaddress.ip_network(c) for c in cidrs))


VICTIMS = net("жертвы UNSW-NB15", "victims", "149.171.126.0/24")
BACKGROUND = net("фон UNSW-NB15", "background", "59.166.0.0/24")
INFRA = net("шлюзы", "infrastructure", "10.0.0.0/8")
OTHER = net("прочее", "other", "172.16.0.0/12")
NETWORKS = (VICTIMS, BACKGROUND, INFRA, OTHER)


def inc(incident_id, src, *targets, severity="high"):
    return {
        "incident_id": incident_id,
        "src_ip": src,
        "targets": list(targets),
        "severity": severity,
        "status": "new",
    }


def test_victim_network_flag():
    flags = source_flags([inc("a", "149.171.126.7", "175.45.176.1")], NETWORKS)
    [f] = flags["a"]
    assert f.kind == "network" and f.role == "victims"
    assert f.network_name == "жертвы UNSW-NB15"
    assert "жертвы UNSW-NB15" in f.explanation and "149.171.126.0/24" in f.explanation


def test_background_network_flag():
    [f] = source_flags([inc("a", "59.166.0.3", "1.2.3.4")], NETWORKS)["a"]
    assert f.role == "background"


def test_infrastructure_and_other_give_no_flag():
    flags = source_flags(
        [inc("a", "10.1.2.3", "8.8.8.8"), inc("b", "172.16.5.5", "8.8.8.8")], NETWORKS
    )
    assert flags.get("a", []) == [] and flags.get("b", []) == []


def test_address_in_two_networks():
    both = (VICTIMS, net("вторая", "background", "149.171.0.0/16"))
    flags = source_flags([inc("a", "149.171.126.7", "1.1.1.1")], both)
    assert sorted(f.network_name for f in flags["a"]) == ["вторая", "жертвы UNSW-NB15"]


def test_target_elsewhere():
    incidents = [
        inc("a", "175.45.176.1", "149.171.126.7"),
        inc("b", "175.45.176.2", "149.171.126.7", "149.171.126.8"),
        inc("c", "149.171.126.7", "175.45.176.1"),
        # свой собственный инцидент не считается: источник совпадает со своей целью
        inc("d", "1.1.1.1", "1.1.1.1"),
    ]
    flags = source_flags(incidents, ())
    [f] = flags["c"]
    assert f.kind == "target_elsewhere"
    assert f.related_incidents == ("a", "b")
    assert "a" in f.explanation and "b" in f.explanation
    # 175.45.176.1 — источник «a» и цель «c»: метка и у «a»
    assert [x.related_incidents for x in flags["a"]] == [("c",)]
    assert flags.get("b", []) == [] and flags.get("d", []) == []


def test_many_related_are_shortened():
    incidents = [inc(f"t{i:02d}", f"10.9.0.{i}", "8.8.8.8") for i in range(15)]
    incidents.append(inc("x", "8.8.8.8", "1.1.1.1"))
    [f] = source_flags(incidents, ())["x"]
    assert len(f.related_incidents) == 15
    assert "и ещё 5" in f.explanation
    assert "t14" not in f.explanation


def test_ipv6():
    v6 = net("v6-жертвы", "victims", "2001:db8::/32")
    incidents = [inc("a", "2001:db8::1", "2001:db9::5"), inc("b", "2001:db9:0:0::5", "::1")]
    flags = source_flags(incidents, (v6,))
    assert [f.kind for f in flags["a"]] == ["network"]
    # разная запись одного адреса IPv6 — всё равно тот же адрес
    assert [f.kind for f in flags["b"]] == ["target_elsewhere"]


def test_no_networks_only_targets():
    incidents = [inc("a", "149.171.126.7", "1.1.1.1"), inc("b", "1.1.1.1", "2.2.2.2")]
    flags = source_flags(incidents, ())
    assert flags.get("a", []) == []
    assert [f.kind for f in flags["b"]] == ["target_elsewhere"]


def test_pure_function_does_not_touch_incidents():
    incidents = [inc("a", "149.171.126.7", "59.166.0.1"), inc("b", "59.166.0.1", "149.171.126.7")]
    before = copy.deepcopy(incidents)
    flags = source_flags(incidents, NETWORKS)
    assert incidents == before
    assert set(flags) == {"a", "b"}
    assert all(i["severity"] == "high" and i["status"] == "new" for i in incidents)


def test_flag_as_dict_for_api():
    [f] = source_flags([inc("a", "149.171.126.7", "1.1.1.1")], NETWORKS)["a"]
    d = f.as_dict()
    assert set(d) == {"kind", "network_name", "role", "related_incidents", "explanation"}
    assert d["related_incidents"] == []
