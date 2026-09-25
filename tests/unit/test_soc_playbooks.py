"""Плейбуки: каждое правило R11, защищённый список, первое совпадение, детерминизм."""

import json
from pathlib import Path

import pytest

from mlsiem.soc.config import Rule, load_soc_config
from mlsiem.soc.playbooks import propose_action, simulate

REPO = Path(__file__).parents[2]
RULES = load_soc_config(REPO / "configs" / "soc.yaml").rules


def inc(cls, targets, severity="high", src="175.45.176.1", iid="inc-000000000001"):
    return {
        "incident_id": iid,
        "src_ip": src,
        "attack_class": cls,
        "targets": json.dumps(targets),
        "severity": severity,
    }


@pytest.mark.parametrize(
    "incident, action, target, rule",
    [
        (inc("exploits", ["10.0.0.5"]), "isolate_host", "10.0.0.5", "intrusion_single_target"),
        (
            inc("worms", ["10.0.0.5", "10.0.0.6"]),
            "block_source_ip",
            "175.45.176.1",
            "intrusion_many_targets",
        ),
        (inc("dos", ["10.0.0.5"], "medium"), "block_source_ip", "175.45.176.1", "noisy_attack"),
        (inc("generic", ["10.0.0.5"], "medium"), "block_source_ip", "175.45.176.1", "noisy_attack"),
        (inc("fuzzers", ["10.0.0.5"], "high"), "block_source_ip", "175.45.176.1", "noisy_attack"),
        (inc("reconnaissance", ["10.0.0.5"], "low"), "observe", None, "default"),
        (inc("reconnaissance", ["10.0.0.5"], "medium"), "block_source_ip", "175.45.176.1", "recon"),
        (inc("analysis", ["10.0.0.5"], "critical"), "block_source_ip", "175.45.176.1", "recon"),
    ],
)
def test_rules(incident, action, target, rule):
    a = propose_action(incident, RULES, ())
    assert (a["action_type"], a["target"], a["rule_id"]) == (action, target, rule)
    assert a["action_id"] == f"act-{incident['incident_id']}"
    assert rule in a["rule_text"] and "→" in a["rule_text"]


def test_protected_source():
    a = propose_action(inc("exploits", ["10.0.0.5"]), RULES, ("175.45.176.1",))
    assert (a["action_type"], a["target"], a["rule_id"]) == ("manual_review", None, "protected")


def test_protected_single_target():
    a = propose_action(inc("exploits", ["10.0.0.5"]), RULES, ("10.0.0.5",))
    assert (a["action_type"], a["rule_id"]) == ("manual_review", "protected")


def test_protected_guard_without_rule():
    # Даже если правило protected убрали из конфига — защищённый адрес не блокируется
    rules = tuple(r for r in RULES if r.id != "protected")
    a = propose_action(inc("dos", ["10.0.0.5", "10.0.0.6"]), rules, ("175.45.176.1",))
    assert a["action_type"] == "manual_review"
    assert a["target"] is None


def test_first_match_wins():
    # exploits с одной целью подходит и под intrusion_single_target, и под intrusion_many_targets
    a = propose_action(inc("exploits", ["10.0.0.5"]), RULES, ())
    assert a["rule_id"] == "intrusion_single_target"
    # Меняем местами два правила вторжений по id (индексы сдвигаются, когда в конфиг
    # добавляют правила — например, unknown_class в фиче 004)
    ids = [r.id for r in RULES]
    i, j = ids.index("intrusion_single_target"), ids.index("intrusion_many_targets")
    reordered = list(RULES)
    reordered[i], reordered[j] = reordered[j], reordered[i]
    assert (
        propose_action(inc("exploits", ["10.0.0.5"]), reordered, ())["rule_id"]
        == "intrusion_many_targets"
    )


def test_deterministic():
    i = inc("dos", ["10.0.0.5"])
    assert propose_action(i, RULES, ()) == propose_action(dict(i), RULES, ())


def test_simulation_is_description_only():
    a = propose_action(inc("exploits", ["10.0.0.5"]), RULES, ())
    sim = simulate(a)
    assert sim["simulated"] is True
    assert sim["action_type"] == "isolate_host" and sim["target"] == "10.0.0.5"
    assert "симуляция" in sim["description"]
    obs = simulate(propose_action(inc("reconnaissance", ["10.0.0.5"], "low"), RULES, ()))
    assert "наблюдение продолжено" in obs["description"]
    mr = simulate(propose_action(inc("dos", ["1.1.1.1"]), RULES, ("175.45.176.1",)))
    assert "ручной разбор" in mr["description"]


# ---------------------------------------------------------------- фича 004: класс anomaly


@pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
@pytest.mark.parametrize("targets", [["10.0.0.5"], ["10.0.0.5", "10.0.0.6", "10.0.0.7"]])
def test_anomaly_always_manual_review(severity, targets):
    a = propose_action(inc("anomaly", targets, severity), RULES, ())
    assert (a["action_type"], a["target"], a["rule_id"]) == ("manual_review", None, "unknown_class")
    assert "класс атаки неизвестен" in a["rule_text"]


def test_anomaly_guard_without_rule():
    # Правило unknown_class убрали — страховка в коде всё равно не даст блокировать
    rules = [r for r in RULES if r.id != "unknown_class"]
    a = propose_action(inc("anomaly", ["10.0.0.5"]), rules, ())
    # без правила аномалия падает в default (наблюдать) — сетевого действия нет
    assert a["action_type"] == "observe"
    blocking = [Rule("block_all", {}, "block_source_ip")]
    a = propose_action(inc("anomaly", ["10.0.0.5"]), blocking, ())
    assert (a["action_type"], a["target"], a["rule_id"]) == ("manual_review", None, "anomaly_guard")
    assert "класс атаки неизвестен" in a["rule_text"]


def test_anomaly_guard_when_rule_below_noisy():
    # Правило стоит ниже блокирующего — страховка всё равно срабатывает
    isolate = Rule("isolate_everything", {}, "isolate_host")
    rules = [r for r in RULES if r.id != "unknown_class"]
    rules.insert(1, isolate)
    a = propose_action(inc("anomaly", ["10.0.0.5"]), rules, ())
    assert (a["action_type"], a["rule_id"]) == ("manual_review", "anomaly_guard")


def test_other_classes_unchanged_by_guard():
    a = propose_action(inc("dos", ["10.0.0.5"], "medium"), RULES, ())
    assert (a["action_type"], a["rule_id"]) == ("block_source_ip", "noisy_attack")
