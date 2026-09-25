"""Плейбуки: правила → ровно одно предложенное действие на инцидент; симуляция (research R11).

Правила — упорядоченный список из configs/soc.yaml; срабатывает первое подходящее. Так
одинаковый инцидент всегда получает одинаковое предложение (FR-017), а логика читается
глазами прямо в конфиге.

БЕЗОПАСНОСТЬ (FR-019, SC-005). Этот модуль ничего не выполняет. Нет импортов subprocess,
socket, os.system, вызовов файрвола или сетевых библиотек — и тест это проверяет по AST.
«Выполнение» действия — это только запись в БД описания «что было бы сделано».

Защищённые адреса (FR-020) проверяются дважды: правилом `protected` из конфига и ещё раз
здесь, после выбора правила. Если кто-то уберёт правило из конфига или поставит его не
первым, блокировка или изоляция защищённого адреса всё равно не будет предложена.

Так же дважды защищён класс «аномалия» (фича 004, FR-017, research R12): сработал только
детектор аномалий, и что это за атака, неизвестно. Правило `unknown_class` в конфиге и
страховка `anomaly_guard` здесь: блокировать или изолировать по такому инциденту
автоматически нельзя — только ручной разбор.
"""

from __future__ import annotations

import json
from typing import Any

from mlsiem.detect.metrics import ANOMALY_CLASS
from mlsiem.soc.config import SEVERITY_LEVELS, Rule

ACTION_TITLES = {
    "block_source_ip": "заблокировать IP-источник",
    "isolate_host": "изолировать хост-цель",
    "observe": "наблюдать",
    "manual_review": "требуется ручной разбор",
}
GUARD_RULE_ID = "protected_guard"
ANOMALY_GUARD_RULE_ID = "anomaly_guard"
# Действия, которые меняют сеть (в симуляции) — их страховки и не пропускают
NETWORK_ACTIONS = ("block_source_ip", "isolate_host")


def _targets(incident: dict) -> list[str]:
    t = incident["targets"]
    return json.loads(t) if isinstance(t, str) else list(t)


def is_protected(incident: dict, protected_ips: tuple[str, ...] | list[str]) -> bool:
    """Источник или единственная цель инцидента — в защищённом списке."""
    protected = set(protected_ips)
    targets = _targets(incident)
    return incident["src_ip"] in protected or (len(targets) == 1 and targets[0] in protected)


def _matches(rule: Rule, incident: dict, protected: bool) -> bool:
    when = rule.when
    if "protected" in when and when["protected"] != protected:
        return False
    if "class_in" in when and incident["attack_class"] not in when["class_in"]:
        return False
    if "max_targets" in when and len(_targets(incident)) > when["max_targets"]:
        return False
    rank = SEVERITY_LEVELS.index
    return not ("min_severity" in when and rank(incident["severity"]) < rank(when["min_severity"]))


def describe_rule(rule: Rule) -> str:
    """Правило человеческим языком: «условия → действие»."""
    parts = []
    w = rule.when
    if "protected" in w:
        parts.append(
            "источник или единственная цель в защищённом списке"
            if w["protected"]
            else "адреса не в защищённом списке"
        )
    if "class_in" in w and list(w["class_in"]) == [ANOMALY_CLASS]:
        # Правило unknown_class (фича 004): аналитику важнее смысл, чем код класса
        parts.append("класс атаки неизвестен (anomaly — сработал только детектор аномалий)")
    elif "class_in" in w:
        parts.append("класс ∈ {" + ", ".join(w["class_in"]) + "}")
    if "max_targets" in w:
        parts.append(f"уникальных целей ≤ {w['max_targets']}")
    if "min_severity" in w:
        parts.append(f"серьёзность ≥ {w['min_severity']}")
    cond = " и ".join(parts) if parts else "во всех остальных случаях"
    return f"правило {rule.id}: {cond} → {ACTION_TITLES[rule.action]}"


def propose_action(
    incident: dict, rules: tuple[Rule, ...] | list[Rule], protected_ips: tuple[str, ...] | list[str]
) -> dict[str, Any]:
    """Предложение ровно одного действия для инцидента (поля — как в таблице actions)."""
    protected = is_protected(incident, protected_ips)
    rule = next((r for r in rules if _matches(r, incident, protected)), None)
    if rule is None:
        # Конфиг без «правила по умолчанию» — не повод молчать: пусть решит человек
        action_type, rule_id, rule_text = (
            "manual_review",
            "no_rule",
            "ни одно правило плейбука не подошло → требуется ручной разбор",
        )
    else:
        action_type, rule_id, rule_text = rule.action, rule.id, describe_rule(rule)

    targets = _targets(incident)
    target = None
    if action_type == "block_source_ip":
        target = incident["src_ip"]
    elif action_type == "isolate_host":
        # Изолировать можно только конкретный хост: при нескольких целях — ручной разбор
        target = targets[0] if len(targets) == 1 else None
        if target is None:
            action_type, rule_id = "manual_review", GUARD_RULE_ID
            rule_text += "; целей несколько, изолировать один хост нельзя → требуется ручной разбор"

    if incident["attack_class"] == ANOMALY_CLASS and action_type in NETWORK_ACTIONS:
        action_type, target, rule_id = "manual_review", None, ANOMALY_GUARD_RULE_ID
        rule_text += (
            "; класс атаки неизвестен (сработал только детектор аномалий) → "
            "требуется ручной разбор (FR-017)"
        )

    if target is not None and target in set(protected_ips):
        action_type, target, rule_id = "manual_review", None, GUARD_RULE_ID
        rule_text += "; объект действия в защищённом списке → требуется ручной разбор (FR-020)"

    return {
        "action_id": f"act-{incident['incident_id']}",
        "incident_id": incident["incident_id"],
        "action_type": action_type,
        "target": target,
        "rule_id": rule_id,
        "rule_text": rule_text,
    }


def simulate(action: dict) -> dict[str, Any]:
    """Описание того, что БЫЛО БЫ сделано. Ничего не выполняет — только текст для журнала."""
    kind, target = action["action_type"], action.get("target")
    texts = {
        "block_source_ip": f"было бы заблокировано входящее и исходящее соединение с IP {target}",
        "isolate_host": f"хост {target} был бы изолирован от сети",
        "observe": "наблюдение продолжено, сетевых действий нет",
        "manual_review": "передано на ручной разбор аналитику, сетевых действий нет",
    }
    return {
        "action_type": kind,
        "target": target,
        "rule_id": action.get("rule_id"),
        "description": texts[kind] + " (симуляция: реальных изменений сети не было)",
        "simulated": True,
    }
