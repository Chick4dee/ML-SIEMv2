"""Русские подписи значений и форматы времени консоли (FR-028, research R13).

Главная проверка — «у каждого значения есть подпись»: если в store или config появится новый
статус, событие или действие, а перевод забудут, тест упадёт раньше, чем аналитик увидит код.
"""

import pytest

from mlsiem.soc import store
from mlsiem.soc.config import ACTION_TYPES, NETWORK_ROLES, SEVERITY_LEVELS
from mlsiem.ui import labels

CYRILLIC = set("абвгдеёжзийклмнопрстуфхцчшщъыьэюя")


@pytest.mark.parametrize(
    "kind, values",
    [
        ("status", store.INCIDENT_STATUSES),
        ("resolution", store.RESOLUTIONS),
        ("action_state", store.ACTION_STATES),
        ("event", store.AUDIT_EVENTS),
        ("severity", SEVERITY_LEVELS),
        ("action_type", ACTION_TYPES),
        ("role", NETWORK_ROLES),
        ("field", ("status", "resolution", "assignee")),
        ("clock", ("traffic", "decision")),
    ],
)
def test_every_value_has_russian_label(kind, values):
    for v in values:
        text = labels.label(v, kind)
        assert text != v, f"нет подписи для {kind}={v}"
        assert CYRILLIC & set(text.lower()), f"подпись {kind}={v} не по-русски: {text}"


def test_incident_assigned_label():
    assert "ответствен" in labels.label("incident_assigned", "event")


def test_unknown_value_shown_as_is():
    assert labels.label("что-то новое", "status") == "что-то новое"
    assert labels.label(None, "resolution") == "—"


def test_utc_ms():
    assert labels.utc_ms(1424242234000) == "2015-02-18 06:50:34 UTC"
    assert labels.utc_ms(None) == "—"


def test_utc_iso():
    assert labels.utc_iso("2026-09-24T11:04:57.123Z") == "2026-09-24 11:04:57 UTC"
    assert labels.utc_iso("2026-09-24T11:04:57+00:00") == "2026-09-24 11:04:57 UTC"
    assert labels.utc_iso(None) == "—"


def test_short_list():
    assert labels.short_list(["a", "b"]) == "a, b"
    assert labels.short_list(["a", "b", "c"]) == "a, b, c"
    assert labels.short_list(list("abcdefgh")) == "a, b, c и ещё 5"
    assert labels.short_list(list("abcd"), n=1) == "a и ещё 3"
    assert labels.short_list([]) == "—"


def test_register_adds_filters():
    from jinja2 import Environment

    env = Environment(autoescape=True)
    labels.register(env)
    assert {"label", "utc_ms", "utc_iso", "short_list"} <= set(env.filters)
    out = env.from_string("{{ 'closed' | label('status') }} {{ 0 | utc_ms }}").render()
    assert out == "закрыт 1970-01-01 00:00:00 UTC"
