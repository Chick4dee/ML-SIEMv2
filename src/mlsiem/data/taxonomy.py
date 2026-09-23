"""Единый словарь классов.

У каждого датасета своя номенклатура: CTU-13 — botnet/normal/background, UNSW-NB15 —
9 категорий атак с «грязными» подписями (регистр, пробелы, Backdoor/Backdoors). Всё сводится
к одному набору канонических классов, и таблица соответствий проверяется тестом.

Незнакомая подпись — ошибка, а не молчаливое «прочее»: новая категория в данных — повод
посмотреть на неё глазами, а не спрятать.
"""

from __future__ import annotations

# Поднимается при изменении таблиц ниже или правил сопоставления в labeling.py
# (допуск, тай-брейки): от этой версии зависит, пересчитывать ли готовые захваты
LABELING_VERSION = "1.0.0"

CANONICAL = frozenset(
    {
        "benign",
        # непроверенный реальный фон CTU-13 — не гарантированно чистый, поэтому не benign
        "background",
        "botnet",
        "dos",
        "exploits",
        "fuzzers",
        "generic",
        "reconnaissance",
        "backdoor",
        "analysis",
        "shellcode",
        "worms",
        # поток CTU-13, для которого в .binetflow не нашлось записи
        "unlabeled",
    }
)

UNSW_MAP = {
    "dos": "dos",
    "exploits": "exploits",
    "fuzzers": "fuzzers",
    "generic": "generic",
    "reconnaissance": "reconnaissance",
    "analysis": "analysis",
    "shellcode": "shellcode",
    "worms": "worms",
    "backdoor": "backdoor",
    "backdoors": "backdoor",
}

CTU13_MAP = {
    "normal": "benign",
    "background": "background",
    "botnet": "botnet",
}

_SOURCE_MAPS = {"unsw": UNSW_MAP, "ctu13": CTU13_MAP}


class UnknownLabelError(ValueError):
    """Подпись класса, которой нет в таблице соответствий."""


def normalize(raw: str) -> str:
    return raw.strip().lower()


def to_canonical(source: str, raw: str) -> str:
    try:
        mapping = _SOURCE_MAPS[source]
    except KeyError as exc:
        raise ValueError(f"неизвестный источник разметки: {source!r}") from exc
    key = normalize(raw)
    if key not in mapping:
        raise UnknownLabelError(
            f"подпись класса {raw!r} (источник {source}) не описана в таксономии — "
            "добавьте её в mlsiem/data/taxonomy.py и поднимите LABELING_VERSION"
        )
    return mapping[key]
