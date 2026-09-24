"""Метки «подозрительный источник» (US3, research R8, data-model SourceFlag).

Откуда взялась задача. В прогоне 002 17 из 66 инцидентов пришли «от» адресов жертв
(149.171.126.x) и фонового трафика (59.166.0.x) UNSW-NB15. Это не атакующие: группировка
по источнику поймала ответное направление соединения. Чинить группировку — задача детекции;
консоль же должна сделать проблему видимой, чтобы аналитик не тратил на каждый такой
инцидент по десять минут.

Две метки:
- `network` — источник входит в именованную сеть с ролью «жертвы» или «фон» (configs/soc.yaml);
- `target_elsewhere` — адрес источника сам встречается среди целей других инцидентов того же
  прогона (признак ответного направления).

Метка — только подсказка (FR-020): функция чистая, ничего не пишет и не меняет ни
серьёзность, ни статус, ни действие. Хранить метки в базе не нужно — поменяли сети в конфиге,
и после перезапуска консоли всё пересчитано.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from collections import defaultdict
from dataclasses import asdict, dataclass

from mlsiem.soc import store
from mlsiem.soc.config import NetworkConfig

# Какие роли сетей делают источник подозрительным. infrastructure/other — только подписи
FLAG_ROLES = ("victims", "background")
# Сколько связанных инцидентов перечислять в объяснении — остальное «и ещё N»
MAX_LINKS = 10


@dataclass(frozen=True)
class SourceFlag:
    kind: str  # network | target_elsewhere
    network_name: str | None
    role: str | None
    related_incidents: tuple[str, ...]
    explanation: str

    def as_dict(self) -> dict:
        d = asdict(self)
        d["related_incidents"] = list(self.related_incidents)
        return d


def _norm(ip: str) -> str:
    """Одна запись адреса: `2001:db9:0:0::5` и `2001:db9::5` — один и тот же адрес."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def _network_flags(src: str, networks: tuple[NetworkConfig, ...]) -> list[SourceFlag]:
    try:
        addr = ipaddress.ip_address(src)
    except ValueError:
        return []
    out = []
    for n in networks:
        if n.role not in FLAG_ROLES:
            continue
        cidr = next((c for c in n.cidrs if addr in c), None)
        if cidr is not None:
            out.append(
                SourceFlag(
                    kind="network",
                    network_name=n.name,
                    role=n.role,
                    related_incidents=(),
                    explanation=f"источник входит в сеть «{n.name}» ({cidr})",
                )
            )
    return out


def _targets_flag(related: list[str]) -> SourceFlag:
    shown = ", ".join(related[:MAX_LINKS])
    rest = len(related) - MAX_LINKS
    tail = f" и ещё {rest}" if rest > 0 else ""
    return SourceFlag(
        kind="target_elsewhere",
        network_name=None,
        role=None,
        related_incidents=tuple(related),
        explanation=(
            f"адрес источника — цель в других инцидентах прогона ({len(related)}): {shown}{tail}"
        ),
    )


def source_flags(
    incidents: list[dict], networks: tuple[NetworkConfig, ...]
) -> dict[str, list[SourceFlag]]:
    """Метки для инцидентов ОДНОГО прогона: `{incident_id: [SourceFlag, …]}`.

    В словаре только помеченные инциденты. На вход нужны `incident_id`, `src_ip`, `targets`.
    """
    # адрес → инциденты, где он цель (в порядке входа — он же порядок ссылок в объяснении)
    as_target: dict[str, list[str]] = defaultdict(list)
    for i in incidents:
        for t in dict.fromkeys(_norm(t) for t in i["targets"]):
            as_target[t].append(i["incident_id"])
    out: dict[str, list[SourceFlag]] = {}
    for i in incidents:
        flags = _network_flags(i["src_ip"], networks)
        related = [j for j in as_target.get(_norm(i["src_ip"]), []) if j != i["incident_id"]]
        if related:
            flags.append(_targets_flag(related))
        if flags:
            out[i["incident_id"]] = flags
    return out


# Кэш по прогону: источники и цели инцидентов после записи прогона не меняются, поэтому
# ключа (прогон, число инцидентов, сети) достаточно. Прогонов — единицы, кэш крошечный
_CACHE: dict[tuple, dict[str, list[SourceFlag]]] = {}
_CACHE_MAX = 16


def run_flags(
    conn: sqlite3.Connection, run_id: str, networks: tuple[NetworkConfig, ...]
) -> dict[str, list[SourceFlag]]:
    """Метки всех инцидентов прогона из базы (с кэшем в памяти процесса)."""
    count = conn.execute("SELECT COUNT(*) FROM incidents WHERE run_id = ?", (run_id,)).fetchone()[0]
    key = (run_id, count, networks)
    if key not in _CACHE:
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.clear()
        _CACHE[key] = source_flags(store.run_sources(conn, run_id), networks)
    return _CACHE[key]
