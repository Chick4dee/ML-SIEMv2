"""План сбора набора стенда (фича 008, research R5, R6, R8, FR-005…FR-008, FR-021).

План строится по сиду и конфигу: раунд r — повтор r всех вариантов сценариев в случайном порядке.
Поэтому порядок по времени совпадает с порядком повторов, а разбиение «ранние повторы — обучение,
средние — валидация, поздние — тест» одновременно является разбиением по времени (конституция III).

Правила:
- значения параметров из `holdout` встречаются только в тестовых повторах (FR-005);
- варианты и сценарии с `reserve_unknown` выполняются только в тестовых раундах, несколько раз за
  раунд (FR-021), чтобы набрать поток для оценки «неизвестного»;
- источники атак чередуются между вариантами и повторами: каждый вариант использует не менее двух
  адресов (FR-002), а адрес не определяет класс;
- доля запусков с нормой во время атаки задаётся `collection.normal_share` (FR-007); в паузах норма
  идёт всегда;
- паузы между запусками не меньше `pause_s` (idle-таймаут экстрактора плюс запас, R6).

План — чистая функция конфига и сида: тест проверяет детерминизм. Модуль — часть хоста (не
копируется
на машины стенда), поэтому может использовать всё, что нужно.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from pathlib import Path

from mlsiem.data.schema import SCHEMA
from mlsiem.lab.variants import expand_variants, source_ips

PLAN_VERSION = 1


class PlanError(ValueError):
    """Ошибка плана или раздела collection конфига; текст — по-русски."""


@dataclass(frozen=True)
class Collection:
    seed: int
    repeats: int
    versions: tuple[str, ...]
    pause_s: float
    normal_share: float
    reserve_runs_per_round: int
    parts: dict[str, tuple[int, ...]]


def parse_collection(raw: dict, idle_timeout_s: float | None = None) -> Collection:
    """Раздел `collection`; проверки: повторы покрыты частями, паузы не меньше idle + 30 с (R6)."""
    c = raw.get("collection")
    if not isinstance(c, dict):
        raise PlanError("в конфиге нет раздела collection (фича 008)")
    try:
        parts = {k: tuple(int(x) for x in v) for k, v in c["parts"].items()}
        repeats = int(c["repeats"])
        coll = Collection(
            seed=int(c["seed"]),
            repeats=repeats,
            versions=tuple(str(v) for v in c.get("versions", ["2"])),
            pause_s=float(c["pause_s"]),
            normal_share=float(c["normal_share"]),
            reserve_runs_per_round=int(c.get("reserve_runs_per_round", 1)),
            parts=parts,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PlanError(f"collection: {type(exc).__name__}: {exc}") from None
    if repeats < 3:
        raise PlanError(
            f"collection.repeats: нужно не меньше 3 (обучение, валидация, тест), а {repeats}"
        )
    if not 0 <= coll.normal_share <= 1:
        raise PlanError("collection.normal_share: нужна доля от 0 до 1")
    flat = sorted(x for v in parts.values() for x in v)
    if flat != list(range(1, repeats + 1)) or set(parts) != {"train", "val", "test"}:
        raise PlanError(
            f"collection.parts: части train/val/test должны покрывать повторы 1…{repeats} без "
            "пересечений"
        )
    if idle_timeout_s is not None and coll.pause_s < idle_timeout_s + 30:
        raise PlanError(
            f"collection.pause_s={coll.pause_s:g} с меньше idle-таймаута экстрактора "
            f"({idle_timeout_s:g} с) + 30 с: "
            "потоки предыдущего запуска не успеют закрыться"
        )
    if max(parts["train"]) > min(parts["val"]) or max(parts["val"]) > min(parts["test"]):
        raise PlanError("collection.parts: части должны идти по времени train → val → test")
    return coll


def config_hash(raw: dict, coll: Collection) -> str:
    """Хеш того, что определяет план: сценарии выбранных версий, источники, раздел collection."""
    payload = {
        "scenarios": [
            s for s in raw.get("scenarios", []) if str(s.get("version")) in coll.versions
        ],
        "sources": raw["lab"].get("sources"),
        "collection": raw["collection"],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:16]


def part_of(coll: Collection, repeat: int) -> str:
    for name, reps in coll.parts.items():
        if repeat in reps:
            return name
    raise PlanError(f"повтор {repeat} не входит ни в одну часть разбиения")


def _choose_params(rng: random.Random, var: dict, in_test: bool) -> dict:
    """Параметры запуска: holdout — только в тесте; в тесте holdout берётся с вероятностью 0,6."""
    out = {}
    for name, dom in var["params"].items():
        values = list(dom["values"])
        hold = list(dom.get("holdout") or [])
        normal = [v for v in values if v not in hold]
        if in_test and hold and rng.random() < 0.6:
            out[name] = rng.choice(hold)
        else:
            out[name] = rng.choice(normal)
    return out


def build_plan(raw: dict, *, seed: int | None = None, repeats: int | None = None) -> dict:
    """Строит план; `seed`/`repeats` переопределяют конфиг (для сокращённых прогонов и тестов)."""
    coll = parse_collection(raw, idle_timeout_s=float(SCHEMA.extractor["idle_timeout"]))
    seed = coll.seed if seed is None else int(seed)
    if repeats is not None and repeats != coll.repeats:
        # Сокращённый план: части пересчитываются пропорционально (последние два раунда — тест, один
        # — валидация)
        if repeats < 3:
            raise PlanError("repeats: нужно не меньше 3")
        n_test, n_val = max(1, repeats // 5), max(1, repeats // 5)
        n_train = repeats - n_test - n_val
        coll = Collection(
            seed=seed,
            repeats=repeats,
            versions=coll.versions,
            pause_s=coll.pause_s,
            normal_share=coll.normal_share,
            reserve_runs_per_round=coll.reserve_runs_per_round,
            parts={
                "train": tuple(range(1, n_train + 1)),
                "val": tuple(range(n_train + 1, n_train + n_val + 1)),
                "test": tuple(range(n_train + n_val + 1, repeats + 1)),
            },
        )
    rng = random.Random(seed)
    variants = [v for v in expand_variants(raw) if str(v["version"]) in coll.versions]
    if not variants:
        raise PlanError(f"нет сценариев версий {list(coll.versions)} в конфиге")
    attackers = [name for name in source_ips(raw, "attacker")]
    if len(attackers) < 2:
        raise PlanError(
            "для устойчивости к ярлыкам нужно не меньше двух адресов источников атак (lab.sources, "
            "FR-002)"
        )
    ips = source_ips(raw)

    runs: list[dict] = []
    for r in range(1, coll.repeats + 1):
        part = part_of(coll, r)
        in_test = part == "test"
        round_runs: list[dict] = []
        for vi, var in enumerate(variants):
            reserved = var["reserve_unknown"]
            if reserved and not in_test:
                continue
            n_times = coll.reserve_runs_per_round if reserved else 1
            for k in range(n_times):
                src = attackers[(vi + r + k) % len(attackers)]
                label = f"r{r:02d}-{var['scenario']}-{var['variant']}" + (
                    f"-{k + 1}" if n_times > 1 else ""
                )
                round_runs.append(
                    {
                        "plan_run_uid": label,
                        "scenario": var["scenario"],
                        "version": str(var["version"]),
                        "variant": var["variant"],
                        "tool": var.get("tool_label") or var["tool"],
                        "binary": var["tool"],
                        "params": _choose_params(rng, var, in_test),
                        "source": src,
                        "source_ip": ips[src],
                        "repeat": r,
                        "part": part,
                        "with_normal": rng.random() < coll.normal_share,
                        "reserve_unknown": bool(reserved),
                        "hard_normal": bool(var["hard"]),
                        "expected_class": var["expected_class"],
                        "duration_limit_s": int(var["duration_limit_s"]),
                    }
                )
        rng.shuffle(round_runs)
        runs.extend(round_runs)

    t = 0.0
    for run in runs:
        run["start_offset_s"] = t
        t += run["duration_limit_s"] + coll.pause_s
    total_s = t
    return {
        "plan_version": PLAN_VERSION,
        "seed": seed,
        "config_hash": config_hash(raw, coll),
        "repeats": coll.repeats,
        "parts": {k: list(v) for k, v in coll.parts.items()},
        "pause_s": coll.pause_s,
        "runs": runs,
        "estimate": {"runs": len(runs), "total_s": total_s, "hours": round(total_s / 3600, 1)},
    }


def summarize(plan: dict) -> dict:
    """Состав плана для печати и проверок: по классам, инструментам, источникам, частям, резерву."""
    by_class: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_part: dict[str, int] = {}
    for r in plan["runs"]:
        by_class[r["expected_class"]] = by_class.get(r["expected_class"], 0) + 1
        by_tool[r["tool"]] = by_tool.get(r["tool"], 0) + 1
        by_source[r["source"]] = by_source.get(r["source"], 0) + 1
        by_part[r["part"]] = by_part.get(r["part"], 0) + 1
    return {
        "runs": len(plan["runs"]),
        "hours": plan["estimate"]["hours"],
        "by_class": by_class,
        "by_tool": by_tool,
        "by_source": by_source,
        "by_part": by_part,
        "reserve_runs": sum(1 for r in plan["runs"] if r["reserve_unknown"]),
        "with_normal": sum(1 for r in plan["runs"] if r["with_normal"]),
    }


def write_plan(plan: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return path


def read_plan(path: str | Path) -> dict:
    plan = json.loads(Path(path).read_text(encoding="utf-8"))
    if plan.get("plan_version") != PLAN_VERSION:
        raise PlanError(
            f"план {path}: версия {plan.get('plan_version')} не поддерживается (нужна "
            f"{PLAN_VERSION})"
        )
    return plan
