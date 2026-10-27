"""Отчёт о качестве набора стенда и вердикт `clean` / `suspect` (фича 008, R9, FR-010, FR-012,
SC-002, SC-004).

Что проверяется (всё по набору версии 2 — `dataset_v2.build_dataset_v2`):
- объём по классам × инструментам × источникам × частям разбиения (таблицы для отчёта);
- доля неоднозначных потоков среди потоков сценариев (порог 5%, FR-010);
- связь класса с источником и с временем (номером повтора) — нормированная взаимная информация (NMI)
  на
  потоках атак без резерва «неизвестное»: близкое к 1 значение значит «адрес или время определяют
  класс»,
  то есть модель может выучить ярлык; порог — `nmi_threshold` (по умолчанию 0,9);
- у каждого класса ≥ 2 инструментов (иначе исключение инструмента невозможно, FR-001);
- в тесте ≥ `min_test_flows` потоков класса и ≥ `min_test_benign` нормы (SC-002) — иначе класс
  «ненадёжный»;
- класс присутствует в обучении (кроме резерва «неизвестное», который только в тесте, FR-021);
- норма идёт с нескольких адресов: ни один адрес не даёт > 90% нормы (FR-003).
Вердикт `suspect` — штатный результат (сигнал владельцу), а не ошибка.
"""

from __future__ import annotations

import json
from pathlib import Path

import polars as pl

from mlsiem.lab.dataset import AMBIGUOUS, BENIGN

AMBIGUOUS_MAX = 0.05
NMI_THRESHOLD = 0.9
MIN_TEST_FLOWS = 100
MIN_TEST_BENIGN = 20_000
BENIGN_SOURCE_MAX = 0.9


def _nmi(a: list, b: list) -> float:
    from sklearn.metrics import normalized_mutual_info_score

    if len(set(a)) < 2 or len(set(b)) < 2:
        return 0.0
    return float(normalized_mutual_info_score(a, b))


def _table(df: pl.DataFrame, by: list[str]) -> list[dict]:
    return df.group_by(by).len().rename({"len": "flows"}).sort(by).to_dicts()


def quality_report(
    labeled: pl.DataFrame,
    *,
    source_names: dict[str, str] | None = None,
    nmi_threshold: float = NMI_THRESHOLD,
    min_test_flows: int = MIN_TEST_FLOWS,
    min_test_benign: int = MIN_TEST_BENIGN,
    seed: int = 0,
) -> dict:
    """Отчёт качества. `source_names` — адрес → имя источника (для нормы без метки источника)."""
    reasons: list[dict] = []
    warnings: list[dict] = []
    total = labeled.height
    attack = labeled.filter(~pl.col("label").is_in([BENIGN, AMBIGUOUS]))
    scen_flows = labeled.filter(pl.col("label") != BENIGN).height
    amb = labeled.filter(pl.col("label") == AMBIGUOUS).height
    amb_share = amb / scen_flows if scen_flows else 0.0
    if amb_share > AMBIGUOUS_MAX:
        reasons.append(
            {
                "type": "ambiguous",
                "value": round(amb_share, 4),
                "text": f"неоднозначных {amb_share:.1%} потоков сценариев (порог "
                "{AMBIGUOUS_MAX:.0%})",
            }
        )

    counts = {
        "by_class": _table(labeled, ["label"]),
        "class_tool": _table(attack, ["label", "tool"]),
        "class_source": _table(attack, ["label", "source"]),
        "class_part": _table(labeled.filter(pl.col("label") != AMBIGUOUS), ["label", "part"]),
        "class_repeat": _table(attack, ["label", "repeat"]),
    }

    # нормальные потоки по источникам (FR-003)
    norm = labeled.filter(pl.col("label") == BENIGN)
    names = source_names or {}
    norm_src = (
        norm.with_columns(
            pl.col("src_ip")
            .map_elements(lambda ip: names.get(ip, ip), return_dtype=pl.String)
            .alias("src_name")
        )
        .group_by("src_name")
        .len()
        .rename({"len": "flows"})
        .sort("flows", descending=True)
    )
    counts["benign_by_source"] = norm_src.to_dicts()
    if norm.height:
        top = norm_src["flows"][0] / norm.height
        if top > BENIGN_SOURCE_MAX:
            reasons.append(
                {
                    "type": "benign_source",
                    "value": round(top, 3),
                    "text": f"{top:.0%} нормы идёт с одного адреса ({norm_src['src_name'][0]})",
                }
            )

    # инструменты на класс (исключение инструмента, FR-001) и резерв
    tools_by_class = {}
    for c in attack["label"].unique().to_list():
        tools_by_class[c] = sorted(
            attack.filter(pl.col("label") == c)["tool"].drop_nulls().unique().to_list()
        )
        if len(tools_by_class[c]) < 2:
            reasons.append(
                {
                    "type": "single_tool",
                    "class": c,
                    "text": f"у класса {c} один инструмент {tools_by_class[c]}: исключение "
                    "инструмента невозможно",
                }
            )

    # NMI класс↔источник и класс↔повтор (на потоках без резерва «неизвестное»)
    base = attack.filter(~pl.col("reserve_unknown"))
    nmi = {"class_source": 0.0, "class_repeat": 0.0}
    if base.height:
        sample = base.sample(n=min(base.height, 200_000), seed=seed)
        cls = sample["label"].to_list()
        nmi["class_source"] = _nmi(cls, sample["source"].fill_null("?").to_list())
        nmi["class_repeat"] = _nmi(cls, sample["repeat"].fill_null(-1).to_list())
        for key, what in (("class_source", "источником"), ("class_repeat", "временем (повтором)")):
            if nmi[key] > nmi_threshold:
                reasons.append(
                    {
                        "type": f"nmi_{key}",
                        "value": round(nmi[key], 3),
                        "text": f"класс определяется {what} (NMI {nmi[key]:.2f} > {nmi_threshold})",
                    }
                )

    # достаточность по частям разбиения (SC-002, FR-011)
    part_counts = {(r["label"], r["part"]): r["flows"] for r in counts["class_part"]}
    reserved = set(attack.filter(pl.col("reserve_unknown"))["label"].unique().to_list()) - set(
        base["label"].unique().to_list()
    )
    unreliable = []
    for c in sorted(attack["label"].unique().to_list()):
        test_n = part_counts.get((c, "test"), 0)
        if test_n < min_test_flows:
            unreliable.append({"class": c, "test_flows": test_n})
            warnings.append(
                {
                    "type": "few_test_flows",
                    "class": c,
                    "value": test_n,
                    "text": f"в тесте {test_n} потоков класса {c} (< {min_test_flows}): оценка "
                    "ненадёжна",
                }
            )
        if c not in reserved and part_counts.get((c, "train"), 0) == 0:
            reasons.append({"type": "no_train", "class": c, "text": f"класса {c} нет в обучении"})
    test_benign = part_counts.get((BENIGN, "test"), 0)
    if test_benign < min_test_benign:
        warnings.append(
            {
                "type": "few_benign_test",
                "value": test_benign,
                "text": f"нормальных потоков в тесте {test_benign} (< {min_test_benign}): доли "
                "ложных срабатываний 0,1% измеряются грубо",
            }
        )

    return {
        "total_flows": total,
        "ambiguous": amb,
        "ambiguous_share_of_scenarios": round(amb_share, 4),
        "counts": counts,
        "tools_by_class": tools_by_class,
        "nmi": {k: round(v, 4) for k, v in nmi.items()},
        "unreliable_classes": unreliable,
        "reserved_classes": sorted(reserved),
        "warnings": warnings,
        "reasons": reasons,
        "verdict": "suspect" if reasons else "clean",
    }


def report_md(rep: dict, version: str) -> str:
    c = rep["counts"]
    lines = [f"# Качество набора стенда {version}", "", f"**Вердикт: {rep['verdict']}**", ""]
    lines += [
        f"- потоков: {rep['total_flows']}; неоднозначных {rep['ambiguous']} "
        f"({rep['ambiguous_share_of_scenarios'] * 100:.1f}% потоков сценариев)"
    ]
    lines += [
        f"- NMI класс↔источник {rep['nmi']['class_source']}, класс↔повтор "
        f"{rep['nmi']['class_repeat']}"
    ]
    if rep["reasons"]:
        lines += ["", "## Причины вердикта `suspect`", ""] + [
            f"- {r['text']}" for r in rep["reasons"]
        ]
    if rep["warnings"]:
        lines += ["", "## Предупреждения", ""] + [f"- {w['text']}" for w in rep["warnings"]]
    lines += ["", "## Потоки по классам", "", "| класс | потоков |", "|---|---|"] + [
        f"| {r['label']} | {r['flows']} |" for r in c["by_class"]
    ]
    lines += ["", "## Инструменты по классам", ""] + [
        f"- {k}: {', '.join(v)}" for k, v in rep["tools_by_class"].items()
    ]
    lines += ["", "## Норма по источникам", "", "| источник | потоков |", "|---|---|"] + [
        f"| {r['src_name']} | {r['flows']} |" for r in c["benign_by_source"]
    ]
    return "\n".join(lines) + "\n"


def write_report(rep: dict, out_dir: Path, version: str) -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    js, md = out_dir / "quality.json", out_dir / "quality.md"
    js.write_text(json.dumps(rep, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    md.write_text(report_md(rep, version), encoding="utf-8")
    return md, js
