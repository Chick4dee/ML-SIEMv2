"""Сборка отчёта о качестве данных: reports/data_quality.html + reports/data_quality.md.

HTML полностью самостоятельный: стили внутри, графики — PNG в base64. Его можно открыть
двойным кликом без сети, приложить к письму или выложить на GitHub Pages. Markdown —
короткая сводка, которая читается прямо в репозитории.

Отчёт ничего не считает заново — только собирает то, что уже лежит в data/: сводки и
манифесты захватов, манифесты разбиений, результаты аудита и сверки с v1. Если какого-то
куска нет (например, сверку не запускали), раздел честно говорит об этом, а не падает.
"""

from __future__ import annotations

import base64
import io
import json
from datetime import UTC, datetime
from pathlib import Path

import polars as pl
from jinja2 import Environment, FileSystemLoader, select_autoescape

from mlsiem.data import captures as cap
from mlsiem.data.compare_v1 import discrepancy_reasons
from mlsiem.data.config import DataConfig
from mlsiem.data.schema import SCHEMA
from mlsiem.data.split import PARTS, SPLIT_DATASET
from mlsiem.data.taxonomy import LABELING_VERSION

TEMPLATES = Path(__file__).parent / "templates"
DATASETS = ("unsw", "ctu13")
DATASET_TITLES = {"unsw": "UNSW-NB15", "ctu13": "CTU-13"}

# Нейтральные цвета графиков: читаются и на светлом, и на тёмном фоне страницы
ACCENT, MUTED, WARN = "#3b82f6", "#8a8f98", "#e8590c"


def _png(fig) -> str:
    import matplotlib.pyplot as plt

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110, bbox_inches="tight", transparent=True)
    plt.close(fig)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


def _style(ax) -> None:
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelsize=8)
    ax.yaxis.label.set_color(MUTED)
    ax.xaxis.label.set_color(MUTED)
    ax.title.set_color(MUTED)


def _figure(width: float, height: float):
    import matplotlib

    matplotlib.use("Agg")  # без окна: отчёт собирается и на машине без дисплея
    import matplotlib.pyplot as plt

    return plt.subplots(figsize=(width, height))


# ---------------------------------------------------------------- сбор данных


def _collect_captures(data_dir: Path) -> dict[str, dict]:
    result = {}
    for ds in DATASETS:
        folder = data_dir / "flows" / ds
        summary_path = folder / "summary.csv"
        if not summary_path.exists():
            continue
        summary = pl.read_csv(summary_path)
        manifests = {}
        for cid in summary["capture_id"].to_list():
            m = cap.read_manifest(folder / f"{cid}.json")
            if m is not None:
                manifests[cid] = m
        rows = []
        for r in summary.iter_rows(named=True):
            m = manifests.get(r["capture_id"])
            rows.append(
                {
                    **r,
                    "content_hash": (m.content_hash or "")[:12] if m else "",
                    "warnings": m.warnings if m else [],
                }
            )
        classes = sorted({k for m in manifests.values() for k in m.label_counts})
        totals = {c: sum(m.label_counts.get(c, 0) for m in manifests.values()) for c in classes}
        n_flows = sum(m.n_flows or 0 for m in manifests.values())
        n_matched = sum(m.n_matched or 0 for m in manifests.values())
        peaks = [m.peak_rss_mb for m in manifests.values() if m.peak_rss_mb]
        result[ds] = {
            "title": DATASET_TITLES[ds],
            "rows": rows,
            "n_captures": len(rows),
            "n_done": sum(r["status"] == "done" for r in rows),
            "n_failed": sum(r["status"] == "failed" for r in rows),
            "n_flows": n_flows,
            "n_matched": n_matched,
            "match_rate": n_matched / n_flows if n_flows else None,
            "class_totals": dict(sorted(totals.items(), key=lambda kv: -kv[1])),
            "peak_rss_mb": max(peaks) if peaks else None,
            "schema_versions": sorted({m.schema_version for m in manifests.values()}),
            "labeling_versions": sorted({m.labeling_version or "—" for m in manifests.values()}),
            "warnings": [(cid, w) for cid, m in manifests.items() for w in m.warnings],
            "chart": _match_chart(rows, ds) if rows else None,
        }
    return result


def _match_chart(rows: list[dict], ds: str) -> str:
    ids = [r["capture_id"].replace(f"{ds}_", "") for r in rows]
    rates = [r["match_rate"] or 0 for r in rows]
    fig, ax = _figure(max(6.0, 0.14 * len(ids)), 2.4)
    ax.bar(
        range(len(ids)), rates, color=[WARN if r["status"] == "failed" else ACCENT for r in rows]
    )
    ax.set_xticks(range(len(ids)))
    ax.set_xticklabels(ids, rotation=90, fontsize=6 if len(ids) > 30 else 8)
    ax.set_ylabel("доля сопоставленных" if ds == "ctu13" else "доля атак (сопоставлено)")
    ax.set_ylim(0, 1)
    _style(ax)
    return _png(fig)


def _collect_splits(data_dir: Path) -> list[dict]:
    out = []
    for name in SPLIT_DATASET:
        path = data_dir / "splits" / f"{name}.json"
        if not path.exists():
            continue
        m = json.loads(path.read_text(encoding="utf-8"))
        classes = sorted({c for p in PARTS for c in m["parts"][p]["label_counts"]})
        table = [
            {
                "class": c,
                **{p: m["parts"][p]["label_counts"].get(c, 0) for p in PARTS},
                "excluded": m["excluded"]["by_label"].get(c, 0),
            }
            for c in classes
        ]
        out.append(
            {
                "name": name,
                "dataset": DATASET_TITLES[m["dataset"]],
                "hash": m["hash"][:12],
                "parts": {p: m["parts"][p] for p in PARTS},
                "classes": table,
                "excluded": m["excluded"],
                "missing": m["missing_classes"],
                "params": m["params"],
                "chart": _split_chart(table),
            }
        )
    return out


def _split_chart(table: list[dict]) -> str | None:
    if not table:
        return None
    fig, ax = _figure(6.5, 0.28 * len(table) + 0.8)
    names = [r["class"] for r in table]
    left = [0.0] * len(table)
    colors = {"train": ACCENT, "val": "#93c5fd", "test": MUTED}
    for p in PARTS:
        totals = [max(1, r["train"] + r["val"] + r["test"]) for r in table]
        shares = [r[p] / t for r, t in zip(table, totals, strict=True)]
        ax.barh(names, shares, left=left, color=colors[p], label=p)
        left = [a + b for a, b in zip(left, shares, strict=True)]
    ax.set_xlim(0, 1)
    ax.invert_yaxis()
    ax.set_xlabel("доля потоков класса по частям")
    legend = ax.legend(loc="lower right", fontsize=7, frameon=False, ncol=3)
    for text in legend.get_texts():
        text.set_color(MUTED)
    _style(ax)
    return _png(fig)


def _collect_audit(data_dir: Path, cfg: DataConfig) -> list[dict]:
    out = []
    for name in SPLIT_DATASET:
        path = data_dir / "audit" / f"{name}.parquet"
        if not path.exists():
            continue
        df = pl.read_parquet(path)
        flagged = df.filter(pl.col("status") != "ok").sort(["status", "lift"], descending=True)
        top = df.sort("lift", descending=True, nulls_last=True).head(20)
        out.append(
            {
                "name": name,
                "n_fields": df.height,
                "baseline": df["baseline"][0] if df.height else None,
                "flagged": flagged.to_dicts(),
                "n_dangerous": int((df["status"] == "dangerous").sum()),
                "n_suspicious": int((df["status"] == "suspicious").sum()),
                "chart": _audit_chart(top, cfg) if top.height else None,
            }
        )
    return out


def _audit_chart(top: pl.DataFrame, cfg: DataConfig) -> str:
    fig, ax = _figure(6.5, 0.26 * top.height + 0.8)
    labels = [
        f"{f}" + (" /24" if v == "subnet24" else "")
        for f, v in zip(top["field"], top["variant"], strict=True)
    ]
    colors = [
        WARN if s == "dangerous" else ("#f59f00" if s == "suspicious" else ACCENT)
        for s in top["status"]
    ]
    ax.barh(labels, top["lift"].fill_null(0).to_list(), color=colors)
    ax.axvline(cfg.audit.dangerous_lift, color=MUTED, linestyle="--", linewidth=1)
    ax.invert_yaxis()
    ax.set_xlabel("lift = PR-AUC поля − базовая линия (пунктир — порог dangerous)")
    _style(ax)
    return _png(fig)


def _collect_compare(data_dir: Path) -> dict | None:
    path = data_dir / "compare_v1.csv"
    if not path.exists():
        return None
    df = pl.read_csv(path, schema_overrides={"explained": pl.String})
    rows = []
    for r in df.iter_rows(named=True):
        r["explained"] = r["explained"] or ""
        r["reasons"] = discrepancy_reasons(r) if r["in_v1"] else ["захвата нет в v1"]
        rows.append(r)
    ctu = [r for r in rows if r["capture_id"].startswith("ctu13_")]
    return {
        "rows": rows,
        "ctu13": ctu,
        "n_unexplained": sum(1 for r in rows if r["in_v1"] and r["reasons"] and not r["explained"]),
    }


# ---------------------------------------------------------------- рендер


def build_report(
    cfg: DataConfig, *, data_dir: Path = Path("data"), output: Path = Path("reports")
) -> tuple[Path, Path]:
    data_dir, output = Path(data_dir), Path(output)
    context = {
        "generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "schema_version": SCHEMA.version,
        "labeling_version": LABELING_VERSION,
        "extractor": SCHEMA.extractor,
        "datasets": _collect_captures(data_dir),
        "splits": _collect_splits(data_dir),
        "audits": _collect_audit(data_dir, cfg),
        "audit_cfg": cfg.audit,
        "compare": _collect_compare(data_dir),
        "parts": PARTS,
    }
    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=select_autoescape(["html.j2"], default=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["num"] = lambda v: "—" if v is None else f"{v:,}".replace(",", " ")
    env.filters["pct"] = lambda v, d=1: "—" if v is None else f"{100 * v:.{d}f}%"
    env.filters["f3"] = lambda v: "—" if v is None else f"{v:.3f}"

    html_path, md_path = output / "data_quality.html", output / "data_quality.md"
    for template, path in (("data_quality.html.j2", html_path), ("data_quality.md.j2", md_path)):
        text = env.get_template(template).render(**context)
        with cap.atomic_path(path) as tmp:
            tmp.write_text(text, encoding="utf-8")
    return html_path, md_path
