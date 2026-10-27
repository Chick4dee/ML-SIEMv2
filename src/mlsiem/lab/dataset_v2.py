"""Набор стенда версии 2 (фича 008, FR-009…FR-011, FR-026, FR-027): метки класса, варианта,
источника,
запуска и части разбиения; несколько сегментов записи одного плана.

Разметка — векторная (polars): окон запусков сотни, потоков — сотни тысяч, построчный цикл 006
(`dataset.label_flow`) здесь был бы слишком медленным. Правила те же, что в 006, плюс:
- запуск `aborted` (прерванный или не стартовавший) даёт потокам окна метку `ambiguous`, а не класс
  и не норму;
- «сложная норма» (`hard_normal`, класс benign) размечает потоки внутри окна как benign с пометкой и
  метаданными;
- потоки у краёв записи сеанса (начались в первые или закончились в последние секунды) —
  `ambiguous`:
  запись могла начаться и закончиться посреди потока (FR-027);
- часть разбиения (`train`/`val`/`test`/`gap`) берётся из запуска; потоки нормы получают часть
  раунда, в
  который попадают по времени; ±`GAP_MS` вокруг границы раундов с разными частями — `gap` (в
  обучении и
  оценке не участвует).

Модуль — часть хоста: не копируется на машины стенда.
"""

from __future__ import annotations

import bisect
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import polars as pl

from mlsiem.lab import journal
from mlsiem.lab.dataset import AMBIGUOUS, BENIGN, DEFAULT_MARGIN_MS, FIRST, LAST

META_COLS = [
    "variant",
    "tool",
    "source",
    "run_uid",
    "plan_run_uid",
    "repeat",
    "part",
    "reserve_unknown",
    "hard_normal",
]
EDGE_MS = 2_000  # край записи сеанса: потоки в первых и последних секундах неоднозначны
GAP_MS = 30_000  # зазор вокруг границы раундов с разными частями разбиения


def _targets(rec: dict) -> list[str]:
    return list(rec.get("targets") or [])


def _round_bounds(records: list[dict]) -> list[tuple[int, int, str]]:
    """Раунды: (начало_мс, повтор, часть) по первому запуску повтора; отсортированы по времени."""
    first: dict[int, tuple[int, str]] = {}
    for r in records:
        if r.get("repeat") is None or r.get("outcome") == "rejected":
            continue
        t = journal.to_ms(r["started_at"])
        rep = int(r["repeat"])
        if rep not in first or t < first[rep][0]:
            first[rep] = (t, r.get("part") or "train")
    return sorted((t, rep, part) for rep, (t, part) in first.items())


def assign_parts(flows: pl.DataFrame, records: list[dict]) -> pl.DataFrame:
    """Колонка `_part_time`: часть разбиения по времени начала потока — раунд, в который он попал;
    близко (±GAP_MS) к границе раундов с разными частями — `gap`.
    Без записей с повторами возвращает потоки как есть."""
    rounds = _round_bounds(records)
    if not rounds:
        return flows
    starts = [t for t, _, _ in rounds]
    parts = [p for _, _, p in rounds]
    out = []
    for t in flows[FIRST].to_list():
        k = max(bisect.bisect_right(starts, t) - 1, 0)
        gap = (k > 0 and parts[k] != parts[k - 1] and t - starts[k] <= GAP_MS) or (
            k + 1 < len(starts) and parts[k + 1] != parts[k] and starts[k + 1] - t <= GAP_MS
        )
        out.append("gap" if gap else parts[k])
    return flows.with_columns(pl.Series("_part_time", out, dtype=pl.String))


def label_flows_v2(
    flows: pl.DataFrame, records: list[dict], *, margin_ms: int = DEFAULT_MARGIN_MS
) -> pl.DataFrame:
    """Метки и метаданные запусков. Потоки обязаны содержать src_ip, dst_ip и времена "
    "первого/последнего пакета."""
    n = flows.height
    first = flows[FIRST].to_numpy()
    last = flows[LAST].to_numpy()
    src = flows["src_ip"].to_numpy()
    dst = flows["dst_ip"].to_numpy()
    label_arr = np.array([BENIGN] * n, dtype=object)
    assigned = np.zeros(n, dtype=bool)
    meta = {c: np.array([None] * n, dtype=object) for c in META_COLS}
    for start, end, rec in journal.windows(records):
        hard = bool(rec.get("hard_normal"))
        if rec["expected_class"] == BENIGN and not hard:
            continue  # фоновая норма рамок не навязывает
        ip = rec.get("source_ip") or rec["attacker_ip"]
        m = (
            (src == ip)
            & np.isin(dst, _targets(rec))
            & ~assigned
            & (last >= start)
            & (first <= end + margin_ms)
        )
        if not m.any():
            continue
        inside = m & (first >= start) & (last <= end + margin_ms)
        if rec["outcome"] == "aborted":
            cls = np.where(m, AMBIGUOUS, None)
        elif hard:
            cls = np.where(inside, BENIGN, None)
            cls = np.where(m & ~inside, AMBIGUOUS, cls)
        else:
            cls = np.where(inside, rec["expected_class"], None)
            cls = np.where(m & ~inside, AMBIGUOUS, cls)
        sel = m
        label_arr[sel] = cls[sel]
        assigned |= sel
        values = {
            "variant": rec.get("variant"),
            "tool": rec.get("tool"),
            "source": rec.get("source"),
            "run_uid": rec["run_uid"],
            "plan_run_uid": rec.get("plan_run_uid"),
            "repeat": rec.get("repeat"),
            "part": rec.get("part"),
            "reserve_unknown": bool(rec.get("reserve_unknown")),
            "hard_normal": hard,
        }
        for k, v in values.items():
            meta[k][sel] = v
    out = flows.with_columns(pl.Series("label", list(label_arr), dtype=pl.String))
    for c in META_COLS:
        dtype = (
            pl.Boolean
            if c in ("reserve_unknown", "hard_normal")
            else (pl.Int64 if c == "repeat" else pl.String)
        )
        vals = list(meta[c])
        if dtype == pl.Boolean:
            vals = [bool(v) if v is not None else False for v in vals]
        out = out.with_columns(pl.Series(c, vals, dtype=dtype))
    return out


def mark_segment_edges(
    df: pl.DataFrame, seg_start_ms: int, seg_end_ms: int, edge_ms: int = EDGE_MS
) -> pl.DataFrame:
    """Потоки у краёв записи сеанса — `ambiguous` (могли начаться до записи или оборваться её "
    "концом)."""
    edge = (pl.col(FIRST) <= seg_start_ms + edge_ms) | (pl.col(LAST) >= seg_end_ms - edge_ms)
    return df.with_columns(
        pl.when(edge & (pl.col("label") != AMBIGUOUS))
        .then(pl.lit(AMBIGUOUS))
        .otherwise(pl.col("label"))
        .alias("label")
    )


def finalize_parts(labeled: pl.DataFrame, records: list[dict]) -> pl.DataFrame:
    """Колонка `part`: у потоков запуска — из записи; у остальных — по времени раунда "
    "(`assign_parts`)."""
    timed = assign_parts(labeled, records)
    if "_part_time" not in timed.columns:
        return labeled.with_columns(pl.col("part").fill_null("train"))
    return timed.with_columns(
        pl.coalesce([pl.col("part"), pl.col("_part_time")]).alias("part")
    ).drop("_part_time")


def build_dataset_v2(
    segments: list[dict],
    records: list[dict],
    out_dir: Path,
    version: str,
    *,
    plan_hash: str | None = None,
    tools: dict | None = None,
    margin_ms: int = DEFAULT_MARGIN_MS,
    extract=None,
) -> dict:
    """Строит набор версии 2 из сегментов записи (`[{session_id, pcaps: [Path], stats}]`) и журнала.

    `extract(pcap, capture_id) -> pl.DataFrame` подменяется в тестах;
    по умолчанию — экстрактор 001."""
    from mlsiem.data.schema import SCHEMA

    if extract is None:
        from mlsiem.data.extract import extract_flows

        def extract(pcap, capture_id):  # noqa: ANN001
            with tempfile.TemporaryDirectory(prefix="mlsiem-lab-ds-") as wd:
                return extract_flows(Path(pcap), capture_id, workdir=Path(wd)).df

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    parts: list[pl.DataFrame] = []
    seg_info = []
    for seg in segments:
        frames = []
        for pcap in seg["pcaps"]:
            df = extract(pcap, f"lab-{version}-{seg['session_id']}")
            if df.height == 0:
                continue
            frames.append(df)
        if not frames:
            continue
        df = pl.concat(frames, how="diagonal_relaxed")
        lab = label_flows_v2(df, records, margin_ms=margin_ms)
        lab = mark_segment_edges(lab, int(df[FIRST].min()), int(df[LAST].max()))
        lab = lab.with_columns(pl.lit(seg["session_id"]).alias("session_id"))
        parts.append(lab)
        seg_info.append(
            {
                "session_id": seg["session_id"],
                "flows": lab.height,
                "stats": seg.get("stats"),
                "files": [str(Path(p).name) for p in seg["pcaps"]],
            }
        )
    if not parts:
        raise ValueError("в сегментах нет потоков — набор не построен")
    labeled = finalize_parts(pl.concat(parts, how="diagonal_relaxed"), records)
    labeled.write_parquet(out_dir / "flows.parquet")
    counts = {r["label"]: r["count"] for r in labeled["label"].value_counts().iter_rows(named=True)}
    scenario_flows = sum(v for k, v in counts.items() if k != BENIGN)
    ambiguous = counts.get(AMBIGUOUS, 0)
    manifest = {
        "version": version,
        "format": 2,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "schema_version": SCHEMA.version,
        "margin_ms": margin_ms,
        "plan_hash": plan_hash,
        "n_flows": labeled.height,
        "by_class": counts,
        "ambiguous_share_of_scenarios": (ambiguous / scenario_flows) if scenario_flows else 0.0,
        "segments": seg_info,
        "tools": tools or {},
        "runs": len(records),
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest
