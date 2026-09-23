"""Конвейер `flows`: все захваты датасета по одному — извлечь, разметить, записать.

Главные свойства:
- возобновление: готовый захват с теми же входами пропускается (решает манифест);
- атомарность: parquet и манифест появляются только целиком — прерванный захват не
  оставляет «полуготовых» файлов;
- изоляция ошибок: битый PCAP помечается `failed`, остальные обрабатываются; а вот
  нехватка памяти или места на диске останавливает прогон целиком — следующие захваты
  упали бы точно так же, только через час;
- пик памяти каждого захвата пишется в манифест: так проверяется ограничение в 16 ГБ.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import polars as pl
import psutil

from mlsiem.data import captures as cap
from mlsiem.data.config import DataConfig
from mlsiem.data.extract import content_hash, extract_flows, write_flows_parquet
from mlsiem.data.labeling import TOLERANCE_MS, label_flows
from mlsiem.data.schema import SCHEMA
from mlsiem.data.sources import ctu13 as ctu13_source
from mlsiem.data.sources import unsw as unsw_source
from mlsiem.data.taxonomy import LABELING_VERSION

log = logging.getLogger("mlsiem")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class PeakMemory:
    """Фоновый замер пиковой памяти процесса вместе с дочерними процессами nfstream.

    nfstream разбирает PCAP в отдельных процессах, и их память `psutil.Process().rss` не
    видит — поэтому суммируем по всему дереву. Опрос раз в секунду: пик может проскочить
    между замерами, но порядок величины (важен запас до 16 ГБ) виден надёжно.
    """

    def __init__(self, interval: float = 1.0) -> None:
        self.interval = interval
        self.peak = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._proc = psutil.Process()

    def _sample(self) -> None:
        total = 0
        try:
            total = self._proc.memory_info().rss
            for child in self._proc.children(recursive=True):
                # дочерний процесс мог завершиться между перечислением и замером
                with contextlib.suppress(psutil.Error):
                    total += child.memory_info().rss
        except psutil.Error:
            return
        self.peak = max(self.peak, total)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self._sample()

    def __enter__(self):
        self._sample()
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()
        self._sample()
        return False

    @property
    def peak_mb(self) -> float:
        return round(self.peak / 1024 / 1024, 1)


@dataclass
class FlowsSummary:
    rows: list[dict] = field(default_factory=list)
    n_done: int = 0
    n_skipped: int = 0
    n_failed: int = 0
    label_counts: dict[str, int] = field(default_factory=dict)


def _params_hash(params: dict) -> str:
    return hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()


class _LabelSource:
    """Откуда брать разметку для захвата + ленивое чтение (GT UNSW читаем один раз на прогон)."""

    def __init__(self, cfg: DataConfig, dataset: str) -> None:
        self.cfg = cfg
        self.dataset = dataset
        self._unsw_gt: pl.DataFrame | None = None
        if dataset == "unsw":
            self.default_label = unsw_source.DEFAULT_LABEL
            params = {
                "source": "unsw",
                "tolerance_ms": TOLERANCE_MS,
                "default_label": self.default_label,
            }
        else:
            self.default_label = ctu13_source.DEFAULT_LABEL
            params = {
                "source": "ctu13",
                "tolerance_ms": TOLERANCE_MS,
                "default_label": self.default_label,
                "timezone": cfg.ctu13.timezone,
            }
        # Параметры разметки — тоже вход: смена часового пояса в конфиге должна привести
        # к пересчёту, иначе старые неверные метки остались бы молча
        self.params_hash = _params_hash(params)

    def path(self, capture: cap.Capture) -> Path:
        if self.dataset == "unsw":
            return self.cfg.unsw.gt_csv
        return ctu13_source.find_binetflow(capture.path.parent)

    def load(self, capture: cap.Capture) -> pl.DataFrame:
        if self.dataset == "unsw":
            if self._unsw_gt is None:
                self._unsw_gt = unsw_source.load_gt(self.cfg.unsw.gt_csv)
            return self._unsw_gt
        return ctu13_source.load_binetflow(self.path(capture), self.cfg.ctu13.timezone)


def _is_fatal(exc: BaseException) -> bool:
    """Ошибки, после которых продолжать бессмысленно: следующий захват упадёт так же."""
    if isinstance(exc, MemoryError | KeyboardInterrupt):
        return True
    return isinstance(exc, OSError) and exc.errno == errno.ENOSPC


def process_capture(
    capture: cap.Capture,
    labels: _LabelSource,
    out_dir: Path,
    *,
    label_fp: dict,
    workdir: Path,
) -> cap.CaptureManifest:
    """Один захват от PCAP до parquet и манифеста. Исключения пробрасываются наружу."""
    started = _now()
    with PeakMemory() as mem:
        extracted = extract_flows(capture.path, capture.capture_id, workdir=workdir)
        labeled = label_flows(
            extracted.df, labels.load(capture), default_label=labels.default_label
        )
        labeled = labeled.select(SCHEMA.names())
        write_flows_parquet(
            labeled,
            out_dir / f"{capture.capture_id}.parquet",
            {"mlsiem.labeling_version": LABELING_VERSION, "mlsiem.capture_id": capture.capture_id},
        )
    counts = labeled["label"].value_counts().sort("label")
    return cap.CaptureManifest(
        capture_id=capture.capture_id,
        fingerprint=capture.fingerprint,
        label_source_fingerprint=label_fp,
        labeling_params_hash=labels.params_hash,
        schema_version=SCHEMA.version,
        labeling_version=LABELING_VERSION,
        status="done",
        n_flows=labeled.height,
        n_matched=int(labeled["label_raw"].is_not_null().sum()),
        label_counts=dict(zip(counts["label"].to_list(), counts["count"].to_list(), strict=True)),
        content_hash=content_hash(labeled),
        warnings=extracted.warnings,
        peak_rss_mb=mem.peak_mb,
        started_at=started,
        finished_at=_now(),
    )


def run_flows(
    cfg: DataConfig,
    dataset: str,
    *,
    only: list[str] | None = None,
    force: bool = False,
    full_hash: bool = False,
    data_dir: Path = Path("data"),
) -> FlowsSummary:
    out_dir = Path(data_dir) / "flows" / dataset
    out_dir.mkdir(parents=True, exist_ok=True)
    # Схема рядом с данными: потребитель видит, чем посчитаны parquet, не заглядывая в код
    SCHEMA.to_json(out_dir / "schema.json")
    SCHEMA.to_json(Path(data_dir) / "flows" / "schema.json")

    all_captures = cap.discover(cfg, dataset)
    if only:
        known = {c.capture_id for c in all_captures}
        missing = [c for c in only if c not in known]
        if missing:
            raise ValueError(f"в датасете {dataset} нет захватов {missing}")
        captures = [c for c in all_captures if c.capture_id in only]
    else:
        captures = all_captures

    labels = _LabelSource(cfg, dataset)
    summary = FlowsSummary()
    total = len(captures)
    for i, capture in enumerate(captures, 1):
        prefix = f"[{i}/{total}] {capture.capture_id}"
        manifest_path = out_dir / f"{capture.capture_id}.json"
        parquet_path = out_dir / f"{capture.capture_id}.parquet"
        old = cap.read_manifest(manifest_path)
        try:
            capture.fingerprint = cap.fingerprint(capture.path, full=full_hash)
            label_path = labels.path(capture)
            label_fp = cap.fingerprint(label_path)
        except (OSError, ValueError) as exc:
            if _is_fatal(exc):
                raise
            _fail(summary, capture, manifest_path, parquet_path, exc, prefix, None, labels)
            continue

        if not cap.needs_processing(
            old,
            fingerprint=capture.fingerprint,
            label_source_fingerprint=label_fp,
            labeling_params_hash=labels.params_hash,
            schema_version=SCHEMA.version,
            labeling_version=LABELING_VERSION,
            output_exists=parquet_path.exists(),
            force=force,
        ):
            # Манифест пропущенного захвата не трогаем: в нём время и пик памяти того прогона
            log.info("%s: пропущен (уже готов)", prefix)
            summary.n_skipped += 1
            continue

        log.info("%s: обрабатываю %s", prefix, capture.path.name)
        try:
            manifest = process_capture(
                capture, labels, out_dir, label_fp=label_fp, workdir=Path(data_dir) / "tmp"
            )
        except BaseException as exc:
            _fail(summary, capture, manifest_path, parquet_path, exc, prefix, label_fp, labels)
            if _is_fatal(exc):
                raise
            continue
        cap.write_manifest(manifest, manifest_path)
        summary.n_done += 1
        rate = manifest.n_matched / manifest.n_flows if manifest.n_flows else 0.0
        log.info(
            "%s: готово — %d потоков, сопоставлено %.1f%%, пик памяти %.0f МБ",
            prefix,
            manifest.n_flows,
            100 * rate,
            manifest.peak_rss_mb,
        )
        for w in manifest.warnings:
            log.warning("%s: предупреждение: %s", prefix, w)

    write_summary(out_dir, [c.capture_id for c in all_captures], summary)
    return summary


def _fail(summary, capture, manifest_path, parquet_path, exc, prefix, label_fp, labels) -> None:
    """Помечает захват failed. Старый parquet удаляется: рядом с failed-манифестом он
    выглядел бы готовым результатом, хотя посчитан по другим входам."""
    reason = (
        "прервано пользователем"
        if isinstance(exc, KeyboardInterrupt)
        else (f"{type(exc).__name__}: {exc}")
    )
    parquet_path.unlink(missing_ok=True)
    cap.write_manifest(
        cap.CaptureManifest(
            capture_id=capture.capture_id,
            fingerprint=capture.fingerprint or {},
            label_source_fingerprint=label_fp,
            labeling_params_hash=labels.params_hash,
            schema_version=SCHEMA.version,
            labeling_version=LABELING_VERSION,
            status="failed",
            error=reason,
            finished_at=_now(),
        ),
        manifest_path,
    )
    summary.n_failed += 1
    log.error("%s: ошибка — %s", prefix, reason)


def write_summary(out_dir: Path, capture_ids: list[str], summary: FlowsSummary) -> None:
    """summary.csv по всем захватам датасета, для которых есть манифест.

    Без отметок времени и в порядке capture_id: если данные не менялись, файл получается
    побайтно тем же, и DVC не перезапускает зависящие от него стадии.
    """
    manifests = [
        m
        for cid in sorted(capture_ids)
        if (m := cap.read_manifest(out_dir / f"{cid}.json")) is not None
    ]
    classes = sorted({k for m in manifests for k in m.label_counts})
    rows = []
    for m in manifests:
        n, matched = m.n_flows or 0, m.n_matched or 0
        row = {
            "capture_id": m.capture_id,
            "status": m.status,
            "n_flows": m.n_flows,
            "n_matched": m.n_matched,
            "match_rate": round(matched / n, 4) if n else None,
            "peak_rss_mb": m.peak_rss_mb,
            "error": m.error,
        }
        row.update({c: m.label_counts.get(c, 0) for c in classes})
        rows.append(row)
        for c in classes:
            summary.label_counts[c] = summary.label_counts.get(c, 0) + m.label_counts.get(c, 0)
    summary.rows = rows
    schema = {
        "capture_id": pl.String,
        "status": pl.String,
        "n_flows": pl.Int64,
        "n_matched": pl.Int64,
        "match_rate": pl.Float64,
        "peak_rss_mb": pl.Float64,
        "error": pl.String,
        **{c: pl.Int64 for c in classes},
    }
    df = pl.DataFrame(rows, schema=schema)
    with cap.atomic_path(out_dir / "summary.csv") as tmp:
        df.write_csv(tmp)


def run_extract(pcap: Path, output: Path, *, workdir: Path) -> dict:
    """`mlsiem data extract`: тот же экстрактор без разметки — признаки как при обучении."""
    pcap = Path(pcap)
    if pcap.suffix.lower() not in (".pcap", ".pcapng"):
        raise ValueError(f"ожидался файл .pcap или .pcapng, а передан {pcap.name}")
    if not pcap.exists():
        raise FileNotFoundError(f"нет файла {pcap}")
    # Двоеточие недопустимо в именах файлов Windows, а capture_id попадает в имена
    capture_id = "adhoc_" + pcap.stem.replace(":", "_")
    result = extract_flows(pcap, capture_id, workdir=workdir)
    write_flows_parquet(result.df, Path(output), {"mlsiem.capture_id": capture_id})
    return {
        "capture_id": capture_id,
        "n_flows": result.df.height,
        "schema_version": SCHEMA.version,
        "warnings": result.warnings,
    }
