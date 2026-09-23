"""Захваты (входные PCAP): поиск, отпечатки, манифесты и атомарная запись.

Манифест — это «память» конвейера между запусками: по нему решается, можно ли пропустить
захват. Поэтому в нём лежат отпечатки ВСЕХ входов (PCAP, файл разметки, параметры разметки)
и версии кода (схема, правила разметки). Поменялось что-то одно — захват пересчитывается.

Безопасность (research R11): в папках CTU-13 лежат настоящие бинарники ботнетов (*.exe).
Здесь файлы выбираются только по явным шаблонам *.pcap / *.pcapng — ничего другого
код не открывает и никуда не копирует.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mlsiem.data.config import DataConfig

CHUNK = 16 * 1024 * 1024  # сколько байт с головы и хвоста файла входит в отпечаток
PCAP_PATTERNS = ("*.pcap", "*.pcapng")
log = logging.getLogger("mlsiem")

# Семейства ботнетов CTU-13 по сценариям (research R7; определены по бинарникам в папках)
CTU13_FAMILIES = {
    1: "Neris",
    2: "Neris",
    9: "Neris",
    3: "Rbot",
    4: "Rbot",
    10: "Rbot",
    11: "Rbot",
    5: "Virut",
    13: "Virut",
    6: "Menti",
    7: "Sogou",
    8: "Murlo",
    12: "NSIS.ay",
}


@dataclass
class Capture:
    capture_id: str
    source: str  # unsw | ctu13 | adhoc
    path: Path
    day: str | None = None
    scenario: int | None = None
    family: str | None = None
    fingerprint: dict | None = None
    status: str = "pending"  # pending | done | failed


@dataclass
class CaptureManifest:
    capture_id: str
    fingerprint: dict
    label_source_fingerprint: dict | None
    labeling_params_hash: str | None
    schema_version: str
    labeling_version: str | None
    status: str
    n_flows: int | None = None
    n_matched: int | None = None
    label_counts: dict[str, int] = field(default_factory=dict)
    content_hash: str | None = None
    warnings: list[str] = field(default_factory=list)
    peak_rss_mb: float | None = None
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None


# ---------------------------------------------------------------- атомарная запись


@contextlib.contextmanager
def atomic_path(final: Path) -> Iterator[Path]:
    """Отдаёт временный путь рядом с итоговым; после успешного блока переименовывает.

    `os.replace` в пределах одного диска атомарен: читатель видит либо старый файл, либо
    новый целиком, но никогда — наполовину записанный. Если внутри блока исключение
    (или Ctrl+C), временный файл удаляется, а итоговый не появляется вовсе.
    """
    final = Path(final)
    final.parent.mkdir(parents=True, exist_ok=True)
    tmp = final.with_name(f".{final.name}.tmp-{os.getpid()}")
    try:
        yield tmp
        os.replace(tmp, final)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------- отпечатки


def fingerprint(path: Path, *, full: bool = False) -> dict:
    """Отпечаток файла: размер + mtime + SHA-256 первых и последних 16 МБ.

    Полный SHA-256 по 100 ГБ считался бы минутами на каждый запуск, а подмену или обрезку
    файла частичный отпечаток ловит и так (research R4). Полный — по флагу --full-hash.
    """
    path = Path(path)
    stat = path.stat()
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read(CHUNK))
        if stat.st_size > CHUNK:
            f.seek(max(CHUNK, stat.st_size - CHUNK))
            h.update(f.read(CHUNK))
    full_sha = None
    if full:
        fh = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(CHUNK), b""):
                fh.update(block)
        full_sha = fh.hexdigest()
    return {
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "partial_sha256": h.hexdigest(),
        "full_sha256": full_sha,
    }


def same_fingerprint(old: dict | None, new: dict | None) -> bool:
    """Совпадают ли отпечатки. Полный хеш сравнивается, только если он есть у обоих —
    иначе один прогон с --full-hash заставил бы потом пересчитать всё заново."""
    if old is None or new is None:
        return old is new
    keys = ("size", "mtime_ns", "partial_sha256")
    if any(old.get(k) != new.get(k) for k in keys):
        return False
    if old.get("full_sha256") and new.get("full_sha256"):
        return old["full_sha256"] == new["full_sha256"]
    return True


# ---------------------------------------------------------------- манифесты


def write_manifest(manifest: CaptureManifest, path: Path) -> None:
    with atomic_path(Path(path)) as tmp:
        tmp.write_text(
            json.dumps(asdict(manifest), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def read_manifest(path: Path) -> CaptureManifest | None:
    """Читает манифест. Нет файла или он битый — None (захват просто пересчитается)."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        return CaptureManifest(**json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, TypeError):
        return None


def needs_processing(
    manifest: CaptureManifest | None,
    *,
    fingerprint: dict,
    label_source_fingerprint: dict | None,
    labeling_params_hash: str | None,
    schema_version: str,
    labeling_version: str | None,
    output_exists: bool,
    force: bool = False,
) -> bool:
    """Нужно ли (пере)считать захват. Пропускаем только полностью совпадающий `done`."""
    if force or manifest is None or manifest.status != "done" or not output_exists:
        return True
    return not (
        same_fingerprint(manifest.fingerprint, fingerprint)
        and same_fingerprint(manifest.label_source_fingerprint, label_source_fingerprint)
        and manifest.labeling_params_hash == labeling_params_hash
        and manifest.schema_version == schema_version
        and manifest.labeling_version == labeling_version
    )


# ---------------------------------------------------------------- поиск захватов


def _day_key(day: str) -> tuple[int, int, int]:
    d, m, y = (int(x) for x in day.split("-"))
    return (y, m, d)


def discover_unsw(cfg: DataConfig) -> list[Capture]:
    """PCAP UNSW-NB15: `pcaps 22-1-2015/7.pcap` → `unsw_22-1-2015_07`."""
    captures = []
    for path in cfg.unsw.root.glob(cfg.unsw.pcap_glob):
        if path.suffix.lower() not in (".pcap", ".pcapng"):
            continue
        m = re.search(r"(\d{1,2}-\d{1,2}-\d{4})", path.parent.name)
        if not m or not path.stem.isdigit():
            raise FileNotFoundError(f"не понимаю, какой это день/номер захвата UNSW: {path}")
        day, num = m.group(1), int(path.stem)
        captures.append(
            Capture(capture_id=f"unsw_{day}_{num:02d}", source="unsw", path=path, day=day)
        )
    if not captures:
        raise FileNotFoundError(
            f"по шаблону {cfg.unsw.pcap_glob!r} в {cfg.unsw.root} не найдено ни одного PCAP"
        )
    # Хронологически: сначала день, потом номер файла внутри дня
    captures.sort(key=lambda c: (_day_key(c.day), c.capture_id))
    return captures


def ctu13_scenario_dir(cfg: DataConfig, scenario: int) -> Path:
    return cfg.ctu13.root / str(scenario)


def discover_ctu13(cfg: DataConfig) -> list[Capture]:
    """PCAP CTU-13: по одному на папку сценария `1`…`13` → `ctu13_07`."""
    captures = []
    for scenario in sorted(CTU13_FAMILIES):
        folder = ctu13_scenario_dir(cfg, scenario)
        if not folder.is_dir():
            # Не падаем: можно работать с частью сценариев. Полноту проверяет сводка
            # (в ней будет меньше 13 строк) и разбиение, которое требует все сценарии
            log.warning("CTU-13: нет папки сценария %s — пропускаю", folder)
            continue
        pcaps = sorted(p for pattern in PCAP_PATTERNS for p in folder.glob(pattern))
        if len(pcaps) != 1:
            raise FileNotFoundError(
                f"CTU-13, сценарий {scenario}: ожидался ровно один PCAP в {folder}, "
                f"найдено {len(pcaps)}"
            )
        captures.append(
            Capture(
                capture_id=f"ctu13_{scenario:02d}",
                source="ctu13",
                path=pcaps[0],
                scenario=scenario,
                family=CTU13_FAMILIES[scenario],
            )
        )
    if not captures:
        raise FileNotFoundError(f"в {cfg.ctu13.root} не найдено ни одной папки сценария CTU-13")
    return captures


def discover(cfg: DataConfig, dataset: str) -> list[Capture]:
    if dataset == "unsw":
        return discover_unsw(cfg)
    if dataset == "ctu13":
        return discover_ctu13(cfg)
    raise ValueError(f"неизвестный датасет: {dataset!r}")


def normalize_capture_arg(dataset: str, value: str) -> str:
    """Переводит короткую запись из командной строки в capture_id.

    UNSW: `22-1-2015:1` → `unsw_22-1-2015_01`; CTU-13: `7` → `ctu13_07`.
    Полный capture_id тоже принимается как есть.
    """
    value = value.strip()
    if value.startswith(f"{dataset}_"):
        return value
    if dataset == "ctu13" and value.isdigit():
        return f"ctu13_{int(value):02d}"
    if dataset == "unsw":
        m = re.fullmatch(r"(\d{1,2}-\d{1,2}-\d{4}):(\d+)", value)
        if m:
            return f"unsw_{m.group(1)}_{int(m.group(2)):02d}"
    raise ValueError(
        f"не понимаю захват {value!r}: для UNSW пишите `22-1-2015:1`, для CTU-13 — номер сценария"
    )
