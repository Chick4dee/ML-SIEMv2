"""Прогон: вход (часть разбиения или PCAP) → вердикты → алерты → инциденты → действия → БД.

Одна точка входа `run_chain()` для обоих сценариев спеки (FR-026, FR-027, research R13):
- `split:<имя>/<часть>` — потоки части разбиения 001 (join разбиения с потоками), в
  хронологическом порядке; `limit` — первые N по времени начала;
- `pcap:<путь>` — признаки извлекаются экстрактором 001 (та же схема, те же настройки
  nfstream) в `var/runs/<run_id>/flows.parquet`, дальше тот же путь.

Порядок безопасен: сначала загрузка детектора и все проверки (версия схемы, признаки,
таблица серьёзности) — и только потом какая-либо обработка и запись. В БД прогон попадает
одной транзакцией в самом конце; если что-то упало раньше, каталог прогона удаляется и в
хранилище нет никаких следов.
"""

from __future__ import annotations

import logging
import shutil
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import polars as pl

from mlsiem.data.captures import atomic_path
from mlsiem.data.extract import content_hash, read_parquet_metadata, write_flows_parquet
from mlsiem.data.schema import SCHEMA
from mlsiem.detect.artifact import Detector, load_detector
from mlsiem.detect.dataset import flow_files, scan_part
from mlsiem.detect.metrics import BENIGN
from mlsiem.soc import store
from mlsiem.soc.config import SEVERITY_LEVELS, SocConfig
from mlsiem.soc.incidents import group_alerts
from mlsiem.soc.playbooks import propose_action
from mlsiem.soc.verdicts import ALERT_CONTEXT, alerts_from_verdicts, compute_verdicts

log = logging.getLogger("mlsiem")
FIRST = "bidirectional_first_seen_ms"


@dataclass
class RunSummary:
    run_id: str
    source: str
    detector_version: str
    n_flows: int
    n_alerts: int
    n_incidents: int
    incidents_by_severity: dict[str, int]
    actions_by_type: dict[str, int]
    # Только для размеченного входа: сколько алертов — действительно атаки
    alerts_true: int | None = None
    alerts_true_share: float | None = None
    alerts_class_match_share: float | None = None
    warnings: list[str] = field(default_factory=list)
    seconds: float = 0.0
    run_dir: Path | None = None


def parse_source(source: str) -> tuple[str, str]:
    kind, _, rest = source.partition(":")
    if kind not in ("split", "pcap") or not rest:
        raise ValueError(
            f"не понимаю источник {source!r}: ожидалось split:<имя>/<часть> или pcap:<файл>"
        )
    return kind, rest


# ---------------------------------------------------------------- загрузка входа


def _needed_columns(detector: Detector) -> list[str]:
    cols = list(ALERT_CONTEXT)
    cols += [f for f in detector.features if f not in cols]
    return cols


def load_split_flows(
    split: str, part: str, detector: Detector, *, data_dir: Path, limit: int | None = None
) -> tuple[pl.DataFrame, str | None]:
    """Потоки части разбиения + версия схемы их parquet. Метка берётся только для сводки."""
    files = flow_files(split, data_dir)
    versions = {read_parquet_metadata(f).get("mlsiem.schema_version") for f in files}
    if len(versions) != 1:
        raise ValueError(
            f"потоки разбиения {split} записаны разными версиями схемы: "
            f"{sorted(map(str, versions))}"
        )
    lazy = scan_part(split, part, data_dir=data_dir, columns=[*_needed_columns(detector), "label"])
    if limit is not None:
        lazy = lazy.sort([FIRST, "flow_uid"]).head(limit)
    return lazy.collect(), versions.pop()


def _check_pcap_path(pcap: Path) -> None:
    # Только явные расширения: рядом с PCAP CTU-13 лежат настоящие бинарники ботнетов
    if pcap.suffix.lower() not in (".pcap", ".pcapng"):
        raise ValueError(f"ожидался файл .pcap или .pcapng, а передан {pcap.name}")
    if not pcap.is_file():
        raise ValueError(f"нет файла {pcap}")


def load_pcap_flows(pcap: Path, run_dir: Path) -> tuple[pl.DataFrame, list[str]]:
    """PCAP → потоки экстрактором 001; пишет `flows.parquet` с версией схемы в метаданных."""
    from mlsiem.data.extract import extract_flows

    pcap = Path(pcap)
    _check_pcap_path(pcap)
    capture_id = "adhoc_" + pcap.stem.replace(":", "_")
    result = extract_flows(pcap, capture_id, workdir=run_dir)
    write_flows_parquet(result.df, run_dir / "flows.parquet", {"mlsiem.capture_id": capture_id})
    return result.df, list(result.warnings)


# ---------------------------------------------------------------- прогон


def _check_detector_classes(detector: Detector, cfg: SocConfig) -> None:
    """Каждому классу атаки детектора нужен базовый уровень серьёзности — проверяем заранее."""
    missing = [c for c in detector.classes if c != BENIGN and c not in cfg.severity_base]
    if missing:
        raise ValueError(
            f"в configs/soc.yaml (severity.base) нет уровня для классов детектора: {missing}"
        )


def run_chain(
    source: str,
    cfg: SocConfig,
    *,
    detector_dir: Path = Path("models/detector"),
    data_dir: Path = Path("data"),
    limit: int | None = None,
) -> RunSummary:
    """Весь прогон одной командой. Возвращает сводку; состояние — в БД и `runs_dir/<run_id>/`."""
    started_perf = time.perf_counter()
    started_at = store.now_iso()
    kind, rest = parse_source(source)

    # 1. Детектор и проверки — до любой обработки: при ошибке ничего не создано
    detector = load_detector(detector_dir)
    _check_detector_classes(detector, cfg)
    if kind == "pcap":
        _check_pcap_path(Path(rest))
    conn = store.connect(cfg.db)
    store.init_db(conn)

    tmp_dir = Path(cfg.runs_dir) / f".pending-{int(time.time() * 1000)}"
    run_dir: Path | None = None
    try:
        warnings: list[str] = []
        if kind == "split":
            split, _, part = rest.partition("/")
            if not part:
                raise ValueError(f"в источнике {source!r} нет части: ожидалось split:<имя>/<часть>")
            log.info("Загружаю потоки %s/%s…", split, part)
            flows, schema_version = load_split_flows(
                split, part, detector, data_dir=Path(data_dir), limit=limit
            )
            detector.check_input(schema_version, flows.columns)
            source_label = f"split:{split}/{part}"
        else:
            pcap = Path(rest)
            log.info("Извлекаю потоки из %s экстрактором 001…", pcap.name)
            tmp_dir.mkdir(parents=True, exist_ok=True)
            flows, warnings = load_pcap_flows(pcap, tmp_dir)
            detector.check_parquet(tmp_dir / "flows.parquet")
            source_label = f"pcap:{pcap.name}"
            if limit is not None:
                flows = flows.sort([FIRST, "flow_uid"]).head(limit)
        flows = flows.sort("flow_uid")

        input_hash = content_hash(flows.select(_needed_columns(detector)))
        run_id = store.new_run_id(conn, input_hash)
        run_dir = Path(cfg.runs_dir) / run_id

        # 2. Вердикты → алерты → инциденты → предложения
        log.info("Вердикты детектора %s для %d потоков…", detector.version, flows.height)
        verdicts = compute_verdicts(detector, flows)
        if tmp_dir.exists():
            tmp_dir.rename(run_dir)
        with atomic_path(run_dir / "verdicts.parquet") as tmp:
            verdicts.write_parquet(tmp)

        log.info("Группировка алертов в инциденты…")
        alerts = alerts_from_verdicts(verdicts, flows)
        alerts, incidents = group_alerts(
            alerts,
            window_ms=cfg.window_ms,
            run_id=run_id,
            severity_base=cfg.severity_base,
            bump_at=cfg.bump_at,
        )
        incident_rows = incidents.to_dicts()
        actions = [propose_action(i, cfg.rules, cfg.protected_ips) for i in incident_rows]

        # 3. Сводка
        by_severity = Counter(i["severity"] for i in incident_rows)
        by_action = Counter(a["action_type"] for a in actions)
        summary = RunSummary(
            run_id=run_id,
            source=source_label,
            detector_version=detector.version,
            n_flows=flows.height,
            n_alerts=alerts.height,
            n_incidents=len(incident_rows),
            incidents_by_severity={s: by_severity.get(s, 0) for s in reversed(SEVERITY_LEVELS)},
            actions_by_type=dict(sorted(by_action.items())),
            warnings=warnings,
            run_dir=run_dir,
        )
        if "true_label" in alerts.columns and alerts.height:
            true_attack = int((alerts["true_label"] != BENIGN).sum())
            summary.alerts_true = true_attack
            summary.alerts_true_share = true_attack / alerts.height
            summary.alerts_class_match_share = float(
                (alerts["true_label"] == alerts["predicted_class"]).mean()
            )

        # 4. Запись одной транзакцией
        log.info("Запись прогона %s в %s…", run_id, cfg.db)
        alert_rows = alerts.select(
            [*ALERT_CONTEXT.values(), "predicted_class", "attack_score", "incident_id"]
        ).to_dicts()
        store.write_run(
            conn,
            {
                "run_id": run_id,
                "source": source_label,
                "input_hash": input_hash,
                "detector_version": detector.version,
                "limit": limit,
                "started_at": started_at,
                "n_flows": flows.height,
                "summary": {
                    "incidents_by_severity": summary.incidents_by_severity,
                    "actions_by_type": summary.actions_by_type,
                    "alerts_true": summary.alerts_true,
                    "alerts_true_share": summary.alerts_true_share,
                    "alerts_class_match_share": summary.alerts_class_match_share,
                    "schema_version": SCHEMA.version,
                    # Фича 003: консоль показывает порог рядом с вероятностями алерта, а
                    # классы — в порядке столбцов p_<класс> в verdicts.parquet. Пишем их
                    # в прогон, потому что детектор в models/ потом могут заменить
                    "threshold": float(detector.threshold),
                    "classes": list(detector.classes),
                },
                "warnings": warnings,
            },
            alert_rows,
            incident_rows,
            actions,
        )
    except BaseException:
        # Прогон не записан в БД (транзакция откатилась или до неё не дошли) — не оставляем
        # на диске и его файлов, чтобы не было «полупрогонов»
        for d in (run_dir, tmp_dir):
            if d is not None and d.exists():
                shutil.rmtree(d, ignore_errors=True)
        raise
    finally:
        conn.close()
    summary.seconds = time.perf_counter() - started_perf
    return summary
