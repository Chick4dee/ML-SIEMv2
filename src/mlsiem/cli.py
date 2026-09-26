"""Точка входа `mlsiem`. Группы: `data` (фича 001), `detect` и `soc` (фича 002),
`stand` и `stream` (фича 005: брокерная машина и потоковая обработка через Kafka).

Договорённости (contracts/cli.md):
- прогресс и предупреждения — в stderr, итоговая сводка — в stdout;
- коды возврата: 0 — успех; 1 — ошибка входных данных, конфига или нехватка ресурсов
  (прогон прерван целиком); 2 — часть захватов не прочиталась, остальные обработаны.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import logging
import sys
from pathlib import Path

log = logging.getLogger("mlsiem")

EXIT_OK, EXIT_ERROR, EXIT_PARTIAL = 0, 1, 2


def _setup_logging() -> None:
    # Когда вывод идёт в пайп (DVC, перенаправление в файл), Windows даёт ему кодировку cp1251,
    # в которой нет «≥», «→» и т. п. — и print падал бы посреди готового результата.
    # Непредставимый символ лучше заменить «?», чем уронить команду
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(errors="replace")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.handlers[:] = [handler]
    log.setLevel(logging.INFO)
    log.propagate = False


def _out(text: str = "") -> None:
    print(text, flush=True)


# ---------------------------------------------------------------- подкоманды


def cmd_flows(args, cfg) -> int:
    from mlsiem.data.captures import normalize_capture_arg
    from mlsiem.data.pipeline import run_flows

    only = [normalize_capture_arg(args.dataset, c) for c in args.capture] if args.capture else None
    summary = run_flows(
        cfg,
        args.dataset,
        only=only,
        force=args.force,
        full_hash=args.full_hash,
        data_dir=Path(args.data_dir),
    )
    total = sum(r["n_flows"] or 0 for r in summary.rows)
    matched = sum(r["n_matched"] or 0 for r in summary.rows)
    _out(
        f"Датасет {args.dataset}: захватов {len(summary.rows)}, "
        f"готово {summary.n_done}, пропущено {summary.n_skipped}, ошибок {summary.n_failed}"
    )
    rate = f"{matched / total:.4f}" if total else "—"
    _out(f"Потоков всего: {total}, сопоставлено с разметкой: {matched} (доля {rate})")
    if summary.label_counts:
        _out("Классы:")
        for name, count in sorted(summary.label_counts.items(), key=lambda kv: -kv[1]):
            _out(f"  {name:<16} {count}")
    for r in summary.rows:
        if r["status"] == "failed":
            _out(f"ОШИБКА {r['capture_id']}: {r['error']}")
    return EXIT_PARTIAL if summary.n_failed else EXIT_OK


def cmd_extract(args, cfg) -> int:
    from mlsiem.data.pipeline import run_extract

    result = run_extract(Path(args.pcap), Path(args.output), workdir=Path(args.data_dir) / "tmp")
    _out(
        f"Записано {result['n_flows']} потоков в {args.output} "
        f"(схема {result['schema_version']}, capture_id {result['capture_id']})"
    )
    for w in result["warnings"]:
        _out(f"Предупреждение: {w}")
    return EXIT_OK


def cmd_split(args, cfg) -> int:
    from mlsiem.data.split import build_split

    manifest = build_split(cfg, args.name, data_dir=Path(args.data_dir))
    _out(f"Разбиение {args.name} (hash {manifest['hash'][:12]}…): инварианты соблюдены")
    for part in ("train", "val", "test"):
        info = manifest["parts"][part]
        classes = ", ".join(f"{k}={v}" for k, v in sorted(info["label_counts"].items()))
        _out(f"  {part:<5} потоков {info['n_flows']:>9}  [{classes}]")
    excluded = manifest["excluded"]
    _out(
        f"Исключено зазором: {excluded['total']} "
        f"({', '.join(f'{k}={v}' for k, v in sorted(excluded['by_label'].items())) or '—'})"
    )
    for part, missing in manifest["missing_classes"].items():
        if missing:
            _out(f"В части {part} нет классов: {', '.join(missing)}")
    return EXIT_OK


def cmd_audit(args, cfg) -> int:
    from mlsiem.data.audit import run_audit

    result = run_audit(cfg, args.split, data_dir=Path(args.data_dir))
    flagged = result.filter(result["status"].is_in(["dangerous", "suspicious"])).sort(
        ["status", "lift"], descending=True
    )
    _out(
        f"Аудит {args.split}: проверено полей {result.height}, "
        f"опасных {int((result['status'] == 'dangerous').sum())}, "
        f"подозрительных {int((result['status'] == 'suspicious').sum())}"
    )
    if result.height and (result["status"] == "n/a").all():
        _out("Аудит невозможен: в val меньше двух классов (см. отсутствующие классы разбиения)")
    _out(
        f"Порог dangerous: lift ≥ {cfg.audit.dangerous_lift}; "
        f"suspicious: PR-AUC ≥ {cfg.audit.suspicious_pr_auc}"
    )
    for r in flagged.iter_rows(named=True):
        _out(
            f"  {r['status']:<10} {r['field']:<34} {r['variant']:<8} "
            f"PR-AUC {r['pr_auc_macro']:.3f}  база {r['baseline']:.3f}  lift {r['lift']:+.3f}"
        )
    return EXIT_OK


def cmd_compare_v1(args, cfg) -> int:
    from mlsiem.data.compare_v1 import run_compare

    v1_dir = Path(args.v1_dir) if args.v1_dir else cfg.v1_processed_dir
    table, unexplained = run_compare(cfg, v1_dir=v1_dir, data_dir=Path(args.data_dir))
    _out(f"Сверка с v1: захватов {table.height}, необъяснённых расхождений {len(unexplained)}")
    for r in unexplained:
        _out(f"  {r['capture_id']}: {r['reason']}")
    return EXIT_OK


def cmd_report(args, cfg) -> int:
    from mlsiem.data.report.build import build_report

    html, md = build_report(cfg, data_dir=Path(args.data_dir), output=Path(args.output))
    _out(f"Отчёт: {html}\nСводка: {md}")
    return EXIT_OK


def cmd_all(args, cfg) -> int:
    import shutil
    import subprocess

    if not Path(".dvc").is_dir():
        log.error(
            "DVC не инициализирован в этой папке: запустите `uv run dvc init` из корня "
            "репозитория (см. quickstart)"
        )
        return EXIT_ERROR
    dvc = shutil.which("dvc")
    cmd = [dvc, "repro"] if dvc else [sys.executable, "-m", "dvc", "repro"]
    log.info("Запускаю весь конвейер: %s", " ".join(cmd))
    return EXIT_OK if subprocess.call(cmd) == 0 else EXIT_ERROR


# ---------------------------------------------------------------- фича 002: detect и soc


def cmd_detect_train(args, cfg) -> int:
    from mlsiem.detect.experiment import run_experiment

    exp = run_experiment(
        cfg,
        data_dir=Path(args.data_dir),
        reports_dir=Path(args.reports_dir),
        mlflow_dir=Path(args.mlflow_dir),
    )

    def f(v) -> str:
        return "—" if v is None else f"{v:.4f}"

    _out(f"Эксперимент на {exp['split']} (сид {exp['seed']}), детектор {exp['detector_version']}")
    _out(f"  {'кандидат':<22} {'PR-AUC val':>10} {'PR-AUC test':>11} {'порог':>7} {'F1 test':>8}")
    for c in exp["candidates"]:
        _out(
            f"  {c['name']:<22} {f(c['val']['macro_pr_auc']):>10} "
            f"{f(c['test']['macro_pr_auc']):>11} "
            f"{c['threshold']:>7.4f} {f(c['test']['binary']['f1']):>8}"
        )
    prior = exp["prior_baseline"]
    _out(
        f"  {'prior (доли классов)':<22} {f(prior['val']['macro_pr_auc']):>10} "
        f"{f(prior['test']['macro_pr_auc']):>11}"
    )
    _out(f"Победитель: {exp['winner']} — {exp['selection_rule']['text']}")
    t = exp["transfer"]
    _out(
        f"Перенос на test {t['split']}: macro PR-AUC {f(t['macro_pr_auc'])}, "
        f"precision {f(t['binary']['precision'])}, recall {f(t['binary']['recall'])}, "
        f"F1 {f(t['binary']['f1'])}"
    )
    for part, missing in exp["classes_without_examples"].items():
        if missing:
            _out(f"Нет примеров в {part}: {', '.join(missing)} (PR-AUC не считается)")
    _out(f"Артефакт: {cfg.output}; отчёт: {Path(args.reports_dir) / 'detector_experiment.md'}")
    return EXIT_OK


def cmd_detect_ensemble(args, cfg) -> int:
    """Эксперимент 004: эксперты + мета-слой против лучшего одиночного эксперта."""
    from mlsiem.detect.artifact import DetectorLoadError
    from mlsiem.detect.ensemble import REPORT_NAME, VARIANT_TITLES, run_ensemble_experiment

    try:
        exp = run_ensemble_experiment(
            cfg,
            data_dir=Path(args.data_dir),
            reports_dir=Path(args.reports_dir),
            mlflow_dir=Path(args.mlflow_dir),
        )
    except DetectorLoadError as exc:
        log.error("Классификатор не загружается: %s", exc)
        return EXIT_ERROR

    def f(v) -> str:
        return "—" if v is None else f"{v:.4f}"

    def p(v) -> str:
        return "—" if v is None else f"{v:.1%}"

    _out(
        f"Эксперимент ансамбля на {exp['split']} (сид {exp['seed']}), "
        f"версия {exp['ensemble_version']}"
    )
    _out(
        f"  {'вариант':<38} {'macro val':>9} {'macro test':>10} {'атака/нет val':>13} "
        f"{'порог':>7} {'F1 test':>8}"
    )
    for v in exp["variants"]:
        _out(
            f"  {VARIANT_TITLES.get(v['name'], v['name']):<38} {f(v['val']['macro_pr_auc']):>9} "
            f"{f(v['test']['macro_pr_auc']):>10} {f(v['val']['pr_auc_binary']):>13} "
            f"{v['threshold']:>7.4f} {f(v['test']['binary']['f1']):>8}"
        )
    an = exp["experts"]["anomaly"]
    _out("Детектор аномалий (PR-AUC «атака/не атака» val / test, норма val выше порога):")
    for c in an["candidates"]:
        _out(
            f"  {c['name']:<12} {f(c['val']['pr_auc_binary'])} / {f(c['test']['pr_auc_binary'])}, "
            f"{p(c['val']['benign_above_threshold'])}"
        )
    _out(f"  выбран {an['winner']} — {an['selection_text']}")
    cands = exp["config"]["meta"]["candidates"]
    _out("Скрытый класс — поимка val / test (классификатор без класса | аномалии | варианты):")
    for h in exp["hidden_class"]:
        c = h["catch"]
        rest = ", ".join(
            f"{v} {p(h['variants'][v]['val'])} / {p(h['variants'][v]['test'])}" for v in cands
        )
        _out(
            f"  {h['class']:<10} {p(c['classifier_without_class']['val'])} / "
            f"{p(c['classifier_without_class']['test'])} | {p(c['anomaly']['val'])} / "
            f"{p(c['anomaly']['test'])} | {rest}"
        )
    sel = exp["selection"]
    condition = {
        "macro_gain": "macro_gain (прирост macro PR-AUC)",
        "unknown_gain": "unknown_gain (поимка скрытых классов)",
        "none": "ни одно — одиночный эксперт",
    }.get(sel["condition"], sel["condition"])
    _out(f"Выбрано: {sel['selected']}; условие: {condition}")
    _out(f"  {sel['text']}")
    flagged = ((exp["audit"].get("anomaly") or {}).get("flagged_features")) or []
    if flagged:
        _out(f"Аудит: подозрение на артефакт — признаки {', '.join(flagged)} (см. отчёт)")
    else:
        _out("Аудит: признаков, в одиночку отделяющих атаки, не найдено")
    _out(
        f"Артефакты: {cfg.output_anomaly}, {cfg.output_ensemble}; "
        f"отчёт: {Path(args.reports_dir) / REPORT_NAME}"
    )
    return EXIT_OK


EXPERT_TITLES = {
    "classifier": "классификатор",
    "anomaly": "детектор аномалий",
    "meta_only": "только мета-слой",
}


def _print_run_summary(s) -> None:
    model = s.model or f"детектор {s.detector_version}"
    _out(f"Прогон {s.run_id} ({s.source}), модель: {model}, {s.seconds:.1f} с")
    _out(f"  потоков {s.n_flows}, алертов {s.n_alerts}, инцидентов {s.n_incidents}")
    if s.alerts_by_expert:
        by = ", ".join(f"{EXPERT_TITLES.get(k, k)} {v}" for k, v in s.alerts_by_expert.items())
        _out(f"  алертов по экспертам: {by} (алерт двух экспертов учтён у обоих)")
    _out(f"  ответных потоков среди алертов: {s.n_reversed} (направление: {s.direction_mode})")
    if s.n_anomaly_incidents:
        _out(
            f"  инцидентов класса anomaly (класс атаки неизвестен): {s.n_anomaly_incidents} — "
            "для них предложен только ручной разбор"
        )
    if s.n_incidents == 0:
        _out("  Атак не найдено — инцидентов нет.")
    else:
        sev = ", ".join(f"{k} {v}" for k, v in s.incidents_by_severity.items())
        _out(f"  инциденты по серьёзности: {sev}")
        acts = ", ".join(f"{k} {v}" for k, v in s.actions_by_type.items())
        _out(f"  предложенные действия: {acts} (выполняются только после подтверждения)")
    if s.alerts_true_share is not None:
        _out(
            f"  верных алертов (это действительно атака): {s.alerts_true} из {s.n_alerts} "
            f"({s.alerts_true_share:.1%}); класс угадан у {s.alerts_class_match_share:.1%}"
        )
    for w in s.warnings:
        _out(f"  Предупреждение: {w}")


def cmd_soc_run(args, cfg) -> int:
    from mlsiem.soc.run import run_chain

    if args.pcap and (args.split or args.part):
        log.error("укажите либо --pcap, либо --split/--part, но не всё сразу")
        return EXIT_ERROR
    if args.pcap:
        source = f"pcap:{args.pcap}"
    elif args.split and args.part:
        source = f"split:{args.split}/{args.part}"
    else:
        log.error("нужен вход: --split <имя> --part <часть> или --pcap <файл>")
        return EXIT_ERROR
    if args.limit is not None and args.limit <= 0:
        log.error("--limit должен быть положительным числом")
        return EXIT_ERROR
    from mlsiem.data.extract import ExtractError

    try:
        summary = run_chain(
            source,
            cfg,
            model_dir=_model_dir(args),
            data_dir=Path(args.data_dir),
            limit=args.limit,
        )
    except ExtractError as exc:
        log.error("Ошибка извлечения потоков: %s", exc)
        return EXIT_ERROR
    _print_run_summary(summary)
    return EXIT_OK


def cmd_soc_review(args, cfg) -> int:
    """Разбор инцидентов с адресов жертв/фона и сравнение прогонов (фича 004, US4)."""
    from mlsiem.soc import store
    from mlsiem.soc.review import review_sources, summary_line, write_review

    if not cfg.db.exists():
        log.error("Хранилище %s пустое: прогонов нет", cfg.db)
        return EXIT_ERROR
    conn = store.connect(cfg.db)
    try:
        store.init_db(conn)
        try:
            report = review_sources(conn, cfg, args.run, args.after, data_dir=Path(args.data_dir))
        except store.NotFound as exc:
            log.error("Ошибка: %s", exc.message)
            return EXIT_ERROR
    finally:
        conn.close()
    md, js = write_review(report, Path(args.reports_dir))
    _out(f"Разбор прогона {args.run}" + (f" (после: {args.after})" if args.after else ""))
    _out(f"  {summary_line(report)}")
    kept = report.get("attackers_kept")
    if kept and kept["lost"]:
        lost = ", ".join(f"{x['ip']}/{x['class']}" for x in kept["lost"])
        _out(f"  ПОТЕРЯНЫ АТАКУЮЩИЕ: {lost}")
    _out(f"Отчёт: {md}; данные: {js}")
    return EXIT_OK


DEFAULT_ENSEMBLE = Path("models/ensemble")
DEFAULT_DETECTOR = Path("models/detector")


def _model_dir(args, *, quiet: bool = False) -> Path:
    """Каталог модели прогона (фича 004, contracts/cli.md).

    `--model` и `--detector` — синонимы (второй остался от 002/003). Без них — ансамбль из
    models/ensemble, если он обучен, иначе детектор 002 и предупреждение об этом.
    """
    chosen = getattr(args, "model", None) or getattr(args, "detector", None)
    if chosen:
        return Path(chosen)
    if (DEFAULT_ENSEMBLE / "ensemble_card.json").exists():
        return DEFAULT_ENSEMBLE
    if not quiet:
        log.warning(
            "Ансамбль не обучен (нет %s/ensemble_card.json) — прогон одиночным детектором %s",
            DEFAULT_ENSEMBLE.as_posix(),
            DEFAULT_DETECTOR.as_posix(),
        )
    return DEFAULT_DETECTOR


LOCAL_HOSTS = ("127.0.0.1", "localhost")


def cmd_soc_serve(args, cfg) -> int:
    import uvicorn

    from mlsiem.soc.api import create_app

    # Аутентификации в API нет, поэтому наружу его не открываем ни при каких настройках
    if cfg.api.host not in LOCAL_HOSTS:
        log.error(
            "API без аутентификации слушает только 127.0.0.1, а в configs/soc.yaml указан "
            "api.host = %s — исправьте конфиг",
            cfg.api.host,
        )
        return EXIT_ERROR
    from mlsiem.soc.store import SCHEMA_VERSION, SchemaTooNew

    port = args.port or cfg.api.port
    try:
        # create_app сам приводит базу к схеме фичи 003 (миграция 002 → 2 одной транзакцией)
        app = create_app(cfg, detector_dir=_model_dir(args, quiet=True))
    except SchemaTooNew as exc:
        log.error("Нельзя открыть %s: %s", cfg.db, exc.message)
        return EXIT_ERROR
    if app.state.migrated:
        log.info(
            "Схема базы %s обновлена до версии %d (прогоны, решения и аудит сохранены целиком; "
            "старые прогоны открываются с пометкой «до ансамбля»)",
            cfg.db,
            SCHEMA_VERSION,
        )
    log.info("Консоль аналитика: http://127.0.0.1:%d/", port)
    log.info(
        "API аналитика: http://127.0.0.1:%d/api/v1 (документация: http://127.0.0.1:%d/docs)",
        port,
        port,
    )
    log.info("База: %s. Остановить — Ctrl+C.", cfg.db)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return EXIT_OK


def cmd_soc_status(args, cfg) -> int:
    from mlsiem.soc import store

    if not cfg.db.exists():
        _out(f"Хранилище {cfg.db} пустое: прогонов ещё не было (`mlsiem soc run`)")
        return EXIT_OK
    conn = store.connect(cfg.db)
    try:
        store.init_db(conn)
        runs = store.list_runs(conn)
    finally:
        conn.close()
    _out(f"Прогонов в {cfg.db}: {len(runs)}")
    for r in runs:
        st = r["incidents_by_status"]
        m = r["model"]
        model = (
            f"ансамбль {m['version']} ({m['selected']})"
            if m["kind"] == "ensemble"
            else f"детектор {m['version']}"
        )
        # Фича 005: у онлайн-сеанса — режим и статус; строки пакетных прогонов прежние
        if r.get("mode") == "stream":
            titles = {"running": "идёт", "stopped": "остановлен", "completed": "завершён"}
            model += f"  поток, {titles.get(r['status'], r['status'])}"
        _out(
            f"  {r['run_id']}  {r['source']:<24} {r['started_at']}  "
            f"{model}  "
            f"инцидентов {r['n_incidents']} (new {st['new']}, in_progress {st['in_progress']}, "
            f"closed {st['closed']})"
        )
    return EXIT_OK


# ---------------------------------------------------------------- фича 005: stand и stream


def cmd_stand_seed_iso(args, cfg) -> int:
    """Seed-ISO автоустановки брокерной машины — только файл, система не меняется."""
    from mlsiem.stand.seed import DEFAULT_PUBKEY, build_seed_iso, read_pubkey

    key = read_pubkey(Path(args.pubkey) if args.pubkey else DEFAULT_PUBKEY)
    out = build_seed_iso(cfg, key, Path(args.out))
    size_kb = out.stat().st_size / 1024
    _out(f"Seed-ISO: {out} ({size_kb:.0f} КБ, метка тома CIDATA)")
    _out(
        f"  машина {cfg.stand.vm_name}: адрес {cfg.stand.broker_ip}/{cfg.stand.prefix}, "
        f"Kafka {cfg.stand.kafka_version}, пользователь {cfg.stand.admin_user} (вход по ключу)"
    )
    _out("Дальше: stand/hyperv/20-vm-broker.ps1 -Iso <образ Ubuntu> (от администратора)")
    return EXIT_OK


def cmd_stand_check(args, cfg) -> int:
    from mlsiem.stand.check import stand_check
    from mlsiem.stream import broker as broker_mod

    report = stand_check(cfg, lambda: broker_mod.make_broker(cfg, "check"))
    for line in report.lines:
        _out(line)
    for w in report.warnings:
        _out(f"Предупреждение: {w}")
    if report.ok:
        _out("Стенд в порядке: брокер доступен из служебной сети, топики на месте.")
        return EXIT_OK
    _out("Проблемы:")
    for p in report.problems:
        _out(f"  - {p}")
    return EXIT_ERROR


def cmd_stream_replay(args, cfg) -> int:
    import tempfile

    from mlsiem.stream import broker as broker_mod
    from mlsiem.stream.config import parse_speed
    from mlsiem.stream.replay import (
        ReplayError,
        find_resume,
        load_pcap_source,
        load_split_source,
        new_source_id,
        replay,
    )

    if args.pcap and (args.split or args.part):
        log.error("укажите либо --pcap, либо --split/--part, но не всё сразу")
        return EXIT_ERROR
    if not args.pcap and not (args.split and args.part):
        log.error("нужен вход: --split <имя> --part <часть> или --pcap <файл>")
        return EXIT_ERROR
    if args.limit is not None and args.limit <= 0:
        log.error("--limit должен быть положительным числом")
        return EXIT_ERROR
    speed = parse_speed(args.speed, "--speed") if args.speed else cfg.replay.default_speed

    with tempfile.TemporaryDirectory(prefix="mlsiem-replay-") as tmp:
        try:
            if args.pcap:
                log.info("Извлекаю потоки из %s экстрактором 001…", Path(args.pcap).name)
                source = load_pcap_source(Path(args.pcap), Path(tmp))
                if args.limit:
                    source.flows = source.flows.head(args.limit)
            else:
                source = load_split_source(
                    args.split, args.part, data_dir=Path(args.data_dir), limit=args.limit
                )
        except ReplayError as exc:
            log.error("Ошибка: %s", exc)
            return EXIT_ERROR
        for w in source.warnings:
            log.warning("Предупреждение: %s", w)

        broker = broker_mod.make_broker(cfg, "replay")
        try:
            broker.ping()
            if cfg.topics.flows not in broker.list_topics():
                log.error(
                    "На брокере нет топика %s — проверьте стенд: uv run mlsiem stand check",
                    cfg.topics.flows,
                )
                return EXIT_ERROR
            first_seq = 0
            if args.resume:
                source_id = args.resume
                first_seq, ended = find_resume(broker, cfg.topics.flows, source_id)
                if ended:
                    _out(f"Источник {source_id} уже отправлен целиком (есть отметка end)")
                    return EXIT_OK
                log.info("Продолжаю %s с потока seq=%d из %d", source_id, first_seq, source.total)
            else:
                source_id = new_source_id(source.label)
            tempo = "max (без пауз)" if speed is None else f"×{speed:g}"
            log.info("Проигрываю %s: %d потоков, темп %s", source.label, source.total, tempo)

            def progress(sent, total, rate, behind):
                log.info(
                    "  отправлено %d из %d, %.0f потоков/с, отставание от графика %.1f с",
                    sent,
                    total,
                    rate,
                    behind,
                )

            summary = replay(
                source,
                broker,
                cfg.topics.flows,
                source_id=source_id,
                speed=speed,
                first_seq=first_seq,
                on_progress=progress,
                progress_interval_s=cfg.replay.progress_interval_s,
            )
        except broker_mod.BrokerUnavailable as exc:
            log.error("Ошибка: %s", exc)
            return EXIT_ERROR
        except ReplayError as exc:
            log.error("Ошибка: %s", exc)
            return EXIT_ERROR
        finally:
            broker.close()
    _out(f"source_id: {summary.source_id}")
    _out(
        f"  отправлено {summary.sent} из {summary.total} потоков (+ отметка end) "
        f"за {summary.seconds:.1f} с, {summary.rate:.0f} потоков/с"
    )
    return EXIT_OK


def _load_soc_for_stream(args):
    from mlsiem.soc.config import load_soc_config

    return load_soc_config(args.soc_config)


def cmd_stream_consume(args, cfg) -> int:
    import signal

    from mlsiem.detect.artifact import DetectorLoadError
    from mlsiem.soc import store
    from mlsiem.stream import broker as broker_mod
    from mlsiem.stream.consumer import ConsumerStopped, consume

    soc = _load_soc_for_stream(args)
    stopping = {"flag": False}

    def on_sigint(signum, frame):
        # Первый Ctrl+C — доделать текущую пачку, записать, подтвердить и выйти; второй —
        # прервать сразу (незаписанная пачка просто прочитается снова при следующем запуске)
        if stopping["flag"]:
            raise KeyboardInterrupt
        stopping["flag"] = True
        log.info("Останавливаюсь: доделываю текущую пачку… (ещё раз Ctrl+C — прервать сразу)")

    previous = signal.signal(signal.SIGINT, on_sigint)
    broker = broker_mod.make_broker(cfg, "consumer")
    try:
        log.info("Потребитель: брокер %s, база %s", cfg.broker.bootstrap, soc.db)
        summary = consume(
            cfg,
            soc,
            broker=broker,
            model_dir=_model_dir(args),
            once=args.once,
            stop=lambda: stopping["flag"],
            on_report=log.info,
        )
    except store.LeaseHeld as exc:
        log.error("Ошибка: %s", exc.message)
        return EXIT_ERROR
    except (ConsumerStopped, broker_mod.BrokerUnavailable, DetectorLoadError) as exc:
        log.error("Ошибка: %s", exc)
        return EXIT_ERROR
    finally:
        signal.signal(signal.SIGINT, previous)
        broker.close()
    _out(
        f"Потребитель остановлен: пачек {summary.batches}, сообщений {summary.messages}, "
        f"обработано потоков {summary.processed}, повторов отброшено {summary.duplicates}, "
        f"отвергнуто {summary.rejected}"
    )
    for st in summary.sessions.values():
        _out(
            f"  {st.run_id} ({st.source_id}): потоков {st.processed}, алертов {st.alerts}, "
            f"отвергнуто {st.rejected}"
        )
    return EXIT_OK


def cmd_stream_status(args, cfg) -> int:
    from mlsiem.soc import store
    from mlsiem.stream import broker as broker_mod
    from mlsiem.stream.stats import status_report

    soc = _load_soc_for_stream(args)
    conn = store.connect(soc.db)
    try:
        store.init_db(conn)
        rep = status_report(conn, cfg, broker_factory=lambda: broker_mod.make_broker(cfg, "status"))
    finally:
        conn.close()
    b, c = rep["broker"], rep["consumer"]
    if b["reachable"]:
        lag = rep["lag_messages"]
        _out(f"Брокер {cfg.broker.bootstrap}: доступен; непрочитанных сообщений {lag}")
    else:
        _out(f"Брокер {cfg.broker.bootstrap}: НЕДОСТУПЕН — {b['error']}")
    if c["alive"]:
        _out(f"Потребитель: работает ({c['holder']}, аренда продлена {c['renewed_at']})")
    else:
        _out("Потребитель: не работает" + (f" (последний — {c['holder']})" if c["holder"] else ""))
    if not rep["sessions"]:
        _out("Сеансов ещё не было (`mlsiem stream consume`)")
    titles = {"running": "идёт", "stopped": "остановлен", "completed": "завершён"}
    for s in rep["sessions"]:

        def f(x, fmt="{:.0f}"):
            return "—" if x is None else fmt.format(x)

        _out(
            f"  {s['run_id']}  {titles.get(s['status'], s['status']):<10} {s['source_id']}\n"
            f"    обработано {s['processed']}, алертов {s['n_alerts']}, инцидентов "
            f"{s['n_incidents']}; {f(s['rate_per_s'])} потоков/с; отставание "
            f"{f(s['lag_messages'])} сообщ. / {f(s['lag_seconds'], '{:.1f}')} с; задержка p50 "
            f"{f(s['latency_p50_ms'])} мс, p95 {f(s['latency_p95_ms'])} мс; отвергнуто "
            f"{s['rejected']}, опоздавших {s['late']}; последняя активность "
            f"{s['last_activity_at']}"
        )
    return EXIT_OK


def cmd_stream_close(args, cfg) -> int:
    from mlsiem.soc import store

    soc = _load_soc_for_stream(args)
    conn = store.connect(soc.db)
    try:
        store.init_db(conn)
        try:
            run = store.get_run(conn, args.session)
        except store.NotFound as exc:
            log.error("Ошибка: %s", exc.message)
            return EXIT_ERROR
        if run["mode"] != "stream":
            log.error("Ошибка: %s — пакетный прогон, закрывать нечего", args.session)
            return EXIT_ERROR
        if run["status"] == "completed":
            _out(f"Сеанс {args.session} уже завершён")
            return EXIT_OK
        store.set_session_status(
            conn, args.session, "completed", "закрыт командой mlsiem stream close"
        )
    finally:
        conn.close()
    _out(f"Сеанс {args.session}: {run['status']} → completed (записано в аудит)")
    return EXIT_OK


def cmd_stream_compare(args, cfg) -> int:
    from mlsiem.soc import store
    from mlsiem.stream.compare import CompareError, compare, write_compare

    soc = _load_soc_for_stream(args)
    conn = store.connect(soc.db)
    try:
        store.init_db(conn)
        try:
            report = compare(conn, soc.runs_dir, args.session, args.batch)
        except CompareError as exc:
            log.error("Ошибка: %s", exc)
            return EXIT_ERROR
    finally:
        conn.close()
    md, js = write_compare(report, Path(args.reports_dir))
    if report["equivalent"]:
        extra = report["divergences_by_reason"]
        note = f" (известные расхождения: {extra})" if extra else ""
        _out(f"Сеанс {args.session} и прогон {args.batch}: эквивалентно{note}")
    else:
        by = ", ".join(f"{k} — {n}" for k, n in report["divergences_by_reason"].items())
        _out(f"Сеанс {args.session} и прогон {args.batch}: расхождения по видам: {by}")
    v, i = report["verdicts"], report["incidents"]
    _out(
        f"  вердикты: совпало {v['matched']} из {v['both']}; инциденты: совпало {i['matched']} "
        f"(в сеансе {i['session']}, в пакетном {i['batch']})"
    )
    _out(f"Отчёт: {md}; данные: {js}")
    return EXIT_OK


def _load_stream_config(args):
    from mlsiem.stream.config import load_stream_config

    return load_stream_config(args.config)


# ---------------------------------------------------------------- разбор аргументов


def _load_data_config(args):
    from mlsiem.data.config import load_config

    return load_config(args.config)


def _load_detect_config(args):
    from mlsiem.detect.config import load_detect_config

    return load_detect_config(args.config)


def _load_ensemble_config(args):
    from mlsiem.detect.config import load_ensemble_config

    return load_ensemble_config(args.config)


def _load_soc_config(args):
    from mlsiem.soc.config import load_soc_config

    return load_soc_config(args.config)


def _model_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--model",
        help="каталог модели: ансамбль (ensemble_card.json) или детектор 002 (model_card.json); "
        "по умолчанию models/ensemble, если он обучен, иначе models/detector",
    )
    p.add_argument("--detector", help="синоним --model (совместимость с 002/003)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mlsiem", description="ML-SIEM v2")
    groups = parser.add_subparsers(dest="group", required=True)

    data = groups.add_parser("data", help="пайплайн данных NIDS (фича 001)")
    data.add_argument("--config", default="configs/data.yaml", help="путь к конфигу данных")
    data.add_argument("--data-dir", default="data", help="куда писать результаты")
    data.set_defaults(load_config=_load_data_config)
    sub = data.add_subparsers(dest="command", required=True)

    p = sub.add_parser("flows", help="PCAP → размеченные потоки")
    p.add_argument("--dataset", required=True, choices=["unsw", "ctu13"])
    p.add_argument(
        "--capture",
        nargs="+",
        metavar="ID",
        help="только эти захваты: `22-1-2015:1` для UNSW, `7` для CTU-13",
    )
    p.add_argument("--full-hash", action="store_true", help="полный SHA-256 PCAP в отпечатке")
    p.add_argument("--force", action="store_true", help="пересчитать даже готовые захваты")
    p.set_defaults(func=cmd_flows)

    p = sub.add_parser("extract", help="неразмеченный PCAP → потоки той же схемы")
    p.add_argument("pcap")
    p.add_argument("--output", required=True)
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("split", help="разбиение train/val/test без утечек")
    p.add_argument(
        "--name", required=True, choices=["unsw_time", "unsw_cross_day", "ctu13_scenario"]
    )
    p.set_defaults(func=cmd_split)

    p = sub.add_parser("audit", help="проверка полей на артефакты датасета")
    p.add_argument(
        "--split", required=True, choices=["unsw_time", "unsw_cross_day", "ctu13_scenario"]
    )
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("compare-v1", help="сверка с таблицами v1")
    p.add_argument("--v1-dir", help="папка с таблицами v1 (по умолчанию из конфига)")
    p.set_defaults(func=cmd_compare_v1)

    p = sub.add_parser("report", help="HTML/MD-отчёт о качестве данных")
    p.add_argument("--output", default="reports", help="папка для отчёта")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("all", help="весь конвейер через `dvc repro`")
    p.set_defaults(func=cmd_all)

    detect = groups.add_parser("detect", help="эксперимент и детектор (фича 002)")
    detect.add_argument("--data-dir", default="data", help="где лежат потоки и разбиения 001")
    detect.set_defaults(load_config=_load_detect_config)
    sub = detect.add_subparsers(dest="command", required=True)
    p = sub.add_parser("train", help="обучить кандидатов, выбрать и сохранить детектор")
    p.add_argument("--config", default="configs/detect.yaml", help="конфиг эксперимента")
    p.add_argument("--reports-dir", default="reports", help="куда писать отчёт эксперимента")
    p.add_argument(
        "--mlflow-dir",
        default=".",
        help="где MLflow держит mlflow.db и mlruns/ (по умолчанию корень)",
    )
    p.set_defaults(func=cmd_detect_train)
    p = sub.add_parser(
        "ensemble", help="эксперимент 004: эксперт аномалий, мета-слой и выбор (FR-010)"
    )
    p.add_argument("--config", default="configs/ensemble.yaml", help="конфиг эксперимента 004")
    p.add_argument("--reports-dir", default="reports", help="куда писать отчёт эксперимента")
    p.add_argument(
        "--mlflow-dir",
        default=".",
        help="где MLflow держит mlflow.db и mlruns/ (по умолчанию корень)",
    )
    p.set_defaults(func=cmd_detect_ensemble, load_config=_load_ensemble_config)

    soc = groups.add_parser("soc", help="инциденты, реагирование и API аналитика (фича 002)")
    soc.add_argument("--config", default="configs/soc.yaml", help="конфиг SOC")
    soc.set_defaults(load_config=_load_soc_config)
    sub = soc.add_subparsers(dest="command", required=True)
    p = sub.add_parser("run", help="прогнать часть разбиения или PCAP через цепочку")
    p.add_argument("--split", help="имя разбиения 001, например unsw_time")
    p.add_argument("--part", choices=["train", "val", "test"], help="часть разбиения")
    p.add_argument("--pcap", help="новый неразмеченный PCAP вместо разбиения")
    p.add_argument("--limit", type=int, help="взять только первые N потоков по времени")
    p.add_argument("--data-dir", default="data", help="где лежат потоки и разбиения 001")
    _model_args(p)
    p.set_defaults(func=cmd_soc_run)
    p = sub.add_parser("serve", help="поднять консоль и API аналитика на 127.0.0.1")
    p.add_argument("--port", type=int, help="порт (по умолчанию из конфига)")
    _model_args(p)
    p.set_defaults(func=cmd_soc_serve)
    p = sub.add_parser("status", help="какие прогоны лежат в хранилище")
    p.set_defaults(func=cmd_soc_status)
    p = sub.add_parser(
        "review-sources",
        help="разбор инцидентов с адресов жертв и фона, сравнение прогонов «до/после» (004)",
    )
    p.add_argument("--run", required=True, help="прогон «до» (его инциденты разбираются)")
    p.add_argument("--after", help="прогон «после» — для сравнения и проверки атакующих")
    p.add_argument("--reports-dir", default="reports", help="куда писать отчёт разбора")
    p.add_argument("--data-dir", default="data", help="где лежат потоки и разбиения 001")
    p.set_defaults(func=cmd_soc_review)

    # ---- фича 005
    stand = groups.add_parser("stand", help="брокерная машина стенда: seed-ISO и проверка (005)")
    stand.add_argument("--config", default="configs/stream.yaml", help="конфиг потока и стенда")
    stand.set_defaults(load_config=_load_stream_config)
    sub = stand.add_subparsers(dest="command", required=True)
    p = sub.add_parser(
        "seed-iso", help="собрать seed-ISO автоустановки Ubuntu с Kafka (только файл)"
    )
    p.add_argument("--out", default="var/stand/seed.iso", help="куда записать образ")
    p.add_argument("--pubkey", help="открытый SSH-ключ хоста (по умолчанию ~/.ssh/id_ed25519.pub)")
    p.set_defaults(func=cmd_stand_seed_iso)
    p = sub.add_parser("check", help="проверить с хоста брокер, топики и изоляцию сети стенда")
    p.set_defaults(func=cmd_stand_check)

    stream = groups.add_parser("stream", help="потоковая обработка через Kafka (фича 005)")
    stream.add_argument("--config", default="configs/stream.yaml", help="конфиг потока")
    stream.add_argument(
        "--soc-config", default="configs/soc.yaml", help="конфиг SOC (база, окно, плейбуки)"
    )
    stream.set_defaults(load_config=_load_stream_config)
    sub = stream.add_subparsers(dest="command", required=True)
    p = sub.add_parser("replay", help="проиграть часть разбиения 001 или PCAP в брокер")
    p.add_argument("--split", help="имя разбиения 001, например unsw_time")
    p.add_argument("--part", choices=["train", "val", "test"], help="часть разбиения")
    p.add_argument("--pcap", help="PCAP вместо разбиения (потоки — экстрактором 001)")
    p.add_argument("--limit", type=int, help="только первые N потоков по времени")
    p.add_argument(
        "--speed",
        help="«реальное время × N» (например 60) или max — без пауз; по умолчанию из "
        "конфига (replay.default_speed)",
    )
    p.add_argument("--resume", metavar="SOURCE_ID", help="продолжить прерванное проигрывание")
    p.add_argument("--data-dir", default="data", help="где лежат потоки и разбиения 001")
    p.set_defaults(func=cmd_stream_replay)
    p = sub.add_parser("consume", help="онлайн-цепочка: сообщения → инциденты в SQLite")
    _model_args(p)
    p.add_argument("--once", action="store_true", help="обработать всё доступное и выйти")
    p.set_defaults(func=cmd_stream_consume)
    p = sub.add_parser("status", help="показатели потока: брокер, потребитель, сеансы")
    p.set_defaults(func=cmd_stream_status)
    p = sub.add_parser("close", help="завершить сеанс без отметки end (живой источник)")
    p.add_argument("--session", required=True, help="run_id сеанса (stream-…)")
    p.set_defaults(func=cmd_stream_close)
    p = sub.add_parser("compare", help="сравнить онлайн-сеанс с пакетным прогоном того же входа")
    p.add_argument("--session", required=True, help="run_id сеанса (stream-…)")
    p.add_argument("--batch", required=True, help="run_id пакетного прогона (`soc run`)")
    p.add_argument("--reports-dir", default="reports", help="куда писать отчёт сравнения")
    p.set_defaults(func=cmd_stream_compare)
    return parser


def main(argv: list[str] | None = None) -> int:
    _setup_logging()
    args = build_parser().parse_args(argv)

    from mlsiem.data.config import ConfigError

    try:
        cfg = args.load_config(args)
        return args.func(args, cfg)
    except ConfigError as exc:
        log.error("Ошибка конфига: %s", exc)
        return EXIT_ERROR
    except MemoryError:
        log.error(
            "Не хватило оперативной памяти — прогон остановлен целиком. Готовые захваты "
            "сохранены, при повторном запуске они будут пропущены."
        )
        return EXIT_ERROR
    except OSError as exc:
        if exc.errno == errno.ENOSPC:
            log.error(
                "Закончилось место на диске — прогон остановлен целиком. Освободите место "
                "и запустите команду снова: готовые захваты будут пропущены."
            )
        else:
            log.error("Ошибка ввода-вывода: %s", exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        log.error("Прервано пользователем. Готовые захваты сохранены, незаконченный отброшен.")
        return EXIT_ERROR
    except ValueError as exc:
        # сюда попадают ошибки входных данных: неизвестный захват, нарушение инвариантов и т. п.
        log.error("Ошибка: %s", exc)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
