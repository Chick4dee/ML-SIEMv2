"""Точка входа `mlsiem`. Группы: `data` (фича 001), `detect` и `soc` (фича 002).

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


def _print_run_summary(s) -> None:
    _out(f"Прогон {s.run_id} ({s.source}), детектор {s.detector_version}, {s.seconds:.1f} с")
    _out(f"  потоков {s.n_flows}, алертов {s.n_alerts}, инцидентов {s.n_incidents}")
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
            detector_dir=Path(args.detector),
            data_dir=Path(args.data_dir),
            limit=args.limit,
        )
    except ExtractError as exc:
        log.error("Ошибка извлечения потоков: %s", exc)
        return EXIT_ERROR
    _print_run_summary(summary)
    return EXIT_OK


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
        app = create_app(cfg, detector_dir=Path(args.detector))
    except SchemaTooNew as exc:
        log.error("Нельзя открыть %s: %s", cfg.db, exc.message)
        return EXIT_ERROR
    if app.state.migrated:
        log.info(
            "Схема базы %s обновлена до версии %d (аудит перенесён целиком)",
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
        _out(
            f"  {r['run_id']}  {r['source']:<24} {r['started_at']}  "
            f"детектор {r['detector_version']}  "
            f"инцидентов {r['n_incidents']} (new {st['new']}, in_progress {st['in_progress']}, "
            f"closed {st['closed']})"
        )
    return EXIT_OK


# ---------------------------------------------------------------- разбор аргументов


def _load_data_config(args):
    from mlsiem.data.config import load_config

    return load_config(args.config)


def _load_detect_config(args):
    from mlsiem.detect.config import load_detect_config

    return load_detect_config(args.config)


def _load_soc_config(args):
    from mlsiem.soc.config import load_soc_config

    return load_soc_config(args.config)


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
    p.add_argument("--detector", default="models/detector", help="каталог артефакта детектора")
    p.set_defaults(func=cmd_soc_run)
    p = sub.add_parser("serve", help="поднять консоль и API аналитика на 127.0.0.1")
    p.add_argument("--port", type=int, help="порт (по умолчанию из конфига)")
    p.add_argument("--detector", default="models/detector", help="каталог артефакта детектора")
    p.set_defaults(func=cmd_soc_serve)
    p = sub.add_parser("status", help="какие прогоны лежат в хранилище")
    p.set_defaults(func=cmd_soc_status)
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
