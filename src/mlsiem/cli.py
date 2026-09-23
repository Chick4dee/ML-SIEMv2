"""Точка входа `mlsiem`. Сейчас есть группа `data` (фича 001); следующие фичи добавят свои.

Договорённости (contracts/cli.md):
- прогресс и предупреждения — в stderr, итоговая сводка — в stdout;
- коды возврата: 0 — успех; 1 — ошибка входных данных, конфига или нехватка ресурсов
  (прогон прерван целиком); 2 — часть захватов не прочиталась, остальные обработаны.
"""

from __future__ import annotations

import argparse
import errno
import logging
import sys
from pathlib import Path

log = logging.getLogger("mlsiem")

EXIT_OK, EXIT_ERROR, EXIT_PARTIAL = 0, 1, 2


def _setup_logging() -> None:
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
    flagged = result.filter(result["status"] != "ok").sort(["status", "lift"], descending=True)
    _out(
        f"Аудит {args.split}: проверено полей {result.height}, "
        f"опасных {int((result['status'] == 'dangerous').sum())}, "
        f"подозрительных {int((result['status'] == 'suspicious').sum())}"
    )
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


# ---------------------------------------------------------------- разбор аргументов


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mlsiem", description="ML-SIEM v2")
    groups = parser.add_subparsers(dest="group", required=True)

    data = groups.add_parser("data", help="пайплайн данных NIDS (фича 001)")
    data.add_argument("--config", default="configs/data.yaml", help="путь к конфигу данных")
    data.add_argument("--data-dir", default="data", help="куда писать результаты")
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
    return parser


def main(argv: list[str] | None = None) -> int:
    _setup_logging()
    args = build_parser().parse_args(argv)

    from mlsiem.data.config import ConfigError, load_config

    try:
        cfg = load_config(args.config)
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
