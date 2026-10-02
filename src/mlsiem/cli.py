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
from datetime import UTC as _UTC
from datetime import datetime as _dt
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


def _soc_direction(args) -> str:
    """Режим правила направления из конфига SOC: окна строятся по той же атакующей стороне,
    что группировка инцидентов (R1), иначе окна обучения и цепочки разошлись бы."""
    from mlsiem.soc.config import load_soc_config

    return load_soc_config(args.soc_config).direction


def cmd_detect_windows(args, cfg) -> int:
    """Эксперимент 007: бустинг окон против нейросети окон против текущей модели (US1)."""
    from mlsiem.detect.artifact import DetectorLoadError
    from mlsiem.detect.windows_experiment import REPORT_NAME, TITLES, run_windows_experiment
    from mlsiem.detect.windows_nn import NNUnavailable, torch_available

    if not args.skip_nn and "gru" in cfg.candidates and not torch_available():
        log.error(
            "Нет PyTorch для нейросети окон — установите `uv sync --extra nn` или запустите "
            "с --skip-nn"
        )
        return EXIT_ERROR
    try:
        exp = run_windows_experiment(
            cfg,
            device=args.device,
            skip_nn=args.skip_nn,
            output=Path(args.output) if args.output else None,
            mlflow_dir=None if args.no_mlflow else Path(args.mlflow_dir),
            data_dir=Path(args.data_dir),
            reports_dir=Path(args.reports_dir),
            direction=_soc_direction(args),
        )
    except NNUnavailable as exc:
        log.error("Ошибка: %s", exc)
        return EXIT_ERROR
    except DetectorLoadError as exc:
        log.error("Текущая модель или модель окон не загружается: %s", exc)
        return EXIT_ERROR

    def f(v) -> str:
        return "—" if v is None or v != v else f"{v:.4f}"

    w = exp["windows"]
    _out(
        f"Эксперимент окон на {exp['split']} (сид {exp['seed']}), версия {exp['window_version']}, "
        f"устройство {exp['device']}"
    )
    _out(
        f"  окон: train {w['train']['n_windows']} (обучение {w['train']['fit']}, хвост "
        f"{w['train']['holdout']}), val {w['val']['n_windows']}, test {w['test']['n_windows']}; "
        f"надёжные классы: {', '.join(exp['reliable_classes'])}"
    )
    _out(
        f"  {'участник':<44} {'надёжных val':>12} {'атака/нет val':>13} {'надёжных test':>13} "
        f"{'обучение, с':>11}"
    )
    for name, p in exp["participants"].items():
        _out(
            f"  {TITLES[name]:<44} {f(p['val']['macro_pr_auc_reliable']):>12} "
            f"{f(p['val']['pr_auc_binary']):>13} {f(p['test']['macro_pr_auc_reliable']):>13} "
            f"{p['train_seconds']:>11}"
        )
    sel = exp["selection"]
    _out(f"Шаг 1: {sel['step1']['text']}")
    _out(f"Шаг 2: {sel['step2']['text']}")
    verdict = (
        "кандидат прошёл выбор, ждёт аудита (`mlsiem detect windows-audit`)"
        if exp["decision"]["passed_selection"]
        else "отрицательный результат — цепочка не меняется"
    )
    _out(
        f"Итог: {verdict}; всего {exp['seconds_total']} с, пиковая память "
        f"{exp['peak_memory_mb']} МБ"
    )
    out = args.output or cfg.output
    _out(f"Модель: {out}; отчёт: {Path(args.reports_dir) / REPORT_NAME}")
    return EXIT_OK


def cmd_detect_windows_audit(args, cfg) -> int:
    """Проверка модели окон на артефакты и перенос (US2): вердикт и итоговое `accepted`."""
    from mlsiem.detect.artifact import DetectorLoadError
    from mlsiem.detect.windows_audit import REPORT_NAME, AuditInputMissing, run_windows_audit
    from mlsiem.detect.windows_nn import NNUnavailable

    try:
        audit, card = run_windows_audit(
            cfg,
            model_dir=Path(args.model) if args.model else None,
            data_dir=Path(args.data_dir),
            device=args.device,
            reports_dir=Path(args.reports_dir),
            mlflow_dir=None if args.no_mlflow else Path(args.mlflow_dir),
        )
    except AuditInputMissing as exc:
        log.error("Ошибка: %s", exc)
        return EXIT_ERROR
    except (DetectorLoadError, NNUnavailable) as exc:
        log.error("Модель не загружается: %s", exc)
        return EXIT_ERROR

    def f(v) -> str:
        return "—" if v is None or v != v else f"{v:.4f}"

    d = card["decision"]
    rt, tr = audit["retrain"], audit["transfer"]
    _out(f"Аудит модели окон {audit['model']['kind']} {audit['model']['window_version']}")
    _out(
        f"  macro надёжных val: {f(audit['base']['macro_pr_auc_reliable_val'])}; без "
        f"подозрительных ({len(rt['removed'])}): "
        f"{f(rt.get('macro_pr_auc_reliable_val')) if rt['done'] else 'повтор не нужен'}; "
        f"падение {rt['drop']:+.4f} (порог {audit['max_drop']})"
    )
    _out(
        f"  перенос на {tr['split']} test: macro надёжных "
        f"{f(tr['winner']['macro_pr_auc_reliable'])}, «атака/нет» "
        f"{f(tr['winner']['pr_auc_binary'])} (с оговоркой о пересечении частей)"
    )
    _out(f"Вердикт: {audit['verdict']} — {audit['text']}")
    _out(f"Итог: accepted = {str(d['accepted']).lower()}; {d['reason']}")
    _out(f"Отчёт: {Path(args.reports_dir) / REPORT_NAME}")
    return EXIT_OK


def cmd_detect_windows_errors(args, cfg) -> int:
    """Разбор ошибок модели окон рядом с моделью потоков (US4)."""
    from mlsiem.detect.artifact import DetectorLoadError
    from mlsiem.detect.windows_audit import (
        ERRORS_REPORT_NAME,
        AuditInputMissing,
        run_windows_errors,
    )

    try:
        err = run_windows_errors(
            cfg,
            model_dir=Path(args.model) if args.model else None,
            part=args.part,
            data_dir=Path(args.data_dir),
            reports_dir=Path(args.reports_dir),
        )
    except AuditInputMissing as exc:
        log.error("Ошибка: %s", exc)
        return EXIT_ERROR
    except DetectorLoadError as exc:
        log.error("Модель не загружается: %s", exc)
        return EXIT_ERROR

    def f(v) -> str:
        return "—" if v is None or v != v else f"{v:.4f}"

    _out(
        f"Разбор ошибок {err['model']['kind']} {err['model']['window_version']} на {err['part']}: "
        f"окон {err['n_windows']}, атакующих {err['n_attack_windows']}, "
        f"полнота {f(err['recall'])}, ложных на норме {err['false_alerts']}"
    )
    _out(f"  {'класс':<16} {'только окна':>11} {'только потоки':>13} {'обе':>6} {'никто':>6}")
    for r in err["catch"]:
        _out(
            f"  {r['label']:<16} {r['only_windows']:>11} {r['only_flows']:>13} {r['both']:>6} "
            f"{r['none']:>6}"
        )
    _out(f"Отчёт: {Path(args.reports_dir) / ERRORS_REPORT_NAME}")
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
    if s.windows_line:
        _out(f"  {s.windows_line}")
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
            windows_mode=args.windows,
            windows_model=Path(args.windows_model) if args.windows_model else None,
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
    """Seed-ISO автоустановки машины стенда по роли — только файл, система не меняется."""
    from mlsiem.stand.seed import DEFAULT_PUBKEY, build_seed_iso, default_out, read_pubkey

    role = args.role
    key = read_pubkey(Path(args.pubkey) if args.pubkey else DEFAULT_PUBKEY)
    out = build_seed_iso(cfg, key, Path(args.out) if args.out else default_out(role), role=role)
    size_kb = out.stat().st_size / 1024
    _out(f"Seed-ISO ({role}): {out} ({size_kb:.0f} КБ, метка тома CIDATA)")
    if role == "broker":
        _out(
            f"  машина {cfg.stand.vm_name}: адрес {cfg.stand.broker_ip}/{cfg.stand.prefix}, "
            f"Kafka {cfg.stand.kafka_version}, пользователь {cfg.stand.admin_user} "
            "(вход по ключу)"
        )
        _out("Дальше: stand/hyperv/20-vm-broker.ps1 -Iso <образ Ubuntu> (от администратора)")
    else:
        machine = getattr(cfg.lab, role)
        _out(f"  машина {machine.vm}: адрес {machine.ip}/{cfg.lab.subnet.prefixlen} в сети стенда")
        script = "40-vm-victim" if role == "victim" else "50-vm-attacker"
        _out(
            f"Дальше: stand/hyperv/{script}.ps1 -Iso <образ Ubuntu> -Seed {out} (от администратора)"
        )
    return EXIT_OK


def cmd_stand_check(args, cfg) -> int:
    from mlsiem.stand.check import stand_check
    from mlsiem.stream import broker as broker_mod

    channel = None
    if cfg.lab is not None:
        from mlsiem.lab.channel import make_channel

        channel = make_channel(cfg)
    report = stand_check(cfg, lambda: broker_mod.make_broker(cfg, "check"), channel=channel)
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


# ---------------------------------------------------------------- фича 006: группа lab


def _lab_channel(cfg):
    from mlsiem.lab.channel import make_channel

    if cfg.lab is None:
        log.error("в конфиге нет раздела lab — стенд описывается там (configs/stream.yaml)")
        return None
    return make_channel(cfg)


def cmd_lab_scenario_list(args, cfg) -> int:
    """Сценарии из конфига — без обращения к машинам (только чтение)."""
    if cfg.lab is None:
        log.error("в конфиге нет раздела lab")
        return EXIT_ERROR
    for sc in cfg.scenarios:
        _out(
            f"  {sc.name}@{sc.version}: {sc.tool} → {sc.target}, класс {sc.expected_class}, "
            f"предел {sc.duration_limit_s} с"
        )
    if not cfg.scenarios:
        _out("Сценариев в конфиге нет")
    return EXIT_OK


def cmd_lab_scenario_run(args, cfg) -> int:
    """Запустить сценарий на атакующей машине через канал управления (R6)."""
    from mlsiem.lab.channel import ChannelError

    channel = _lab_channel(cfg)
    if channel is None:
        return EXIT_ERROR
    try:
        sc = cfg.scenario(args.name, args.version)
        reply = channel.request(
            {"cmd": "scenario", "name": sc.name, "version": sc.version},
            timeout_s=sc.duration_limit_s + 30,
        )
    except ChannelError as exc:
        log.error("Ошибка канала: %s", exc)
        return EXIT_ERROR
    if not reply.get("ok"):
        rec = reply.get("record") or {}
        _out(f"Сценарий {args.name}: отклонён — {rec.get('reject_reason') or reply.get('error')}")
        return EXIT_ERROR
    rec = reply["record"]
    _out(f"Сценарий {rec['name']}@{rec['version']}: {rec['outcome']} (run_uid {rec['run_uid']})")
    return EXIT_OK


def cmd_lab_normal(args, cfg) -> int:
    from mlsiem.lab.channel import ChannelError

    channel = _lab_channel(cfg)
    if channel is None:
        return EXIT_ERROR
    try:
        reply = channel.request({"cmd": "normal", "action": args.action}, timeout_s=30)
    except ChannelError as exc:
        log.error("Ошибка канала: %s", exc)
        return EXIT_ERROR
    if not reply.get("ok"):
        log.error("Ошибка: %s", reply.get("error"))
        return EXIT_ERROR
    _out(f"Фоновая норма: {'запущена' if args.action == 'start' else 'остановлена'}")
    return EXIT_OK


def _fetch_journal(channel):
    from mlsiem.lab.channel import ChannelError

    try:
        reply = channel.request({"cmd": "journal"}, timeout_s=30)
    except ChannelError as exc:
        log.error("Ошибка канала: %s", exc)
        return None
    if not reply.get("ok"):
        log.error("Ошибка: %s", reply.get("error"))
        return None
    return reply["records"]


def cmd_lab_demo(args, cfg) -> int:
    """Готовность стенда → контрольный сценарий → остальные → сводка (US3, FR-015)."""
    from mlsiem.lab.channel import ChannelError

    channel = _lab_channel(cfg)
    if channel is None:
        return EXIT_ERROR
    order = ["control_replay"] + [
        s.name for s in cfg.scenarios if s.name not in ("control_replay",)
    ]
    summary = []
    for name in order:
        try:
            sc = cfg.scenario(name)
        except Exception:  # noqa: BLE001 — нет такого сценария в конфиге, пропускаем
            continue
        try:
            reply = channel.request(
                {"cmd": "scenario", "name": sc.name, "version": sc.version},
                timeout_s=sc.duration_limit_s + 30,
            )
        except ChannelError as exc:
            log.error("Ошибка канала на %s: %s", name, exc)
            return EXIT_ERROR
        rec = reply.get("record") or {}
        ok = reply.get("ok")
        summary.append((name, rec.get("outcome", "?"), rec.get("run_uid")))
        _out(f"  {name}: {rec.get('outcome', reply.get('error'))}")
        if not ok and name == "control_replay":
            log.error("Контрольный сценарий не выполнился — демо остановлено")
            return EXIT_ERROR
    _out("Сводка демо:")
    for name, outcome, uid in summary:
        _out(f"  {name}: {outcome} ({uid or '—'})")
    _out("Инциденты смотрите в консоли: uv run mlsiem soc serve")
    return EXIT_OK


def cmd_lab_report(args, cfg) -> int:
    """Отчёт по запуску сценария (FR-016): журнал забирается с машины, алерты — из хранилища."""
    from mlsiem.lab import journal
    from mlsiem.lab.report import report_md, run_report
    from mlsiem.soc import store

    channel = _lab_channel(cfg)
    if channel is None:
        return EXIT_ERROR
    records = _fetch_journal(channel)
    if records is None:
        return EXIT_ERROR
    try:
        rec = journal.find(records, args.run)
    except journal.JournalError as exc:
        log.error("Ошибка: %s", exc)
        return EXIT_ERROR
    soc = _load_soc_for_stream(args)
    run_id = store.session_run_id(_sensor_source_id(cfg))
    conn = store.connect(soc.db)
    try:
        store.init_db(conn)
        rep = run_report(conn, run_id, rec)
    finally:
        conn.close()
    _out(report_md(rep))
    return EXIT_OK


def cmd_lab_dataset_build(args, cfg) -> int:
    """Собрать размеченный набор стенда из записи сеанса и журнала (US4, R12)."""
    import tempfile

    from mlsiem.data.extract import extract_flows
    from mlsiem.lab import journal
    from mlsiem.lab.dataset import build_dataset

    if not args.pcap:
        log.error("нужен --pcap: запись сеанса сенсора (забирается с машины Copy-VMFile)")
        return EXIT_ERROR
    records = journal.read(args.journal) if args.journal else []
    version = args.version or _dt.now(_UTC).strftime("%Y%m%dT%H%M%S")
    out = Path(args.out) if args.out else Path("data/lab") / version
    # Потоки экстрактором 001 — со всеми колонками схемы, включая ключевые (flow_uid нужен
    # оценке для сортировки/соединения). Тот же код, что `soc run --pcap` → единство признаков
    with tempfile.TemporaryDirectory(prefix="mlsiem-lab-ds-") as wd:
        flows = extract_flows(Path(args.pcap), "lab-" + version, workdir=Path(wd)).df
    report = build_dataset(flows, records, out, version, sources=[Path(args.pcap).name])
    _out(f"Набор стенда: {out} ({report['total_flows']} потоков)")
    _out(f"  классы: {report['by_class']}")
    _out(
        f"  ambiguous: {report['ambiguous']} ({report['ambiguous_share_of_scenarios'] * 100:.1f}%)"
    )
    return EXIT_OK


def cmd_lab_evaluate(args, cfg) -> int:
    """Оценка модели на наборе стенда: PR-AUC, поимка, FPR, разбор (US5, FR-022/FR-024)."""
    import json as _json

    import polars as pl

    from mlsiem.detect.ensemble import load_model
    from mlsiem.lab.evaluate import evaluate_dataset, write_report

    dataset_dir = Path(args.dataset)
    if not dataset_dir.exists():
        dataset_dir = Path("data/lab") / args.dataset
    flows_path = dataset_dir / "flows.parquet"
    if not flows_path.exists():
        log.error("нет набора %s (ожидался flows.parquet)", flows_path)
        return EXIT_ERROR
    labeled = pl.read_parquet(flows_path)
    manifest = {}
    man_path = dataset_dir / "manifest.json"
    if man_path.exists():
        manifest = _json.loads(man_path.read_text(encoding="utf-8"))
    model = load_model(_model_dir(args))
    catch = {sc.expected_class: sc.catch_threshold for sc in cfg.scenarios} if cfg.lab else {}
    lossy = bool((manifest.get("sensor_losses") or {}).get("flows_dropped")) or bool(
        (manifest.get("sensor_losses") or {}).get("packets_dropped")
    )
    report = evaluate_dataset(model, labeled, [], catch_thresholds=catch, lossy=lossy)
    version = manifest.get("version") or dataset_dir.name
    md, js = write_report(report, Path(args.reports_dir), version)
    _record_lab_eval_mlflow(args, report, model, version)
    _append_journal_eval(report, model, version)
    _out(f"Оценка записана: {md}")
    _out(
        f"  PR-AUC macro {report['pr_auc_macro']}, «атака/нет» {report['pr_auc_attack']}, "
        f"FPR норма {report['fpr_normal']}"
    )
    for u in report["unexplained"]:
        _out(f"  не поймано {u['scenario_class']}: {u['reason']}")
    return EXIT_OK


def _record_lab_eval_mlflow(args, report, model, version) -> None:
    """Запись версии модели/набора/метрик в MLflow (эксперимент lab). Сбой MLflow не валит
    команду: отчёт на диске уже есть."""
    try:
        import mlflow

        mlflow.set_tracking_uri(f"sqlite:///{Path(args.mlflow_dir) / 'mlflow.db'}")
        mlflow.set_experiment("lab")
        with mlflow.start_run(run_name=f"lab_eval_{version}"):
            mlflow.log_params({"model_version": model.version, "dataset_version": version})
            for k in ("pr_auc_macro", "pr_auc_attack", "fpr_normal", "threshold"):
                if report.get(k) is not None:
                    mlflow.log_metric(k, float(report[k]))
    except Exception as exc:  # noqa: BLE001 — наблюдаемость не должна ронять оценку
        log.warning("MLflow недоступен, метрики не записаны: %s", exc)


def _append_journal_eval(report, model, version) -> None:
    """Итог оценки — в docs/JOURNAL.md даже при плохом результате (FR-024, конституция VI)."""
    path = Path("docs/JOURNAL.md")
    if not path.exists():
        return
    line = (
        f"\n### Оценка стенда {version} ({_dt.now(_UTC).date()})\n\n"
        f"- модель {model.version}, порог {report['threshold']}\n"
        f"- PR-AUC macro {report['pr_auc_macro']}, «атака/нет» {report['pr_auc_attack']}, "
        f"FPR норма {report['fpr_normal']}, ложных инцидентов {report['false_incidents']}\n"
    )
    if report["unexplained"]:
        line += (
            "- не поймано: "
            + "; ".join(f"{u['scenario_class']} — {u['reason']}" for u in report["unexplained"])
            + "\n"
        )
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)


def _sensor_source_id(cfg) -> str:
    return cfg.lab.sensor.source_id if cfg.lab else "sensor:live"


def cmd_stream_sensor_start(args, cfg) -> int:
    """Живой сенсор: слушает интерфейс зеркала, шлёт потоки в брокер как sensor:live (US2)."""
    import signal

    from mlsiem.soc import store
    from mlsiem.stream import broker as broker_mod
    from mlsiem.stream.sensor import flows_from_pcap, iter_live_flows, run_sensor

    if cfg.lab is None:
        log.error("в конфиге нет раздела lab — сенсор описывается там (configs/stream.yaml)")
        return EXIT_ERROR
    iface = args.iface or cfg.lab.sensor.iface
    soc = _load_soc_for_stream(args)
    conn = store.connect(soc.db)
    stopping = {"flag": False}

    def on_sigint(signum, frame):
        stopping["flag"] = True
        log.info("Останавливаю сенсор: досылаю буфер и завершаю…")

    previous = signal.signal(signal.SIGINT, on_sigint)
    broker = broker_mod.make_broker(cfg, "sensor")
    try:
        store.init_db(conn)
        broker.ping()
        flows = flows_from_pcap(Path(args.pcap)) if args.pcap else iter_live_flows(iface)
        src = f"запись {Path(args.pcap).name}" if args.pcap else f"интерфейс {iface}"
        log.info(
            "Сенсор: %s → брокер %s (источник %s)",
            src,
            cfg.broker.bootstrap,
            _sensor_source_id(cfg),
        )
        summary = run_sensor(
            cfg, conn, broker, flows, stop=lambda: stopping["flag"], on_report=log.info
        )
    except broker_mod.BrokerUnavailable as exc:
        log.error("Ошибка: %s", exc)
        return EXIT_ERROR
    finally:
        signal.signal(signal.SIGINT, previous)
        broker.close()
        conn.close()
    _out(
        f"Сенсор остановлен: потоков {summary.counters.flows_sent} из "
        f"{summary.counters.flows_seen}, потери {summary.counters.flows_dropped} потоков / "
        f"{summary.counters.packets_dropped} пакетов"
        + (" (сеанс с потерями)" if summary.lossy else "")
    )
    return EXIT_OK


def cmd_stream_sensor_status(args, cfg) -> int:
    from mlsiem.soc import store
    from mlsiem.stream.stats import status_report

    soc = _load_soc_for_stream(args)
    source_id = _sensor_source_id(cfg)
    conn = store.connect(soc.db)
    try:
        store.init_db(conn)
        rep = status_report(conn, cfg)
    finally:
        conn.close()
    sessions = [s for s in rep["sessions"] if s["source_id"] == source_id]
    if not sessions:
        _out(f"Сеанса сенсора ({source_id}) ещё не было")
        return EXIT_OK

    def f(x, fmt="{:.0f}"):
        return "—" if x is None else fmt.format(x)

    for s in sessions:
        _out(f"Сенсор {s['source_id']} ({s['status']}): потоков {s['processed']}")
        _out(
            f"  {f(s['packets_per_s'])} пак/с, {f(s['flows_per_s'], '{:.1f}')} пот/с, потери "
            f"{f(s['drops'])}, буфер {f(s['buffer_fill'], '{:.0%}')}, живость "
            f"{'да' if s['liveness'] else 'нет'}" + (", СЕАНС С ПОТЕРЯМИ" if s["lossy"] else "")
        )
    return EXIT_OK


def cmd_stream_sensor_stop(args, cfg) -> int:
    """Завершить сеанс сенсора: как stream close для sensor:live."""
    from mlsiem.soc import store

    soc = _load_soc_for_stream(args)
    source_id = _sensor_source_id(cfg)
    run_id = store.session_run_id(source_id)
    conn = store.connect(soc.db)
    try:
        store.init_db(conn)
        run = store.session_by_source(conn, source_id)
        if run is None:
            _out(f"Сеанса сенсора ({source_id}) ещё не было")
            return EXIT_OK
        if run["status"] == "completed":
            _out(f"Сеанс сенсора {run_id} уже завершён")
            return EXIT_OK
        store.set_session_status(conn, run_id, "completed", "закрыт командой stream sensor stop")
    finally:
        conn.close()
    _out(f"Сеанс сенсора {run_id} завершён")
    return EXIT_OK


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
            windows_mode=args.windows,
            windows_model=Path(args.windows_model) if args.windows_model else None,
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
        if s.get("windows_enabled"):
            _out(
                f"    окна: открыто {s['n_open_windows']}, закрыто {s['n_windows_closed']}, "
                f"алертов {s['n_window_alerts']}, опоздавших-вне-окна {s['n_window_late_dropped']}"
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
        # Фича 007: перед завершением — закрыть открытые окна сеанса (вердикты и алерты окон
        # пишутся, как при отметке end)
        from mlsiem.stream.windows_online import close_session_windows

        closed = close_session_windows(conn, soc, args.session)
        if closed["n_windows"]:
            _out(f"Закрыто окон: {closed['n_windows']}, алертов окон: {closed['n_window_alerts']}")
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


def _load_windows_config(args):
    from mlsiem.detect.windows import load_windows_config

    return load_windows_config(args.config)


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


def _windows_args(p: argparse.ArgumentParser) -> None:
    """Флаги эксперта окон (фича 007) у `soc run` и `stream consume`."""
    p.add_argument(
        "--windows",
        choices=["auto", "off", "force"],
        help="эксперт окон: auto — только принятая модель (по умолчанию из soc.yaml), off — "
        "как в 005, force — включить и непринятую (для проверки интеграции)",
    )
    p.add_argument("--windows-model", help="каталог модели окон (по умолчанию windows.model)")


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

    p = sub.add_parser(
        "windows", help="эксперимент 007: окна потоков — бустинг против нейросети (US1)"
    )
    p.add_argument("--config", default="configs/windows.yaml", help="конфиг эксперимента окон")
    p.add_argument(
        "--device",
        default="auto",
        choices=["auto", "cuda", "cpu"],
        help="где обучать нейросеть: auto — видеокарта, если есть, иначе CPU",
    )
    p.add_argument("--skip-nn", action="store_true", help="без нейросети: бустинг и текущая модель")
    p.add_argument("--output", help="куда сохранить модель окон (по умолчанию из конфига)")
    p.add_argument("--no-mlflow", action="store_true", help="не писать запуски в MLflow")
    p.add_argument("--reports-dir", default="reports", help="куда писать отчёт эксперимента")
    p.add_argument("--mlflow-dir", default=".", help="где mlflow.db и mlruns/")
    p.add_argument(
        "--soc-config",
        default="configs/soc.yaml",
        help="конфиг SOC: режим правила направления (grouping.direction) — ключ окна",
    )
    p.set_defaults(func=cmd_detect_windows, load_config=_load_windows_config)

    p = sub.add_parser(
        "windows-audit", help="007: проверка модели окон на артефакты и перенос (US2)"
    )
    p.add_argument("--model", help="каталог модели окон (по умолчанию output из конфига)")
    p.add_argument("--config", default="configs/windows.yaml", help="конфиг эксперимента окон")
    p.add_argument(
        "--device",
        default="auto",
        choices=["auto", "cuda", "cpu"],
        help="где переобучать нейросеть при повторе без подозрительных признаков",
    )
    p.add_argument("--no-mlflow", action="store_true", help="не писать метрики аудита в MLflow")
    p.add_argument("--reports-dir", default="reports", help="куда писать отчёт аудита")
    p.add_argument("--mlflow-dir", default=".", help="где mlflow.db и mlruns/")
    p.set_defaults(func=cmd_detect_windows_audit, load_config=_load_windows_config)

    p = sub.add_parser("windows-errors", help="007: разбор ошибок модели окон (US4)")
    p.add_argument("--model", help="каталог модели окон (по умолчанию output из конфига)")
    p.add_argument("--config", default="configs/windows.yaml", help="конфиг эксперимента окон")
    p.add_argument("--part", default="test", choices=["train", "val", "test"], help="часть")
    p.add_argument("--reports-dir", default="reports", help="куда писать отчёт разбора")
    p.set_defaults(func=cmd_detect_windows_errors, load_config=_load_windows_config)

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
    _windows_args(p)
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
    p.add_argument(
        "--role",
        choices=("broker", "victim", "attacker"),
        default="broker",
        help="какая машина: брокер (005), жертва или атакующий (006)",
    )
    p.add_argument("--out", help="куда записать образ (по умолчанию var/stand/seed[-<роль>].iso)")
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
    _windows_args(p)
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
    # ---- фича 006: живой сенсор
    p = sub.add_parser("sensor", help="живой сенсор: трафик стенда → потоки в брокер (006)")
    ssub = p.add_subparsers(dest="sensor_command", required=True)
    sp = ssub.add_parser("start", help="запустить живой захват на интерфейсе зеркала")
    sp.add_argument("--iface", help="интерфейс-приёмник зеркала (по умолчанию из lab.sensor.iface)")
    sp.add_argument("--pcap", help="вместо живого захвата проиграть запись (отладка/демо)")
    sp.set_defaults(func=cmd_stream_sensor_start)
    sp = ssub.add_parser(
        "status", help="показатели живого сенсора (== stream status для sensor:live)"
    )
    sp.set_defaults(func=cmd_stream_sensor_status)
    sp = ssub.add_parser("stop", help="завершить сеанс сенсора (как stream close)")
    sp.set_defaults(func=cmd_stream_sensor_stop)

    # ---- фича 006: группа lab (сценарии, норма, набор, оценка)
    lab = groups.add_parser("lab", help="лабораторный стенд 006: сценарии, норма, набор, оценка")
    lab.add_argument("--config", default="configs/stream.yaml", help="конфиг потока и стенда")
    lab.add_argument("--soc-config", default="configs/soc.yaml", help="конфиг SOC (база, окно)")
    lab.set_defaults(load_config=_load_stream_config)
    lsub = lab.add_subparsers(dest="command", required=True)

    sc = lsub.add_parser("scenario", help="сценарии атак: список и запуск")
    scsub = sc.add_subparsers(dest="scenario_command", required=True)
    q = scsub.add_parser("list", help="сценарии из конфига (без обращения к машинам)")
    q.set_defaults(func=cmd_lab_scenario_list)
    q = scsub.add_parser("run", help="запустить сценарий на атакующей машине (через канал)")
    q.add_argument("name", help="имя сценария (lab scenario list)")
    q.add_argument("--version", help="версия сценария (по умолчанию любая)")
    q.set_defaults(func=cmd_lab_scenario_run)

    q = lsub.add_parser("normal", help="фоновая норма: start | stop")
    q.add_argument("action", choices=("start", "stop"))
    q.set_defaults(func=cmd_lab_normal)

    q = lsub.add_parser("demo", help="готовность → контрольный сценарий → остальные → сводка")
    q.set_defaults(func=cmd_lab_demo)

    q = lsub.add_parser("report", help="отчёт по запуску сценария (FR-016)")
    q.add_argument("--run", required=True, help="run_uid запуска из журнала")
    q.set_defaults(func=cmd_lab_report)

    q = lsub.add_parser("dataset", help="собрать размеченный набор стенда")
    dsub = q.add_subparsers(dest="dataset_command", required=True)
    b = dsub.add_parser("build", help="запись сеанса + журнал → data/lab/<версия>/")
    b.add_argument("--pcap", help="запись сеанса сенсора (Copy-VMFile с машины)")
    b.add_argument("--journal", help="журнал сценариев (JSONL, забранный с машины)")
    b.add_argument("--version", help="версия набора (по умолчанию метка времени)")
    b.add_argument("--out", help="каталог набора (по умолчанию data/lab/<версия>)")
    b.set_defaults(func=cmd_lab_dataset_build)

    q = lsub.add_parser("evaluate", help="честная оценка модели на наборе стенда (FR-022)")
    q.add_argument("--dataset", required=True, help="версия набора или путь к data/lab/<версия>")
    q.add_argument("--model", help="каталог модели (по умолчанию ансамбль/детектор)")
    q.add_argument("--reports-dir", default="reports", help="куда писать отчёт оценки")
    q.add_argument("--mlflow-dir", default=".", help="где mlflow.db и mlruns/")
    q.set_defaults(func=cmd_lab_evaluate)
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
