"""Команды `mlsiem lab plan | collect | tools` (фича 008) — разбор аргументов и вывод; логика в
plan.py/collect.py.

Каталог сбора по умолчанию — `var/lab/collect`: там лежат план, состояние `collect_state.json`,
журнал,
сегменты записи сеансов. Остановка работает из другого окна: `lab collect stop` ставит флаг рядом с
планом.
"""

from __future__ import annotations

import json
import signal
import sys
from datetime import UTC, datetime
from pathlib import Path

from mlsiem.lab import collect as collect_mod
from mlsiem.lab.capture import CaptureError, SensorCapture
from mlsiem.lab.channel import ChannelError, make_channel
from mlsiem.lab.plan import PlanError, build_plan, read_plan, write_plan
from mlsiem.lab.variants import list_variants

DEFAULT_DIR = Path("var/lab/collect")
EXIT_OK, EXIT_ERROR, EXIT_NOT_READY, EXIT_TOOLS, EXIT_INTERRUPTED = 0, 1, 2, 3, 4


def _out(text: str = "") -> None:
    print(text, flush=True)


def cmd_plan(args, cfg) -> int:
    try:
        plan = build_plan(cfg.raw, seed=args.seed, repeats=args.repeats)
    except PlanError as exc:
        _out(f"Ошибка плана: {exc}")
        return EXIT_ERROR
    out = Path(args.out) if args.out else DEFAULT_DIR / "plan.json"
    write_plan(plan, out)
    _out(f"План записан: {out}")
    collect_mod.print_plan_summary(plan, _out)
    return EXIT_OK


def _workdir(args) -> Path:
    return Path(args.workdir) if getattr(args, "workdir", None) else DEFAULT_DIR


def cmd_collect(args, cfg) -> int:
    action = args.action or "run"
    workdir = _workdir(args)
    if action in ("stop", "status"):
        state_path = workdir / collect_mod.STATE_FILE
        if action == "stop":
            workdir.mkdir(parents=True, exist_ok=True)
            (workdir / collect_mod.STOP_FLAG).write_text("stop\n", encoding="utf-8")
            if args.now:
                (workdir / collect_mod.HARD_FLAG).write_text("now\n", encoding="utf-8")
            _out(
                "Остановка запрошена: "
                + ("срочная" if args.now else "мягкая (после текущего запуска и паузы-дренажа)")
            )
            _out(
                "Следите: uv run mlsiem lab collect status — «можно выключать: да» после "
                "завершения сеанса"
            )
            return EXIT_OK
        if not state_path.exists():
            _out(f"Состояния сбора нет ({state_path}): сбор не запускался.")
            return EXIT_OK
        st = json.loads(state_path.read_text(encoding="utf-8"))
        runs = st["runs"]
        count = lambda s: sum(1 for v in runs.values() if v["status"] == s)  # noqa: E731
        _out(
            f"Сеансов: {len(st['sessions'])}; выполнено {count('done')}, прервано "
            f"{count('aborted')}, пропущено {count('skipped')}, "
            f"осталось {st['remaining']} (≈ {st['eta_s'] / 3600:.1f} ч)"
        )
        _out(
            "Можно выключать: "
            f"{'да' if st['safe_to_power_off'] else 'нет (сеанс идёт или запись не выгружена)'}"
        )
        if (workdir / collect_mod.STOP_FLAG).exists():
            _out("Остановка запрошена, ждём конца текущего запуска.")
        return EXIT_OK

    plan_path = Path(args.plan) if args.plan else workdir / "plan.json"
    try:
        plan = read_plan(plan_path)
    except (PlanError, OSError, json.JSONDecodeError) as exc:
        _out(f"План не прочитан ({plan_path}): {exc}\nПостройте его: uv run mlsiem lab plan")
        return EXIT_ERROR
    if cfg.lab is None:
        _out("В конфиге нет раздела lab")
        return EXIT_ERROR
    channel = make_channel(cfg)
    capture = SensorCapture.from_config(cfg.raw)
    try:
        col = collect_mod.Collector(cfg.raw, plan, workdir, channel, capture, log=_out)
    except collect_mod.CollectError as exc:
        _out(f"Ошибка: {exc}")
        return EXIT_ERROR
    collect_mod.print_plan_summary(plan, _out)
    st = col.status()
    _out(
        f"Выполнено {st['done']}, осталось {st['remaining']} (≈ {st['eta_h']} ч); сеансов до "
        f"этого: {st['sessions']}"
    )
    if not args.yes:
        if not sys.stdin.isatty():
            _out(
                "Нужно подтверждение: добавьте --yes (запись займёт место на сенсорной машине и на "
                "хосте)."
            )
            return EXIT_NOT_READY
        if input("Начать сеанс сбора? [y/N] ").strip().lower() not in ("y", "yes", "д", "да"):
            return EXIT_OK

    presses = {"n": 0}

    def on_sigint(signum, frame):  # noqa: ARG001
        presses["n"] += 1
        if presses["n"] == 1:
            col.request_stop()
            _out(
                "\nМягкая остановка: дожидаюсь конца запуска и паузы-дренажа. Повторное Ctrl+C — "
                "срочная остановка."
            )
        else:
            col.request_stop(now=True)
            raise KeyboardInterrupt

    old = signal.signal(signal.SIGINT, on_sigint)
    try:
        return col.run(max_runs=args.stop_after)
    except (ChannelError, CaptureError) as exc:
        _out(f"Ошибка: {exc}")
        return EXIT_ERROR
    finally:
        signal.signal(signal.SIGINT, old)


def cmd_tools_check(args, cfg) -> int:
    """Инструменты вариантов и нормы на атакующей машине и запись на сенсорной (код 3 — часть "
    "недоступна)."""
    channel = make_channel(cfg)
    try:
        reply = channel.request({"cmd": "tools"}, 90)
    except ChannelError as exc:
        _out(f"Канал к атакующей: {exc}")
        return EXIT_NOT_READY
    if not reply.get("ok"):
        _out(
            "Раннер не знает команды tools (нужно обновить код: stand/cloud/deploy_lab.py): "
            f"{reply.get('error')}"
        )
        return EXIT_NOT_READY
    tools = reply["tools"]
    missing = sorted(t for t, v in tools.items() if v is None)
    used = {v["binary"] for v in list_variants(cfg.raw)}
    for name in sorted(tools):
        info = tools[name]
        mark = "нет" if info is None else (info["version"] or "есть")
        known = name in used or name in ("curl", "dig", "ssh", "sshpass", "ip")
        _out(f"  {name:<14} {mark}{'' if known else ' (не используется)'}")
    try:
        cap = SensorCapture.from_config(cfg.raw).check()
        _out(f"Сенсорная машина: tcpdump и интерфейс есть, свободно {cap['free_mb']} МБ")
    except CaptureError as exc:
        _out(f"Сенсорная машина: {exc}")
        return EXIT_NOT_READY
    if missing:
        _out(f"Недоступны: {', '.join(missing)} — их варианты будут пропущены при сборе")
        return EXIT_TOOLS
    return EXIT_OK


EXIT_SUSPECT = 5


def _source_names(cfg) -> dict[str, str]:
    return {s["ip"]: s["name"] for s in (cfg.raw["lab"].get("sources") or [])}


def cmd_dataset_build_v2(args, cfg) -> int:
    """Набор версии 2 из каталога сбора (`lab collect`): сегменты записи + журнал → "
    "data/lab/<версия>/ + отчёт качества."""
    import polars as pl

    from mlsiem.lab import journal, quality
    from mlsiem.lab.dataset_v2 import build_dataset_v2

    workdir = Path(args.collect_dir)
    state_path = workdir / collect_mod.STATE_FILE
    if not state_path.exists():
        _out(f"Нет состояния сбора {state_path}: сначала lab collect")
        return EXIT_ERROR
    state = json.loads(state_path.read_text(encoding="utf-8"))
    records = journal.read(workdir / collect_mod.JOURNAL_FILE)
    segments = []
    for s in state["sessions"]:
        pcaps = sorted((workdir / "sessions" / s["session_id"]).glob("session.pcap*"))
        if pcaps:
            segments.append(
                {"session_id": s["session_id"], "pcaps": pcaps, "stats": s.get("capture")}
            )
    if not segments:
        _out("В каталоге сбора нет записей сеансов (sessions/*/session.pcap)")
        return EXIT_ERROR
    version = args.version or datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    out = Path(args.out) if args.out else Path("data/lab") / version
    manifest = build_dataset_v2(
        segments, records, out, version, plan_hash=state.get("plan_hash"), tools=state.get("tools")
    )
    _out(
        f"Набор стенда {version}: {out} ({manifest['n_flows']} потоков, сегментов {len(segments)})"
    )
    _out(f"  классы: {manifest['by_class']}")
    _out(
        f"  неоднозначных: {manifest['ambiguous_share_of_scenarios'] * 100:.1f}% потоков сценариев"
    )
    labeled = pl.read_parquet(out / "flows.parquet")
    rep = quality.quality_report(labeled, source_names=_source_names(cfg))
    md, _ = quality.write_report(rep, out, version)
    _out(f"Качество: {rep['verdict']} → {md}")
    for r in rep["reasons"]:
        _out(f"  ! {r['text']}")
    for w in rep["warnings"]:
        _out(f"  · {w['text']}")
    return EXIT_SUSPECT if rep["verdict"] == "suspect" else EXIT_OK


def cmd_quality(args, cfg) -> int:
    import polars as pl

    from mlsiem.lab import quality

    d = Path(args.dataset)
    if not d.exists():
        d = Path("data/lab") / args.dataset
    path = d / "flows.parquet"
    if not path.exists():
        _out(f"Нет набора {path}")
        return EXIT_ERROR
    labeled = pl.read_parquet(path)
    if "tool" not in labeled.columns:
        _out(
            "Набор версии 1 (006): метаданных варианта нет; отчёт качества строится для набора "
            "версии 2"
        )
        return EXIT_ERROR
    rep = quality.quality_report(labeled, source_names=_source_names(cfg))
    version = d.name
    md, _ = quality.write_report(rep, d, version)
    _out(f"Качество {version}: {rep['verdict']} → {md}")
    for r in rep["reasons"]:
        _out(f"  ! {r['text']}")
    for w in rep["warnings"]:
        _out(f"  · {w['text']}")
    return EXIT_SUSPECT if rep["verdict"] == "suspect" else EXIT_OK


def _resolve_dataset(arg: str) -> Path:
    d = Path(arg)
    return d if d.exists() else Path("data/lab") / arg


def _journal_append(text: str) -> None:
    """Итог — в docs/JOURNAL.md даже при плохом результате (конституция VI).

    Идемпотентно: запись с тем же заголовком (первая непустая строка `### …`) заменяется, а не
    дублируется, — повторный прогон за тот же день обновляет итог.
    """
    path = Path("docs/JOURNAL.md")
    if not path.exists():
        return
    title = next((ln for ln in text.splitlines() if ln.startswith("### ")), None)
    content = path.read_text(encoding="utf-8")
    if title and title in content:
        head, _, rest = content.partition(title)
        nxt = rest.find(chr(10) + "### ")
        content = head.rstrip(chr(10)) + chr(10) + (rest[nxt:] if nxt != -1 else "")
    path.write_text(content.rstrip(chr(10)) + chr(10) + text, encoding="utf-8")


def _mlflow_lab(run_name: str, params: dict, metrics: dict, mlflow_dir: str) -> None:
    """Запись в эксперимент `lab`; сбой MLflow не валит команду — отчёт на диске уже есть."""
    try:
        import mlflow

        mlflow.set_tracking_uri(f"sqlite:///{Path(mlflow_dir) / 'mlflow.db'}")
        mlflow.set_experiment("lab")
        with mlflow.start_run(run_name=run_name):
            mlflow.log_params(params)
            for k, v in metrics.items():
                if v is not None:
                    mlflow.log_metric(k, float(v))
    except Exception as exc:  # noqa: BLE001
        _out(f"MLflow недоступен, метрики не записаны: {exc}")


def cmd_shortcuts(args, cfg) -> int:
    """Аудит ярлыков: исключение инструмента и адреса, признаки окружения (код 5 — вердикт "
    "suspect)."""
    import polars as pl

    from mlsiem.lab import shortcuts

    d = _resolve_dataset(args.dataset)
    path = d / "flows.parquet"
    if not path.exists():
        _out(f"Нет набора {path}")
        return EXIT_ERROR
    labeled = pl.read_parquet(path)
    if "tool" not in labeled.columns:
        _out(
            "Набор версии 1 (006): нет метаданных инструмента; аудит ярлыков строится для набора "
            "версии 2"
        )
        return EXIT_ERROR
    ips = {s["name"]: s["ip"] for s in (cfg.raw["lab"].get("sources") or [])}
    conf = dict(cfg.raw.get("shortcuts") or {})
    rep = shortcuts.run_shortcuts(labeled, source_ips=ips, cfg=conf, seeds=args.seeds, log=_out)
    version = d.name
    md, js = shortcuts.write_report(rep, d, Path(args.reports_dir), version)
    a = rep["env_audit"]
    drops = [r["drop"]["0.01"] for r in rep["exclusion"]["tools"]] + [
        r["drop"]["0.01"] for r in rep["exclusion"]["hosts"]
    ]
    _out(f"Отчёт: {md}")
    _out(
        "  исключение инструмента/адреса: падение полноты при 1% ложных — максимум "
        f"{max(drops):.3f}"
    )
    _out(
        f"  признаки окружения: {a['verdict']} (PR-AUC {a['pr_auc_full']} → "
        f"{a['pr_auc_without_env']}, падение {a['drop']})"
    )
    _mlflow_lab(
        f"lab_shortcuts_{version}",
        {"dataset_version": version, "seeds": str(rep["exclusion"]["seeds"])},
        {"env_audit_drop": a["drop"], "max_exclusion_drop_1pct": max(drops)},
        args.mlflow_dir,
    )
    _journal_append(
        chr(10).join(
            [
                "",
                f"### Ярлыки набора стенда {version} ({datetime.now(UTC).date()})",
                "",
                "- исключение инструмента/адреса: максимальное падение полноты при 1% ложных "
                f"{max(drops):.3f}",
                f"- признаки окружения: {a['verdict']}, PR-AUC {a['pr_auc_full']} → "
                f"{a['pr_auc_without_env']} (порог {a['threshold']})",
                f"- {shortcuts.DISCLAIMER}",
                "",
            ]
        )
    )
    return EXIT_SUSPECT if a["verdict"] == "suspect" else EXIT_OK


def cmd_unknown(args, cfg) -> int:
    """Раздел «неизвестные атаки»: резервные варианты и класс целиком, четыре способа оценки "
    "(FR-021…FR-023)."""
    import polars as pl

    from mlsiem.lab import unknown

    d = _resolve_dataset(args.dataset)
    path = d / "flows.parquet"
    if not path.exists():
        _out(f"Нет набора {path}")
        return EXIT_ERROR
    labeled = pl.read_parquet(path)
    if "reserve_unknown" not in labeled.columns:
        _out("Набор версии 1 (006): нет резерва «неизвестное»; раздел строится для набора версии 2")
        return EXIT_ERROR
    conf = dict(cfg.raw.get("shortcuts") or {})
    seeds = tuple(args.seeds if args.seeds else conf.get("seeds", (0, 1, 2)))
    rep = unknown.run_unknown(
        labeled,
        seeds=seeds,
        fprs=tuple(conf.get("fpr_levels", unknown.DEFAULT_FPR)),
        min_test_flows=int(conf.get("min_test_flows", 100)),
        log=_out,
    )
    version = d.name
    md, js = unknown.write_report(rep, d, Path(args.reports_dir), version)
    _out(f"Отчёт: {md}")
    _out(f"  {unknown.DISCLAIMER}")
    best, metrics = {}, {}
    for g in rep["groups"]:
        name = f"{g['variant'] or g['class']}" + (
            " (класс целиком)" if g["kind"] == "class" else ""
        )
        best[name] = {m: g["unknown"][m]["0.01"]["recall"] for m in rep["methods"]}
        _out(
            f"  {name}: полнота при 1% ложных — "
            + ", ".join(f"{m} {v:.3f}" for m, v in best[name].items())
        )
        # имена метрик MLflow — только латиница, цифры и «_»: пробелы, скобки и кириллицу он не
        # принимает
        key = f"{g['kind']}_{g['variant'] or g['class']}"
        metrics.update({f"recall1pct_{key}_{m}": v for m, v in best[name].items()})
    _mlflow_lab(
        f"lab_unknown_{version}",
        {"dataset_version": version, "seeds": str(list(seeds))},
        metrics,
        args.mlflow_dir,
    )
    _journal_append(
        chr(10).join(
            [
                "",
                f"### Неизвестные атаки на наборе стенда {version} ({datetime.now(UTC).date()})",
                "",
                *[
                    f"- {k}: "
                    + ", ".join(f"{m} {v:.3f}" for m, v in row.items())
                    + " (полнота при 1% ложных)"
                    for k, row in best.items()
                ],
                f"- {unknown.DISCLAIMER}",
                "",
            ]
        )
    )
    return EXIT_OK


def _git_commit() -> str:
    import subprocess

    try:
        done = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=10
        )
        return done.stdout.strip() or "?"
    except Exception:  # noqa: BLE001 — коммит нужен лишь для журнала
        return "?"


def _transfer_log(out: Path, d: Path):
    """Хронологический журнал эксперимента: каждая строка и на экран, и в `log.md` каталога "
    "результатов."""
    log_path = out / "log.md"
    if not log_path.exists():
        log_path.write_text(
            f"# Журнал эксперимента переноса, набор {d.name}\n\n"
            f"Протокол: reports/lab_transfer_protocol_20261024.md. git {_git_commit()}.\n\n",
            encoding="utf-8",
        )

    def log(msg: str) -> None:
        _out(msg)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(f"- {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC — {msg}\n")

    return log


def _transfer_flows_stage(args, d: Path, out: Path, log) -> None:
    from mlsiem.lab import transfer

    def to_mlflow(rec: dict) -> None:
        s, u = rec["stand"], rec["unsw"]
        r1 = s["recall"]["0.01"]["all"]
        metrics = {
            "stand_pr_auc_binary": s["pr_auc_binary"],
            "stand_macro_shared4": s["macro_shared4"],
            "stand_recall_1pct": r1["k"] / max(r1["n"], 1),
            "unsw_pr_auc_binary": u["pr_auc_binary"],
            "fit_seconds": rec["fit_seconds"],
        }
        _mlflow_lab(
            f"transfer_{rec['arm']}_{rec['k']}_{rec['seed']}",
            {"dataset_version": d.name, "arm": rec["arm"], "k": rec["k"], "seed": str(rec["seed"])},
            metrics,
            args.mlflow_dir,
        )

    log("этап 1 (потоки): загрузка данных (UNSW train/test, набор стенда, артефакт)")
    data = transfer.load_real_data(d)
    log(
        f"стенд: {data.stand.height} потоков; UNSW train {len(data.unsw_train[1])}, test "
        f"{len(data.unsw_test[1])}"
    )
    seeds = tuple(args.seeds) if args.seeds else (0, 1, 2)
    curve = tuple(args.curve) if args.curve is not None else (2, 4)
    try:
        results = transfer.run_transfer(
            data, out, seeds=seeds, curve=curve, on_result=to_mlflow, log=log
        )
    except Exception as exc:  # noqa: BLE001 — сбой пишем в журнал; сделанное в results.jsonl сохранено
        log(f"СБОЙ: {type(exc).__name__}: {exc}")
        raise
    md, _ = transfer.write_report(results, out, Path(args.reports_dir), d.name)
    sm = transfer.summarize(results)
    log(f"отчёт: {md}; вывод по критерию протокола: {sm['verdict']['status']}")
    lines = ["", f"### Перенос на трафик стенда {d.name} ({datetime.now(UTC).date()})", ""]
    for name, row in sm["table"].items():
        m = row["metrics"]
        rec1 = m["стенд полнота при 1.0% ложных"]["mean"]
        macro = m["стенд macro PR-AUC (4 общих класса)"]["mean"]
        lines.append(
            f"- {name} (сидов {len(row['seeds'])}): полнота при 1% ложных на стенде {rec1:.3f}, "
            f"macro PR-AUC (4 общих) {macro if macro is None else round(macro, 4)}, "
            f"PR-AUC атака/норма {m['стенд PR-AUC атака/норма']['mean']:.4f}"
        )
    lines += [f"- вывод по критерию протокола: {sm['verdict']['status']}", f"- отчёт: {md}", ""]
    _journal_append(chr(10).join(lines))


def _transfer_windows_stage(args, d: Path, out: Path, log) -> None:
    from mlsiem.lab import transfer_windows as tw

    def to_mlflow(rec: dict) -> None:
        s, u = rec["stand"], rec["unsw"]
        r5 = s["recall"]["0.05"]["all"]
        metrics = {
            "stand_pr_auc_binary": s["pr_auc_binary"],
            "stand_macro_shared4": s["macro_shared4"],
            "stand_recall_5pct": r5["k"] / max(r5["n"], 1),
            "unsw_pr_auc_binary": u["pr_auc_binary"],
        }
        _mlflow_lab(
            f"transfer_windows_{rec['arm']}_{rec['k']}_{rec['seed']}",
            {
                "dataset_version": d.name,
                "level": "windows",
                "arm": rec["arm"],
                "k": rec["k"],
                "seed": str(rec["seed"]),
            },
            metrics,
            args.mlflow_dir,
        )

    log("этап 2 (окна): загрузка данных и построение окон UNSW (минуты)")
    data = tw.load_real_wdata(d)
    seeds = tuple(args.seeds) if args.seeds else (0, 1, 2)
    curve = tuple(args.curve) if args.curve is not None else (2, 4)
    try:
        results = tw.run_windows(data, out, seeds=seeds, curve=curve, on_result=to_mlflow, log=log)
    except Exception as exc:  # noqa: BLE001
        log(f"СБОЙ (окна): {type(exc).__name__}: {exc}")
        raise
    md = tw.write_report(results, Path(args.reports_dir), d.name)
    log(f"отчёт окон: {md}")
    _journal_append(
        chr(10).join(
            [
                "",
                f"### Перенос на трафик стенда, окна {d.name} ({datetime.now(UTC).date()})",
                "",
                f"- отчёт: {md}",
                "",
            ]
        )
    )


def cmd_transfer(args, cfg) -> int:
    """Эксперимент переноса: UNSW-детектор против переобученных с данными стенда (протокол в "
    "reports/)."""
    d = _resolve_dataset(args.dataset)
    if not (d / "flows.parquet").exists():
        _out(f"Нет набора {d / 'flows.parquet'}")
        return EXIT_ERROR
    out = Path(args.out) if args.out else Path("var/lab/transfer") / d.name
    out.mkdir(parents=True, exist_ok=True)
    log = _transfer_log(out, d)
    level = getattr(args, "level", "flows")
    if level in ("flows", "all"):
        _transfer_flows_stage(args, d, out, log)
    if level in ("windows", "all"):
        _transfer_windows_stage(args, d, out, log)
    return EXIT_OK
