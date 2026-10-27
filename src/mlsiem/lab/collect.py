"""Исполнение плана сбора с безопасной остановкой и возобновлением (фича 008, R6, R15, FR-006,
FR-024…FR-029).

Сбор делится на **сеансы**: каждый старт создаёт сеанс со своим сегментом записи (pcap на сенсорной
машине → хост) и сегментом журнала. Запуск — единица атомарности: до запуска в журнал пишется маркер
начала, после — итоговая запись; нет итоговой записи → запуск прерван, его окно в разметке набора
становится неоднозначным, а сам запуск плана повторяется целиком (новая попытка).

Остановка:
- **мягкая** (`request_stop()` / файл `collect.stop` / первый Ctrl+C): текущий запуск доводится до
  конца,
  выдерживается пауза-дренаж (потоки закрываются по idle-таймауту), норма и запись останавливаются,
  состояние сохраняется; в `collect_state.json` ставится `safe_to_power_off`;
- **срочная** (`request_stop(now=True)` / второй Ctrl+C): запуск прерывается, пишется `aborted`.

Управление машинами — через два подменяемых объекта (канал к атакующему и `SensorCapture`), часы и
ожидание тоже подменяются: сценарий остановок проверяют тесты без стенда.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from pathlib import Path

from mlsiem.lab import journal
from mlsiem.lab.capture import CaptureError, SensorCapture
from mlsiem.lab.channel import Channel, ChannelError
from mlsiem.lab.plan import PlanError, read_plan, summarize
from mlsiem.lab.variants import find_variant

STATE_FILE = "collect_state.json"
STOP_FLAG = "collect.stop"
HARD_FLAG = "collect.stop.now"
JOURNAL_FILE = "journal.jsonl"
MAX_ATTEMPTS = 3

EXIT_OK, EXIT_NOT_READY, EXIT_INTERRUPTED = 0, 2, 4


class CollectError(RuntimeError):
    """Сбор невозможен или прерван ошибкой; текст — по-русски."""


class Collector:
    def __init__(
        self,
        raw: dict,
        plan: dict,
        workdir: str | Path,
        channel: Channel,
        capture: SensorCapture,
        *,
        clock: Callable[[], str] = journal.now_iso,
        sleep: Callable[[float], None] = time.sleep,
        host_now: Callable[[], float] = time.time,
        log: Callable[[str], None] = print,
        skew_max_s: float | None = None,
    ):
        self.raw = raw
        self.plan = plan
        self.workdir = Path(workdir)
        self.channel = channel
        self.capture = capture
        self.clock = clock
        self.sleep = sleep
        self.host_now = host_now
        self.log = log
        self.skew_max_s = float(
            skew_max_s if skew_max_s is not None else raw["lab"].get("clock_skew_max_s", 1)
        )
        self.margin_s = float(raw["collection"].get("reply_margin_s", 40))
        self.pause_s = float(plan["pause_s"])
        self.journal_path = self.workdir / JOURNAL_FILE
        self.state_path = self.workdir / STATE_FILE
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.state = self._load_state()
        self._normal_on = False
        self._session_id: str | None = None

    # ---------------------------------------------------------------- состояние

    def _fresh_state(self) -> dict:
        return {
            "plan_hash": self.plan["config_hash"],
            "seed": self.plan["seed"],
            "sessions": [],
            "runs": {},
            "remaining": len(self.plan["runs"]),
            "eta_s": 0.0,
            "safe_to_power_off": True,
        }

    def _load_state(self) -> dict:
        if not self.state_path.exists():
            return self._fresh_state()
        st = json.loads(self.state_path.read_text(encoding="utf-8"))
        if st.get("plan_hash") != self.plan["config_hash"]:
            raise CollectError(
                f"состояние сбора {self.state_path} относится к другому плану (хеш "
                f"{st.get('plan_hash')}, "
                f"а у плана {self.plan['config_hash']}); удалите каталог {self.workdir} или "
                "возьмите прежний план"
            )
        return st

    def _save_state(self) -> None:
        self._update_counts()
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(self.state, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
        )
        os.replace(tmp, self.state_path)

    def _update_counts(self) -> None:
        pending = self._pending_runs()
        self.state["remaining"] = len(pending)
        self.state["eta_s"] = sum(r["duration_limit_s"] + self.pause_s for r in pending)

    def _run_state(self, uid: str) -> dict:
        return self.state["runs"].setdefault(
            uid, {"status": "pending", "attempts": 0, "last_run_uid": None}
        )

    def _pending_runs(self) -> list[dict]:
        out = []
        for r in self.plan["runs"]:
            st = self.state["runs"].get(r["plan_run_uid"], {"status": "pending", "attempts": 0})
            if st["status"] in ("done", "skipped"):
                continue
            if st["status"] == "aborted" and st["attempts"] >= MAX_ATTEMPTS:
                continue
            out.append(r)
        return out

    def _lost_runs(self) -> list[str]:
        """Запуски, исчерпавшие попытки: в план они уже не вернутся, но набор останется без них."""
        return [
            u
            for u, st in self.state["runs"].items()
            if st["status"] == "aborted" and st["attempts"] >= MAX_ATTEMPTS
        ]

    def status(self) -> dict:
        self._update_counts()
        runs = self.state["runs"]
        count = lambda s: sum(1 for v in runs.values() if v["status"] == s)  # noqa: E731
        return {
            "plan_runs": len(self.plan["runs"]),
            "done": count("done"),
            "aborted": count("aborted"),
            "skipped": count("skipped"),
            "lost": len(self._lost_runs()),
            "remaining": self.state["remaining"],
            "sessions": len(self.state["sessions"]),
            "eta_h": round(self.state["eta_s"] / 3600, 1),
            "safe_to_power_off": self.state["safe_to_power_off"],
            "stop_requested": (self.workdir / STOP_FLAG).exists(),
        }

    # ---------------------------------------------------------------- остановка

    def request_stop(self, now: bool = False) -> None:
        """Ставит флаг остановки (мягкой или срочной); работает и из другого процесса."""
        (self.workdir / STOP_FLAG).write_text("stop\n", encoding="utf-8")
        if now:
            (self.workdir / HARD_FLAG).write_text("now\n", encoding="utf-8")

    def _soft_stop(self) -> bool:
        return (self.workdir / STOP_FLAG).exists()

    def _hard_stop(self) -> bool:
        return (self.workdir / HARD_FLAG).exists()

    def _clear_flags(self) -> None:
        for name in (STOP_FLAG, HARD_FLAG):
            (self.workdir / name).unlink(missing_ok=True)

    # ---------------------------------------------------------------- готовность

    def check_ready(self) -> list[str]:
        """Проблемы, мешающие старту (пусто — готово): запись, часы, раннер, инструменты."""
        problems: list[str] = []
        try:
            info = self.capture.check()
            if info["free_mb"] < 3000:
                problems.append(
                    f"на сенсорной машине мало места: {info['free_mb']} МБ (нужно ≥ 3000)"
                )
            skew = self.capture.clock_skew_s(self.host_now)
            if abs(skew) > self.skew_max_s:
                problems.append(
                    f"часы сенсорной машины расходятся с хостом на {skew:+.2f} с (допуск "
                    f"{self.skew_max_s:g} с)"
                )
        except CaptureError as exc:
            problems.append(str(exc))
        try:
            reply = self.channel.request({"cmd": "ping"}, 30)
            if not reply.get("ok") or "variants" not in reply:
                problems.append(
                    "раннер на атакующей машине не знает вариантов (нужно обновить код: lab deploy)"
                )
            clock = self.channel.request({"cmd": "clock"}, 20)
            skew = journal.parse_iso(clock["now"]).timestamp() - self.host_now()
            if abs(skew) > self.skew_max_s:
                problems.append(
                    f"часы атакующей машины расходятся с хостом на {skew:+.2f} с (допуск "
                    f"{self.skew_max_s:g} с)"
                )
        except ChannelError as exc:
            problems.append(str(exc))
        return problems

    def mark_unavailable_tools(self) -> dict[str, str | None]:
        """Запрашивает у раннера инструменты и помечает запуски недоступных как `skipped` (Edge "
        "Case 008)."""
        reply = self.channel.request({"cmd": "tools"}, 60)
        tools = reply.get("tools", {})
        missing: dict[str, str | None] = {}
        for r in self.plan["runs"]:
            binary = r.get("binary") or r["tool"]
            if binary in tools and tools[binary] is None:
                st = self._run_state(r["plan_run_uid"])
                if st["status"] == "pending":
                    st["status"] = "skipped"
                    st["reason"] = f"инструмент {binary} недоступен на атакующей машине"
                missing[binary] = None
        self._save_state()
        return missing

    # ---------------------------------------------------------------- норма

    def _normal(self, start: bool) -> None:
        if start == self._normal_on:
            return
        reply = self.channel.request({"cmd": "normal", "action": "start" if start else "stop"}, 30)
        if not reply.get("ok"):
            self.log(f"предупреждение: норма {'start' if start else 'stop'}: {reply.get('error')}")
            return
        self._normal_on = start
        if not start and reply.get("record"):
            journal.append(self.journal_path, reply["record"])

    # ---------------------------------------------------------------- запуск

    def _execute(self, run: dict, attempt: int) -> str:
        """Выполняет запуск плана; возвращает исход: completed | aborted | rejected."""
        uid = f"{run['plan_run_uid']}#{attempt}"
        var = find_variant(self.raw, run["scenario"], run["variant"], run["version"])
        from mlsiem.lab.scenarios import targets_of

        targets = targets_of(self.raw, var)
        meta = {
            "run_uid": uid,
            "plan_run_uid": run["plan_run_uid"],
            "repeat": run["repeat"],
            "part": run["part"],
            "attempt": attempt,
            "session_id": self._session_id,
            "concurrent": "normal" if run["with_normal"] else None,
        }
        journal.append_marker(
            self.journal_path,
            journal.make_start_marker(
                run_uid=uid,
                started_at=self.clock(),
                name=run["scenario"],
                source_ip=run["source_ip"],
                version=run["version"],
                targets=targets,
                expected_class=run["expected_class"],
                variant=run["variant"],
                tool=run["tool"],
                params=run["params"],
                source=run["source"],
                repeat=run["repeat"],
                part=run["part"],
                plan_run_uid=run["plan_run_uid"],
                attempt=attempt,
                session_id=self._session_id,
                reserve_unknown=run["reserve_unknown"],
            ),
        )
        try:
            reply = self.channel.request(
                {
                    "cmd": "variant",
                    "scenario": run["scenario"],
                    "variant": run["variant"],
                    "params": run["params"],
                    "source_ip": run["source_ip"],
                    "meta": meta,
                },
                run["duration_limit_s"] + self.margin_s,
            )
        except (ChannelError, KeyboardInterrupt) as exc:
            # Исход неизвестен: инструмент на машине мог работать до предела длительности
            closed = journal.close_pending(
                self.journal_path, self.clock(), limit_s=float(run["duration_limit_s"])
            )
            self.log(
                f"запуск {uid} прерван ({type(exc).__name__}); окно закрыто как aborted "
                f"({len(closed)})"
            )
            if isinstance(exc, KeyboardInterrupt):
                raise
            return "aborted"
        rec = reply.get("record")
        if not rec:
            closed = journal.close_pending(
                self.journal_path, self.clock(), limit_s=float(run["duration_limit_s"])
            )
            self.log(
                f"запуск {uid}: раннер ответил без записи ({reply.get('error')}); закрыто как "
                f"aborted ({len(closed)})"
            )
            return "aborted"
        journal.append(self.journal_path, rec)
        return rec["outcome"]

    def _pause(self, seconds: float) -> None:
        """Пауза-дренаж: потоки предыдущего запуска закрываются по idle-таймауту; срочная "
        "остановка её обрывает."""
        waited = 0.0
        while waited < seconds and not self._hard_stop():
            self.sleep(1.0)
            waited += 1.0

    # ---------------------------------------------------------------- сеанс

    def _new_session_id(self) -> str:
        return f"s{len(self.state['sessions']) + 1:02d}"

    def run(self, *, max_runs: int | None = None, skip_ready_check: bool = False) -> int:
        """Выполняет оставшиеся запуски плана. Коды: 0 — план выполнен, 2 — не готово, 4 — "
        "остановлено."""
        if not skip_ready_check:
            problems = self.check_ready()
            if problems:
                for p in problems:
                    self.log(f"не готово: {p}")
                return EXIT_NOT_READY
        # Прерванные запуски прошлого сеанса (обрыв питания) закрываются как aborted до первого
        # запуска
        journal.close_pending(self.journal_path, self.clock(), limit_s=150.0)
        self._clear_flags()
        self.mark_unavailable_tools()
        self._reopen_aborted()
        self._session_id = self._new_session_id()
        session = {
            "session_id": self._session_id,
            "started": self.clock(),
            "stopped": None,
            "stop_kind": None,
            "files": [],
            "capture": None,
        }
        self.state["sessions"].append(session)
        self.state["safe_to_power_off"] = False
        self._save_state()
        self.capture.start(self._session_id)
        self.log(
            f"сеанс {self._session_id}: запись запущена, осталось запусков "
            f"{self.state['remaining']}"
        )
        done_now, kind = 0, "complete"
        try:
            while True:
                pending = self._pending_runs()
                if not pending:
                    break
                if self._soft_stop() or (max_runs is not None and done_now >= max_runs):
                    kind = "soft"
                    break
                run = pending[0]
                st = self._run_state(run["plan_run_uid"])
                st["attempts"] += 1
                attempt = st["attempts"]
                self._normal(bool(run["with_normal"]))
                if not run["with_normal"]:
                    self.sleep(3.0)  # конец потоков нормы до начала атаки
                self.log(
                    f"[{run['repeat']}/{self.plan['repeats']}] {run['scenario']}/{run['variant']} "
                    f"с {run['source']} (попытка {attempt})"
                )
                try:
                    outcome = self._execute(run, attempt)
                except KeyboardInterrupt:
                    st["status"] = "aborted"
                    kind = "hard"
                    break
                st["last_run_uid"] = f"{run['plan_run_uid']}#{attempt}"
                st["status"] = "done" if outcome == "completed" else "aborted"
                self._save_state()
                done_now += 1
                self._normal(True)
                self._pause(self.pause_s)
                if self._hard_stop():
                    kind = "hard"
                    break
        finally:
            self._finalize(session, kind)
        return EXIT_OK if not self._pending_runs() and not self._lost_runs() else EXIT_INTERRUPTED

    def _reopen_aborted(self) -> None:
        """Прерванные запуски (не исчерпавшие попытки) снова ставятся в очередь."""
        for st in self.state["runs"].values():
            if st["status"] == "aborted" and st["attempts"] < MAX_ATTEMPTS:
                st["status"] = "pending"

    def _finalize(self, session: dict, kind: str) -> None:
        """Остановка норме и записи, выгрузка сегмента, сохранение состояния; "
        "`safe_to_power_off`."""
        session["stop_kind"] = kind
        try:
            self._normal(False)
        except (ChannelError, KeyboardInterrupt):
            self.log("предупреждение: норму остановить не удалось")
        try:
            stats = self.capture.stop(self._session_id)
            session["capture"] = stats
            session["files"] = self.capture.fetch(
                self._session_id, self.workdir / "sessions" / self._session_id
            )
        except CaptureError as exc:
            self.log(f"ОШИБКА записи сеанса: {exc}; файлы сеанса остались на сенсорной машине")
            session["capture_error"] = str(exc)
        session["stopped"] = self.clock()
        self.state["safe_to_power_off"] = "capture_error" not in session
        self._save_state()
        self.log(
            f"сеанс {self._session_id} закончен ({kind}); можно выключать: "
            f"{self.state['safe_to_power_off']}"
        )


def load_collector(
    raw: dict,
    plan_path: str | Path,
    workdir: str | Path,
    channel: Channel,
    capture: SensorCapture,
    **kw,
) -> Collector:
    try:
        plan = read_plan(plan_path)
    except (PlanError, OSError, json.JSONDecodeError) as exc:
        raise CollectError(f"план не прочитан: {exc}") from exc
    return Collector(raw, plan, workdir, channel, capture, **kw)


def print_plan_summary(plan: dict, log: Callable[[str], None] = print) -> None:
    s = summarize(plan)
    log(f"план: {s['runs']} запусков, около {s['hours']} ч; по частям {s['by_part']}")
    log(f"  классы: {s['by_class']}")
    log(f"  инструменты: {s['by_tool']}")
    log(
        f"  источники: {s['by_source']}; с нормой в атаке: {s['with_normal']}; резерв "
        f"«неизвестное»: {s['reserve_runs']}"
    )
