"""Артефакт модели окон и эксперт окон для цепочки (фича 007, research R11, R12).

Каталог `models/windows/` (выход DVC-стадии `train_windows`):
- `window_card.json` — всё о модели без её загрузки: версия, вид (lgbm | gru), классы, порог,
  параметры окна (длина, ключ, режим направления, предел последовательности), списки
  признаков, версия схемы 001, РЕШЕНИЕ эксперимента (`accepted`, шаг, цифры, вердикт аудита),
  с какой текущей моделью сравнивали, сид, устройство, версии библиотек;
- `model.joblib` (конвейер LightGBM) или `model.pt` (веса GRU);
- `preprocess.joblib` — предобработка последовательностей и порядок признаков;
- `experiment.json` — полный протокол эксперимента (для аудита и отчётов).

Это граница ML ↔ SOC, как `load_model` в 004: цепочка знает только `load_window_expert`,
`resolve_window_expert` и `WindowExpert`. Победитель сохраняется ВСЕГДА, даже при
отрицательном результате; цепочка включает его только при `accepted: true` (или флагом
`--windows force` — для тестов и демонстрации).

Загрузчик строгий: битая карточка, чужая мажорная версия схемы, классы модели не совпадают с
карточкой — отказ с понятным текстом. Модель, получившая «не те» признаки, выдаёт уверенную
чепуху, и это хуже любой ошибки.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from mlsiem.data.captures import atomic_path
from mlsiem.data.schema import SCHEMA
from mlsiem.detect import metrics as M
from mlsiem.detect import windows as W
from mlsiem.detect.artifact import DetectorLoadError, major
from mlsiem.detect.meta import final_class

log = logging.getLogger("mlsiem")

CARD_FILE = "window_card.json"
LGBM_FILE = "model.joblib"
GRU_FILE = "model.pt"
PREPROCESS_FILE = "preprocess.joblib"
EXPERIMENT_FILE = "experiment.json"
KINDS = ("lgbm", "gru")
AUDIT_VERDICTS = ("clean", "relies_on_artifacts", "not_run")
REQUIRED_CARD_FIELDS = (
    "window_version",
    "kind",
    "classes",
    "threshold",
    "window",
    "summary_features",
    "seq_features",
    "schema_version",
    "decision",
)
TOP_FEATURES = 5
TOP_FLOWS = 20
EXPERT_NAME = "windows"


class WindowExpertLoadError(DetectorLoadError):
    """Артефакт модели окон отсутствует, повреждён или не подходит цепочке."""


class WindowExpertNotAccepted(WindowExpertLoadError):
    """Модель окон не принята экспериментом/аудитом, а `force` не указан."""


def window_version(config_raw: dict, data: dict) -> str:
    """`YYYYMMDD-<хеш8>` — по образцу `detector_version` (002): хеш от конфига эксперимента
    (без `output`) и версии данных. Тот же конфиг и те же данные — та же версия."""
    from mlsiem.detect.artifact import detector_version

    return detector_version(config_raw, data)


def library_versions() -> dict[str, str]:
    from mlsiem.detect.artifact import library_versions as base

    versions = base()
    try:
        import torch

        versions["torch"] = torch.__version__
    except ImportError:
        pass
    return versions


# ================================================================ эксперт


@dataclass
class WindowResult:
    """Результат эксперта окон на входе: окна, соответствие поток → окно, вердикты окон."""

    windows: pl.DataFrame
    assignment: pl.DataFrame
    verdicts: pl.DataFrame
    top_features: dict[str, list[dict]]


@dataclass
class WindowExpert:
    """Загруженная модель окон: вид, модель, предобработка, карточка."""

    kind: str
    model: Any
    preprocess: dict
    card: dict
    path: Path | None = None

    # ---- карточка
    @property
    def version(self) -> str:
        return self.card["window_version"]

    @property
    def classes(self) -> list[str]:
        return list(self.card["classes"])

    @property
    def threshold(self) -> float:
        return float(self.card["threshold"])

    @property
    def length_ms(self) -> int:
        return int(self.card["window"]["length_ms"])

    @property
    def seq_max(self) -> int:
        return int(self.card["window"]["seq_max"])

    @property
    def direction(self) -> str:
        return str(self.card["window"].get("direction", "auto"))

    @property
    def accepted(self) -> bool:
        return bool(self.card["decision"].get("accepted"))

    def describe(self) -> str:
        return f"эксперт окон {self.kind} {self.version}"

    # ---- проверки до прогона (FR-013)
    def check(self, soc_cfg) -> None:
        """Длина окна и режим направления совпадают с конфигом SOC, для каждого класса есть
        уровень серьёзности. Всё — до обработки: падать посреди прогона обидно."""
        from mlsiem.soc.config import check_model_classes

        want = getattr(soc_cfg.windows, "length_ms", None)
        if want is not None and want != self.length_ms:
            raise ValueError(
                f"эксперт окон обучен на окнах {self.length_ms} мс, а configs/soc.yaml "
                f"(windows.length_ms) ждёт {want} мс — переобучите модель окон или поправьте конфиг"
            )
        if soc_cfg.direction != self.direction:
            raise ValueError(
                f"эксперт окон обучен с правилом направления {self.direction!r}, а цепочка "
                f"работает в режиме {soc_cfg.direction!r} (grouping.direction): окна вышли бы "
                "другими — переобучите модель окон или поправьте конфиг"
            )
        check_model_classes(soc_cfg, self.classes)

    # ---- вердикты
    def proba(
        self,
        flows: pl.DataFrame,
        side: pl.DataFrame,
        assignment: pl.DataFrame,
        windows: pl.DataFrame,
    ) -> tuple[np.ndarray, np.ndarray | None]:
        """(вероятности классов в порядке `classes`, сводные признаки для пояснений или None)."""
        if windows.height == 0:
            return np.zeros((0, len(self.classes))), None
        if self.kind == "lgbm":
            X = W.summary_matrix(windows, W.summary_features(flows, side, assignment))
            return self.model.predict_proba(X), X
        from mlsiem.detect.windows_nn import SeqData, predict_gru

        X, mask, scalars = W.sequences(
            flows, side, assignment, windows, seq_max=self.seq_max, scaler=self.preprocess["scaler"]
        )
        return predict_gru(self.model, SeqData(X, mask, scalars)), None

    def verdicts(self, flows: pl.DataFrame, side: pl.DataFrame) -> WindowResult:
        """Окна входа (основная сетка) и вердикт по каждому (data-model «Вердикт окна»).

        Окна строит `build_windows` — та же функция, что при обучении (FR-003). Класс при
        алерте — самый вероятный класс атаки, как у детектора 002 (`final_class`).
        """
        side = side.select(W.SIDE_COLUMNS)
        assignment = W.assign_windows(flows, side, length_ms=self.length_ms)
        windows = W.build_windows(
            flows, side, length_ms=self.length_ms, seq_max=self.seq_max, assignment=assignment
        )
        proba, X = self.proba(flows, side, assignment, windows)
        classes = self.classes
        score = M.attack_score(proba, classes) if len(proba) else np.zeros(0)
        is_alert = score >= self.threshold
        predicted = final_class(proba, classes, is_alert, is_alert, None) if len(proba) else []
        cols = [
            windows["window_id"],
            windows["attacker_ip"],
            windows["window_start_ms"],
            windows["n_flows"],
            windows["truncated"],
            pl.Series("predicted_class", list(predicted), dtype=pl.String),
            pl.Series("attack_score", score, dtype=pl.Float64),
            pl.Series("is_alert", is_alert, dtype=pl.Boolean),
        ]
        cols += [pl.Series(f"p_{c}", proba[:, i], dtype=pl.Float64) for i, c in enumerate(classes)]
        verdicts = pl.DataFrame(cols)
        if "label" in flows.columns:
            labels = W.window_labels(assignment, flows.select("flow_uid", "label"))
            verdicts = verdicts.join(
                labels.select("window_id", pl.col("label").alias("true_label")),
                on="window_id",
                how="left",
            )
        top = self.explain(windows, verdicts, X, proba)
        return WindowResult(windows, assignment, verdicts, top)

    def explain(
        self, windows: pl.DataFrame, verdicts: pl.DataFrame, X: np.ndarray | None, proba
    ) -> dict[str, list[dict]]:
        """Топ-5 признаков окна для алертов: вклад `pred_contrib` LightGBM в класс окна.

        У GRU вкладов признаков нет — его пояснение строится по самым подозрительным потокам
        окна (`top_flows` в `window_info`), здесь пусто.
        """
        out: dict[str, list[dict]] = {}
        if self.kind != "lgbm" or X is None or verdicts.height == 0:
            return out
        alert_rows = np.flatnonzero(verdicts["is_alert"].to_numpy())
        if alert_rows.size == 0:
            return out
        names = list(self.card["summary_features"])
        model = self.model.named_steps["model"]
        Xa = self.model.named_steps["impute"].transform(X[alert_rows])
        contrib = np.asarray(model.predict(Xa, pred_contrib=True))
        F = len(names)
        classes = self.classes
        pred = verdicts["predicted_class"].to_list()
        ids = verdicts["window_id"].to_list()
        for j, row in enumerate(alert_rows):
            k = classes.index(pred[row])
            block = (
                contrib[j, k * (F + 1) : k * (F + 1) + F]
                if contrib.shape[1] > F + 1
                else (contrib[j, :F])
            )
            best = np.argsort(-block, kind="stable")[:TOP_FEATURES]
            out[ids[row]] = [
                {
                    "name": names[i],
                    "value": None if np.isnan(X[row, i]) else round(float(X[row, i]), 6),
                    "contribution": round(float(block[i]), 6),
                }
                for i in best
            ]
        return out

    def summary(self, mode: str) -> dict:
        """Раздел `windows` сводки прогона/сеанса (data-model «Прогон / сеанс»)."""
        return {
            "mode": mode,
            "enabled": True,
            "expert_version": self.version,
            "kind": self.kind,
            "accepted": self.accepted,
            "length_ms": self.length_ms,
            "threshold": self.threshold,
        }


# ================================================================ сохранение и загрузка


def save_window_expert(
    out_dir: Path, *, kind: str, model: Any, preprocess: dict, card: dict
) -> None:
    """Атомарно пишет модель, предобработку и карточку. Файл другого вида удаляется: в
    каталоге не должно остаться `model.pt` от прошлого победителя рядом с `model.joblib`."""
    import joblib

    if kind not in KINDS:
        raise ValueError(f"вид модели окон {kind!r}: поддерживаются {KINDS}")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if kind == "lgbm":
        with atomic_path(out_dir / LGBM_FILE) as tmp:
            joblib.dump(model, tmp)
        (out_dir / GRU_FILE).unlink(missing_ok=True)
    else:
        from mlsiem.detect.windows_nn import save_state

        with atomic_path(out_dir / GRU_FILE) as tmp:
            save_state(model, tmp)
        (out_dir / LGBM_FILE).unlink(missing_ok=True)
    with atomic_path(out_dir / PREPROCESS_FILE) as tmp:
        joblib.dump(preprocess, tmp)
    write_card(out_dir, card)


def write_card(out_dir: Path, card: dict) -> None:
    with atomic_path(Path(out_dir) / CARD_FILE) as tmp:
        tmp.write_text(json.dumps(card, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_card(path: Path) -> dict:
    """Карточка модели окон с проверкой полей — без загрузки самой модели."""
    card_file = Path(path) / CARD_FILE
    if not card_file.exists():
        raise WindowExpertLoadError(
            f"нет модели окон в {path} (ожидался {CARD_FILE}) — сначала обучите её: "
            "`uv run mlsiem detect windows`"
        )
    try:
        card = json.loads(card_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise WindowExpertLoadError(f"{card_file} повреждён: {exc}") from exc
    if not isinstance(card, dict):
        raise WindowExpertLoadError(f"{card_file} повреждён: ожидался JSON-объект")
    missing = [f for f in REQUIRED_CARD_FIELDS if f not in card]
    if missing:
        raise WindowExpertLoadError(f"{card_file} повреждён: нет полей {missing}")
    if card["kind"] not in KINDS:
        raise WindowExpertLoadError(f"{card_file}: неизвестный вид модели {card['kind']!r}")
    if not isinstance(card["decision"], dict) or not isinstance(card["window"], dict):
        raise WindowExpertLoadError(f"{card_file} повреждён: decision и window — объекты")
    if major(card["schema_version"]) != major(SCHEMA.version):
        raise WindowExpertLoadError(
            f"модель окон обучена на схеме признаков {card['schema_version']}, а код — на "
            f"{SCHEMA.version} (разные мажорные версии): переобучите `mlsiem detect windows`"
        )
    return card


def load_window_expert(path: Path = Path("models/windows"), *, force: bool = False) -> WindowExpert:
    """Загружает модель окон со всеми проверками (R11, FR-013).

    `accepted: false` без `force` — `WindowExpertNotAccepted`: непринятая модель в цепочку не
    идёт. Для `gru` без PyTorch — сообщение, как его установить.
    """
    import joblib

    path = Path(path)
    card = read_card(path)
    if not card["decision"].get("accepted") and not force:
        raise WindowExpertNotAccepted(
            f"модель окон {card['window_version']} не принята ({card['decision'].get('reason')}) "
            "— в цепочку не включается; для проверки интеграции — --windows force"
        )
    pre_file = path / PREPROCESS_FILE
    if not pre_file.exists():
        raise WindowExpertLoadError(f"нет файла предобработки {pre_file}")
    try:
        preprocess = joblib.load(pre_file)
    except Exception as exc:  # битый pickle бросает что угодно
        raise WindowExpertLoadError(f"{pre_file} не загружается: {exc}") from exc
    classes = list(card["classes"])
    if card["kind"] == "lgbm":
        model_file = path / LGBM_FILE
        if not model_file.exists():
            raise WindowExpertLoadError(f"нет файла модели {model_file}")
        try:
            model = joblib.load(model_file)
        except Exception as exc:
            raise WindowExpertLoadError(f"{model_file} не загружается: {exc}") from exc
        got = [str(c) for c in getattr(model, "classes_", [])]
        if got != classes:
            raise WindowExpertLoadError(
                f"классы модели {got} не совпадают с карточкой {classes} — файлы от разных "
                "обучений?"
            )
    else:
        from mlsiem.detect.windows_nn import NNUnavailable, load_state

        model_file = path / GRU_FILE
        if not model_file.exists():
            raise WindowExpertLoadError(f"нет файла модели {model_file}")
        try:
            model = load_state(
                model_file, len(card["seq_features"]), len(classes), card["gru_params"]
            )
        except NNUnavailable as exc:
            raise WindowExpertLoadError(f"модель окон вида gru: {exc}") from exc
        except (RuntimeError, KeyError, OSError) as exc:
            raise WindowExpertLoadError(
                f"{model_file} не подходит к карточке (классы {classes}): {exc}"
            ) from exc
    return WindowExpert(kind=card["kind"], model=model, preprocess=preprocess, card=card, path=path)


def update_decision(path: Path, audit: dict) -> dict:
    """Итог аудита → карточка (T035): `audit_verdict`, итоговый `accepted`, `reason`.

    Итоговое `accepted` = шаг 2 выбора пройден И аудит `clean` (FR-012). Версия модели не
    меняется — поменялось только решение о ней. Запись атомарная.
    """
    card = read_card(path)
    d = dict(card["decision"])
    verdict = audit["verdict"]
    if verdict not in AUDIT_VERDICTS:
        raise ValueError(f"вердикт аудита {verdict!r}: ожидалось одно из {AUDIT_VERDICTS}")
    passed = bool(d.get("passed_selection", d.get("accepted")))
    d["passed_selection"] = passed
    d["audit_verdict"] = verdict
    d["accepted"] = passed and verdict == "clean"
    if not passed:
        d["reason"] = f"{d.get('selection_reason') or d.get('reason')}; аудит: {audit['text']}"
    elif verdict == "clean":
        d["step"] = "audit"
        d["reason"] = f"прошёл выбор и аудит: {audit['text']}"
    else:
        d["step"] = "audit"
        d["reason"] = f"снято аудитом: {audit['text']}"
    card["decision"] = d
    write_card(path, card)
    return card


# ================================================================ включение в цепочку (R12)

WINDOW_MODES = ("auto", "off", "force")


@dataclass
class WindowsChoice:
    """Решение «включать ли эксперт окон» — для сводки прогона и сеанса."""

    mode: str
    expert: WindowExpert | None
    reason: str

    def summary(self) -> dict:
        if self.expert is None:
            return {"mode": self.mode, "enabled": False, "reason": self.reason}
        out = self.expert.summary(self.mode)
        out["reason"] = self.reason
        return out

    def describe(self) -> str:
        if self.expert is None:
            return f"эксперт окон: {self.reason}"
        mark = "принудительно" if self.mode == "force" and not self.expert.accepted else "принят"
        return f"{self.expert.describe()} ({mark})"


def resolve_window_expert(
    soc_cfg, mode: str | None = None, path: Path | None = None
) -> WindowsChoice:
    """`auto` — модель есть и принята; `off` — как в 005; `force` — включить и непринятую.

    Все проверки — здесь, до обработки: при ошибке прогон и сеанс не начинаются (FR-013).
    В `auto` непринятая или отсутствующая модель — не ошибка: цепочка работает как в 005.
    """
    mode = mode or soc_cfg.windows.mode
    if mode not in WINDOW_MODES:
        raise ValueError(f"--windows: ожидалось auto, off или force, а передано {mode!r}")
    path = Path(path or soc_cfg.windows.model)
    if mode == "off":
        return WindowsChoice(mode, None, "выключен (windows off)")
    if mode == "auto":
        if not (path / CARD_FILE).exists():
            return WindowsChoice(mode, None, f"нет модели в {path.as_posix()}")
        card = read_card(path)
        if not card["decision"].get("accepted"):
            return WindowsChoice(
                mode,
                None,
                f"не принят ({card['window_version']}: {card['decision'].get('reason')})",
            )
    expert = load_window_expert(path, force=True)
    expert.check(soc_cfg)
    reason = (
        "принят экспериментом и аудитом"
        if expert.accepted
        else ("ВНИМАНИЕ: включён принудительно (--windows force), модель не принята")
    )
    return WindowsChoice(mode, expert, reason)
