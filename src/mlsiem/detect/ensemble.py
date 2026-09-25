"""Ансамбль экспертов: эксперимент 004 и общий интерфейс модели для цепочки (research R5, R7).

Две части.

1. `load_model(path)` — единая граница «ML ↔ SOC». Принимает каталог детектора 002
   (`model_card.json`) или ансамбля (`ensemble_card.json`) и возвращает `LoadedModel` с одним
   и тем же интерфейсом: версия, классы, порог, признаки, эксперты и `verdict_frame(flows)`.
   Цепочка `soc.run` не знает, что внутри — один детектор или ансамбль.

2. `run_ensemble_experiment(cfg)` — эксперимент «эксперты + мета-слой против лучшего
   одиночного эксперта» (US1, US2). Порядок строго такой, чтобы test ни на что не влиял
   (принцип III, contracts/cli.md):
   классификатор 002 → эксперт аномалий (норма train, порог на норме val) → мета-кандидаты
   (OOF по блокам времени val, пороги на OOF) → «скрытый класс» → выбор по FR-010 только
   по val → метрики test всех вариантов (только отчёт) → артефакты и отчёт.

Правило выбора (FR-010, clarify Q1): ансамбль принимается, если на val он лучше лучшего
одиночного эксперта на `min_gain` macro PR-AUC, ИЛИ ловит скрытые классы на `min_unknown_gain`
лучше, а macro PR-AUC при этом падает не больше чем на `min_gain`. Иначе в цепочку идёт
классификатор 002 — и это честно записывается как отрицательный результат.
"""

from __future__ import annotations

import gc
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from mlsiem.data.captures import atomic_path
from mlsiem.data.extract import read_parquet_metadata
from mlsiem.data.schema import SCHEMA
from mlsiem.detect import metrics as M
from mlsiem.detect.anomaly import (
    AnomalyExpert,
    anomaly_features,
    fit_anomaly_expert,
    load_anomaly_expert,
    save_anomaly_expert,
)
from mlsiem.detect.artifact import (
    CARD_FILE as DETECTOR_CARD,
)
from mlsiem.detect.artifact import (
    Detector,
    DetectorLoadError,
    detector_version,
    library_versions,
    load_detector,
    major,
)
from mlsiem.detect.config import EnsembleConfig
from mlsiem.detect.dataset import data_hashes, load_part, scan_part
from mlsiem.detect.meta import (
    ANY_FIRED_THRESHOLD,
    RULE_CANDIDATES,
    StackModel,
    explain,
    final_class,
    meta_input,
    oof_predict,
    rescale_proba,
    rule_scores,
    time_blocks,
    top_attack,
)

log = logging.getLogger("mlsiem")

ENSEMBLE_CARD = "ensemble_card.json"
META_FILE = "meta.joblib"
EXPERIMENT_FILE = "experiment.json"
REPORT_NAME = "ensemble_experiment.md"
MLFLOW_EXPERIMENT = "ensemble"
SINGLE = "single:classifier"
REQUIRED_ENSEMBLE_FIELDS = (
    "ensemble_version",
    "selected",
    "experts",
    "classes",
    "threshold",
    "schema_version",
)


# ================================================================ общий интерфейс модели


def combine(
    variant: str,
    P: np.ndarray,
    classes: list[str],
    anomaly_pct: np.ndarray,
    clf_threshold: float,
    anomaly_threshold: float,
    stack: StackModel | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    """(вероятности итогового вердикта, скор атаки) для мета-кандидата.

    Скор правил считается прямо правилом, а не как `1 − P(benign)` пересчитанных
    вероятностей: иначе на самом пороге any_fired мог бы «съехать» из-за округления.
    """
    if variant in RULE_CANDIDATES:
        score = rule_scores(variant, P, classes, anomaly_pct, clf_threshold, anomaly_threshold)
        return rescale_proba(P, classes, score), score
    if variant == "stack_logreg":
        if stack is None:
            raise ValueError("для stack_logreg нужна обученная мета-модель (meta.joblib)")
        proba = stack.predict_proba(meta_input(P, anomaly_pct))
        return proba, 1.0 - proba[:, classes.index(M.BENIGN)]
    raise ValueError(f"неизвестный кандидат мета-слоя {variant!r}")


@dataclass
class LoadedModel:
    """Модель прогона: детектор 002 или ансамбль — с одинаковым интерфейсом для цепочки.

    - `kind` — `detector` | `ensemble`; `version` — версия детектора или ансамбля;
    - `selected` — выбор эксперимента (`ensemble:<мета>` | `single:classifier`);
      у детектора 002 — None;
    - `classes`, `threshold` — классы классификатора и порог итогового вердикта;
    - `experts`, `experts_meta` — какие эксперты участвуют, их версии и пороги;
    - `verdict_frame(flows)` — вердикты всех потоков (data-model «Вердикт потока»).
    """

    kind: str
    version: str
    selected: str | None
    classifier: Detector
    anomaly: AnomalyExpert | None = None
    variant: str | None = None
    stack: StackModel | None = None
    ensemble_threshold: float | None = None
    card: dict = field(default_factory=dict)

    @property
    def classes(self) -> list[str]:
        return self.classifier.classes

    @property
    def threshold(self) -> float:
        return float(self.ensemble_threshold if self.variant else self.classifier.threshold)

    @property
    def schema_version(self) -> str:
        return self.classifier.schema_version

    @property
    def experts(self) -> list[str]:
        return ["classifier", "anomaly"] if self.anomaly is not None else ["classifier"]

    @property
    def output_classes(self) -> list[str]:
        """Классы, которые может выдать итоговый вердикт: классы классификатора и `anomaly`,
        если в модели есть детектор аномалий (для проверки таблицы серьёзности SOC)."""
        extra = [M.ANOMALY_CLASS] if self.anomaly is not None else []
        return [*self.classes, *extra]

    @property
    def features(self) -> list[str]:
        """Объединение признаков экспертов в порядке схемы (для чтения входа)."""
        need = set(self.classifier.features)
        if self.anomaly is not None:
            need |= set(self.anomaly.features)
        order = SCHEMA.feature_columns()
        return [f for f in order if f in need] + sorted(need - set(order))

    @property
    def experts_meta(self) -> dict[str, dict]:
        meta = {
            "classifier": {
                "kind": "classifier",
                "version": self.classifier.version,
                "threshold": self.classifier.threshold,
                "classes": self.classifier.classes,
            }
        }
        if self.anomaly is not None:
            meta["anomaly"] = {
                "kind": "anomaly",
                "version": self.anomaly.version,
                "threshold": self.anomaly.threshold,
            }
        return meta

    def describe(self) -> str:
        """Как модель называется в сводках: «ансамбль <версия> (<вариант>)» или «детектор …»."""
        if self.kind == "ensemble":
            return f"ансамбль {self.version} ({self.selected})"
        return f"детектор {self.version}"

    def summary(self) -> dict:
        """Раздел `model` сводки прогона (data-model «Прогон»)."""
        return {
            "kind": self.kind,
            "version": self.version,
            "selected": self.selected,
            "experts": {n: m["version"] for n, m in self.experts_meta.items()},
        }

    def check_input(self, schema_version: str | None, columns: list[str]) -> None:
        self.classifier.check_input(schema_version, columns)
        if self.anomaly is not None:
            self.anomaly.check_input(schema_version, columns)

    def check_parquet(self, path: Path) -> None:
        import pyarrow.parquet as pq

        meta = read_parquet_metadata(Path(path))
        self.check_input(meta.get("mlsiem.schema_version"), pq.read_schema(path).names)

    def verdict_frame(self, flows: pl.DataFrame) -> pl.DataFrame:
        """Вердикт для каждого потока (вход сортируется по flow_uid — порядок не важен).

        Колонки: flow_uid, predicted_class, attack_score, is_alert, p_<класс>…,
        e_<эксперт>_score, e_<эксперт>_fired, explanation (только у алертов), true_label
        (если во входе есть `label`; в модели метка не участвует).
        """
        flows = flows.sort("flow_uid")
        classes = self.classes
        clf = self.classifier
        n = flows.height
        P = np.zeros((0, len(classes))) if n == 0 else clf.predict_proba(flows)
        s_c = M.attack_score(P, classes)
        fired_c = s_c >= clf.threshold
        a = fired_a = None
        if self.anomaly is not None:
            a = self.anomaly.score(flows)
            fired_a = a >= self.anomaly.threshold
        if self.variant is not None:
            proba, score = combine(
                self.variant, P, classes, a, clf.threshold, self.anomaly.threshold, self.stack
            )
            is_alert = score >= self.ensemble_threshold
        else:
            proba, score, is_alert = P, s_c, fired_c
        predicted = final_class(proba, classes, is_alert, fired_c, fired_a)
        clf_cls = top_attack(P, classes)

        explanations: list[str | None] = [None] * n
        for i in np.flatnonzero(is_alert):
            kwargs: dict[str, Any] = {
                "clf_class": str(clf_cls[i]),
                "clf_score": float(s_c[i]),
                "clf_threshold": clf.threshold,
                "clf_fired": bool(fired_c[i]),
            }
            if a is not None:
                kwargs.update(
                    anomaly_score=float(a[i]),
                    anomaly_threshold=self.anomaly.threshold,
                    anomaly_fired=bool(fired_a[i]),
                    meta_score=float(score[i]),
                    meta_threshold=self.threshold,
                )
            explanations[i] = explain(**kwargs)

        cols = [
            flows["flow_uid"],
            pl.Series("predicted_class", predicted, dtype=pl.String),
            pl.Series("attack_score", score, dtype=pl.Float64),
            pl.Series("is_alert", is_alert, dtype=pl.Boolean),
        ]
        cols += [pl.Series(f"p_{c}", proba[:, i], dtype=pl.Float64) for i, c in enumerate(classes)]
        cols += [
            pl.Series("e_classifier_score", s_c, dtype=pl.Float64),
            pl.Series("e_classifier_fired", fired_c, dtype=pl.Boolean),
        ]
        if a is not None:
            cols += [
                pl.Series("e_anomaly_score", a, dtype=pl.Float64),
                pl.Series("e_anomaly_fired", fired_a, dtype=pl.Boolean),
            ]
        cols.append(pl.Series("explanation", explanations, dtype=pl.String))
        if "label" in flows.columns:
            cols.append(flows["label"].alias("true_label"))
        return pl.DataFrame(cols)


def _read_card(path: Path, what: str) -> dict:
    try:
        card = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DetectorLoadError(f"{what}: {path} повреждён: {exc}") from exc
    if not isinstance(card, dict):
        raise DetectorLoadError(f"{what}: {path} повреждён: ожидался JSON-объект")
    return card


def _expert_path(entry: dict) -> Path:
    return Path(entry.get("path") or "")


def load_model(path: Path) -> LoadedModel:
    """Детектор 002 или ансамбль — по тому, какая карточка лежит в каталоге (R7, FR-014).

    Все проверки — здесь, до какой-либо обработки: каждый эксперт на месте, его версия
    совпадает с записанной в карточке ансамбля, мажорная версия схемы у всех одна, для
    обучаемого мета-слоя есть `meta.joblib`. Любое нарушение — `DetectorLoadError` с именем
    эксперта: аналитик должен понять, ЧТО чинить.
    """
    import joblib

    path = Path(path)
    if (path / ENSEMBLE_CARD).exists():
        card = _read_card(path / ENSEMBLE_CARD, "ансамбль")
        lacking = [f for f in REQUIRED_ENSEMBLE_FIELDS if f not in card]
        if lacking:
            raise DetectorLoadError(
                f"ансамбль: {path / ENSEMBLE_CARD} повреждён: нет полей {lacking}"
            )
        experts = {e.get("name"): e for e in card["experts"] if isinstance(e, dict)}
        if "classifier" not in experts:
            raise DetectorLoadError("ансамбль: в карточке нет эксперта classifier")
        loaded: dict[str, Any] = {}
        for name, entry in experts.items():
            where = _expert_path(entry)
            try:
                obj = load_detector(where) if name == "classifier" else load_anomaly_expert(where)
            except DetectorLoadError as exc:
                raise DetectorLoadError(f"ансамбль: эксперт {name} не загружается: {exc}") from exc
            if obj.version != entry.get("version"):
                raise DetectorLoadError(
                    f"ансамбль: эксперт {name} в {where} другой версии ({obj.version}), "
                    f"чем записано в карточке ансамбля ({entry.get('version')}) — эксперта "
                    "переобучили без ансамбля; перезапустите `mlsiem detect ensemble`"
                )
            if major(obj.schema_version) != major(card["schema_version"]):
                raise DetectorLoadError(
                    f"ансамбль: эксперт {name} обучен на схеме {obj.schema_version}, а ансамбль — "
                    f"на {card['schema_version']} (разные мажорные версии)"
                )
            loaded[name] = obj
        selected = card["selected"]
        variant = stack = None
        anomaly = None
        if selected != SINGLE:
            kind, _, variant = selected.partition(":")
            if kind != "ensemble" or not variant:
                raise DetectorLoadError(f"ансамбль: непонятный выбранный вариант {selected!r}")
            if "anomaly" not in loaded:
                raise DetectorLoadError("ансамбль: выбран мета-слой, но нет эксперта anomaly")
            anomaly = loaded["anomaly"]
            if variant == "stack_logreg":
                meta_file = path / META_FILE
                if not meta_file.exists():
                    raise DetectorLoadError(
                        f"ансамбль: выбран обучаемый мета-слой {variant}, а файла {meta_file} нет"
                    )
                try:
                    stack = joblib.load(meta_file)
                except Exception as exc:  # битый pickle
                    raise DetectorLoadError(
                        f"ансамбль: мета-слой {meta_file} не загружается: {exc}"
                    ) from exc
                if not isinstance(stack, StackModel):
                    raise DetectorLoadError(f"ансамбль: в {meta_file} не мета-модель")
        clf = loaded["classifier"]
        if list(card["classes"]) != clf.classes:
            raise DetectorLoadError(
                f"ансамбль: классы карточки {card['classes']} не совпадают с классами "
                f"классификатора {clf.classes}"
            )
        return LoadedModel(
            kind="ensemble",
            version=card["ensemble_version"],
            selected=selected,
            classifier=clf,
            anomaly=anomaly,
            variant=variant,
            stack=stack,
            ensemble_threshold=float(card["threshold"]) if variant else None,
            card=card,
        )
    if (path / DETECTOR_CARD).exists():
        det = load_detector(path)
        return LoadedModel(kind="detector", version=det.version, selected=None, classifier=det)
    raise DetectorLoadError(
        f"в {path} нет ни карточки ансамбля ({ENSEMBLE_CARD}), ни карточки детектора "
        f"({DETECTOR_CARD}) — обучите модель: `uv run mlsiem detect ensemble` или "
        "`uv run mlsiem detect train`"
    )


# ================================================================ правило выбора (FR-010)


def select_variant(
    val_macro: dict[str, float],
    unknown_gain: dict[str, float | None],
    *,
    min_gain: float,
    min_unknown_gain: float,
    order: list[str] | tuple[str, ...],
) -> dict:
    """Выбор варианта ТОЛЬКО по val (FR-010). Метрик test сигнатура не принимает вовсе.

    - `val_macro`: вариант → macro PR-AUC на val (OOF для мета-кандидатов). Обязателен
      `classifier` — лучший одиночный эксперт: у детектора аномалий нет классов, macro
      PR-AUC у него не определён, поэтому «одиночный» по macro — только классификатор;
    - `unknown_gain`: мета-вариант → средний по скрытым классам прирост поимки итогового
      вердикта над классификатором, не видевшим класса (val);
    - `order`: мета-кандидаты от простого к сложному — при равенстве берётся более простой.

    Вариант проходит, если (а) прирост macro ≥ min_gain, или (б) прирост поимки ≥
    min_unknown_gain и macro упал не больше чем на min_gain. Если кто-то прошёл по (а) —
    из них наибольший macro PR-AUC; иначе из прошедших по (б) — наибольшая поимка скрытых.
    Если не прошёл никто — `single:classifier` и честный отрицательный результат.
    """
    if "classifier" not in val_macro:
        raise ValueError("нет результата одиночного эксперта classifier на val")
    base = val_macro["classifier"]
    rows = []
    for v in order:
        if v not in val_macro:
            continue
        gain = val_macro[v] - base
        ug = unknown_gain.get(v)
        cond_a = gain >= min_gain - 1e-12
        cond_b = ug is not None and ug >= min_unknown_gain - 1e-12 and gain >= -min_gain - 1e-12
        rows.append(
            {
                "variant": v,
                "macro_gain": gain,
                "unknown_gain": ug,
                "passes": "macro_gain" if cond_a else ("unknown_gain" if cond_b else None),
            }
        )
    by_macro = [r for r in rows if r["passes"] == "macro_gain"]
    by_unknown = [r for r in rows if r["passes"] == "unknown_gain"]
    best = None
    # max с ключом берёт ПЕРВЫЙ максимум — при равенстве это более простой кандидат
    if by_macro:
        # Условие (а) сильнее: вариант лучше и на известных классах — берём лучший по macro
        best = max(by_macro, key=lambda r: r["macro_gain"])
    elif by_unknown:
        # Только условие (б): вариант принят ради неизвестных атак — берём лучший по поимке
        best = max(by_unknown, key=lambda r: r["unknown_gain"])
    if best is not None:
        v = best["variant"]
        if best["passes"] == "macro_gain":
            text = (
                f"ансамбль {v} лучше классификатора на val на {best['macro_gain']:+.4f} macro "
                f"PR-AUC (≥ {min_gain}) — выбран ensemble:{v} (условие macro_gain)"
            )
        else:
            text = (
                f"ансамбль {v} ловит скрытые классы на val лучше на {best['unknown_gain']:+.4f} "
                f"(≥ {min_unknown_gain}), а macro PR-AUC изменился на {best['macro_gain']:+.4f} "
                f"(падение не больше {min_gain}) — выбран ensemble:{v} (условие unknown_gain)"
            )
        return {
            "selected": f"ensemble:{v}",
            "condition": best["passes"],
            "text": text,
            "rows": rows,
            "best_single": "classifier",
        }
    return {
        "selected": SINGLE,
        "condition": "none",
        "text": (
            "отрицательный результат: ни один вариант ансамбля не дал на val ни +"
            f"{min_gain} macro PR-AUC, ни +{min_unknown_gain} поимки скрытых классов без "
            f"падения macro больше {min_gain} — в цепочке остаётся одиночный классификатор 002"
        ),
        "rows": rows,
        "best_single": "classifier",
    }


# ================================================================ эксперимент


def evaluate_variant(
    y: np.ndarray,
    proba: np.ndarray,
    score: np.ndarray,
    classes: list[str],
    threshold: float,
    only_anomaly: np.ndarray | None = None,
) -> dict:
    """Метрики варианта на части: PR-AUC по классам и macro, «атака/не атака», F1 при пороге."""
    per_class = M.per_class_pr_auc(y, proba, classes)
    alerts = score >= threshold
    out = {
        "macro_pr_auc": M.macro_pr_auc(per_class),
        "per_class": per_class,
        "pr_auc_binary": M.binary_pr_auc(np.asarray(y) != M.BENIGN, score),
        "binary": M.binary_report(np.asarray(y) != M.BENIGN, score, threshold),
        "classes_without_examples": M.classes_without_examples(per_class),
        "n_flows": int(len(y)),
    }
    if only_anomaly is not None:
        # SC-002: норма, ставшая алертом ТОЛЬКО из-за детектора аномалий
        out["benign_alert_only_anomaly"] = M.fpr_on_benign(y, alerts & only_anomaly)
        out["n_only_anomaly_alerts"] = int((alerts & only_anomaly).sum())
    return out


@dataclass
class _Experts:
    """Ответы экспертов на одной части: P классификатора, перцентиль аномалий, срабатывания."""

    P: np.ndarray
    a: np.ndarray
    fired_c: np.ndarray
    fired_a: np.ndarray


def _classifier_winner_params(classifier_dir: Path) -> tuple[str, dict]:
    """Кандидат и гиперпараметры классификатора 002 — из его experiment.json (R5)."""
    exp_file = Path(classifier_dir) / EXPERIMENT_FILE
    if not exp_file.exists():
        raise ValueError(
            f"нет {exp_file}: для эксперимента «скрытый класс» нужно знать, как обучался "
            "классификатор (кандидат и гиперпараметры) — перезапустите `mlsiem detect train`"
        )
    exp = json.loads(exp_file.read_text(encoding="utf-8"))
    winner = exp["winner"]
    return winner, dict(exp["config"]["candidates"][winner])


def _fit_meta(variant, P, a, y, classes, thr_c, thr_a, seed, blocks) -> dict:
    """OOF-предсказания мета-кандидата на val, его порог и финальная модель на всей val."""
    if variant in RULE_CANDIDATES:
        proba, score = combine(variant, P, classes, a, thr_c, thr_a)
        if variant == "any_fired":
            thr = ANY_FIRED_THRESHOLD
        else:
            thr = M.choose_threshold(y != M.BENIGN, score)
        return {"proba": proba, "score": score, "threshold": thr, "stack": None}
    X = meta_input(P, a)

    def fit_fn(X_tr, y_tr):
        model = StackModel(classes, seed).fit(X_tr, y_tr)
        return model.predict_proba

    proba = oof_predict(fit_fn, X, y, blocks)
    score = 1.0 - proba[:, classes.index(M.BENIGN)]
    thr = M.choose_threshold(y != M.BENIGN, score)
    stack = StackModel(classes, seed).fit(X, y)
    return {"proba": proba, "score": score, "threshold": thr, "stack": stack}


def _jsonable(obj):
    """numpy → обычные типы Python для json.dumps."""
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, np.ndarray):
        return [_jsonable(v) for v in obj.tolist()]
    if isinstance(obj, np.bool_):
        return bool(obj)
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, Path):
        return obj.as_posix()
    return obj


def ensemble_version(config_raw: dict, experts: dict[str, str], data: dict) -> str:
    """`YYYYMMDD-<хеш8>` от конфига, версий экспертов и хешей данных (как у детектора 002)."""
    return detector_version({**config_raw, "experts": experts}, data)


def run_ensemble_experiment(
    cfg: EnsembleConfig,
    *,
    data_dir: Path = Path("data"),
    reports_dir: Path = Path("reports"),
    mlflow_dir: Path = Path("."),
    force_variant: str | None = None,
) -> dict:
    """Весь эксперимент 004. Возвращает содержимое experiment.json.

    `force_variant` — ТОЛЬКО для тестов цепочки (чтобы у неё всегда были два эксперта):
    подменяет выбор, и это честно пишется в карточку (`selection.forced: true`). У CLI
    такого флага нет.
    """
    from mlsiem.detect.audit_models import audit_expert, meta_weights
    from mlsiem.detect.candidates import build_candidate
    from mlsiem.detect.experiment import _setup_mlflow, git_commit

    started_all = time.perf_counter()
    data_dir = Path(data_dir)

    # ---- 1. Классификатор 002 и проверки — до любого обучения
    clf = load_detector(cfg.classifier)
    classes = clf.classes
    if major(clf.schema_version) != major(SCHEMA.version):
        raise ValueError(
            f"классификатор обучен на схеме {clf.schema_version}, а данные — схема {SCHEMA.version}"
        )
    clf_split = (clf.card.get("data") or {}).get("split")
    if clf_split is not None and clf_split != cfg.split:
        raise ValueError(
            f"классификатор обучен на разбиении {clf_split}, а эксперимент — на {cfg.split}: "
            "метрики не сравнить (FR-002)"
        )
    bad_hidden = [h for h in cfg.hidden_classes if h not in classes]
    if bad_hidden:
        raise ValueError(
            f"ключ hidden_classes: классов {bad_hidden} нет у классификатора ({classes})"
        )
    winner_name, winner_params = _classifier_winner_params(cfg.classifier)
    if force_variant is not None and force_variant not in cfg.meta.candidates:
        raise ValueError(f"force_variant {force_variant!r} не из meta.candidates")
    data = data_hashes(cfg.split, data_dir)
    mlflow = _setup_mlflow(mlflow_dir, MLFLOW_EXPERIMENT)
    commit = git_commit()

    # ---- 2. val и test: признаки, метки, время (val — для блоков OOF)
    log.info("Загружаю %s: val / test…", cfg.split)
    val = load_part(cfg.split, "val", data_dir=data_dir)
    test = load_part(cfg.split, "test", data_dir=data_dir)
    t_val = (
        scan_part(cfg.split, "val", data_dir=data_dir, columns=["bidirectional_first_seen_ms"])
        .collect()["bidirectional_first_seen_ms"]
        .to_numpy()
    )
    y_val, y_test = val.y, test.y

    def P_of(part, pipe=clf.pipeline, feats=clf.features) -> np.ndarray:
        return pipe.predict_proba(part.X.select(feats).to_numpy())

    P_val, P_test = P_of(val), P_of(test)

    # ---- 3. Эксперт аномалий (US2: оба кандидата + аудит)
    a_feats = anomaly_features(cfg.anomaly.exclude_features)
    Xa_val = val.X.select(a_feats).to_numpy()
    Xa_test = test.X.select(a_feats).to_numpy()

    def audit_fn(expert, X, y):
        return audit_expert(
            expert.score_matrix,
            X,
            np.asarray(y) != M.BENIGN,
            a_feats,
            seed=cfg.seed,
            flag_at=cfg.audit.probe_flag,
            top=cfg.audit.top,
            max_rows=cfg.audit.permutation_rows,
            excluded=cfg.anomaly.exclude_features,
        )

    expert, anomaly_section = fit_anomaly_expert(
        cfg,
        data_dir=data_dir,
        X_val=Xa_val,
        y_val=y_val,
        X_test=Xa_test,
        y_test=y_test,
        data=data,
        audit_fn=audit_fn,
    )
    anomaly_section.pop("benign_uids", None)
    thr_c, thr_a = clf.threshold, expert.threshold
    ex_val = _Experts(
        P_val, expert.score_matrix(Xa_val), M.attack_score(P_val, classes) >= thr_c, None
    )
    ex_val.fired_a = ex_val.a >= thr_a
    ex_test = _Experts(
        P_test, expert.score_matrix(Xa_test), M.attack_score(P_test, classes) >= thr_c, None
    )
    ex_test.fired_a = ex_test.a >= thr_a
    del Xa_val, Xa_test

    # ---- 4. Варианты: одиночный классификатор и мета-кандидаты (OOF по блокам val)
    blocks = time_blocks(t_val, cfg.meta.folds, cfg.meta.gap_ms)
    s_val_c = M.attack_score(P_val, classes)
    s_test_c = M.attack_score(P_test, classes)
    variants: list[dict] = [
        {
            "name": "classifier",
            "kind": "single",
            "threshold": thr_c,
            "val": evaluate_variant(y_val, P_val, s_val_c, classes, thr_c),
            "test": evaluate_variant(y_test, P_test, s_test_c, classes, thr_c),
        }
    ]
    fitted_meta: dict[str, dict] = {}
    only_a_val = ~ex_val.fired_c & ex_val.fired_a
    only_a_test = ~ex_test.fired_c & ex_test.fired_a
    for v in cfg.meta.candidates:
        log.info("Мета-кандидат %s: out-of-fold по %d блокам val…", v, blocks.k)
        fm = _fit_meta(v, P_val, ex_val.a, y_val, classes, thr_c, thr_a, cfg.seed, blocks)
        proba_t, score_t = combine(v, P_test, classes, ex_test.a, thr_c, thr_a, fm["stack"])
        variants.append(
            {
                "name": v,
                "kind": "rule" if v in RULE_CANDIDATES else "trained",
                "threshold": fm["threshold"],
                "val": evaluate_variant(
                    y_val, fm["proba"], fm["score"], classes, fm["threshold"], only_a_val
                ),
                "test": evaluate_variant(
                    y_test, proba_t, score_t, classes, fm["threshold"], only_a_test
                ),
            }
        )
        fitted_meta[v] = fm

    # ---- 5. Скрытые классы (R5): классификатор без класса + мета-слой без класса
    log.info("Скрытые классы %s: загружаю train для классификаторов-копий…", cfg.hidden_classes)
    train = load_part(cfg.split, "train", data_dir=data_dir)
    X_train = train.X.select(clf.features).to_numpy()
    y_train = train.y
    del train
    gc.collect()
    hidden: list[dict] = []
    for h in cfg.hidden_classes:
        log.info("Скрытый класс %s: обучаю %s без его строк…", h, winner_name)
        keep_tr = y_train != h
        copy = build_candidate(winner_name, winner_params, cfg.seed)
        copy.fit(X_train[keep_tr], y_train[keep_tr])
        cls_h = [str(c) for c in copy.classes_]
        Ph_val = P_of(val, copy)
        Ph_test = P_of(test, copy)
        keep_val = y_val != h
        sh_val, sh_test = M.attack_score(Ph_val, cls_h), M.attack_score(Ph_test, cls_h)
        thr_h = M.choose_threshold(y_val[keep_val] != M.BENIGN, sh_val[keep_val])
        clf_val_alert, clf_test_alert = sh_val >= thr_h, sh_test >= thr_h
        row: dict[str, Any] = {
            "class": h,
            "n_val": int((y_val == h).sum()),
            "n_test": int((y_test == h).sum()),
            "classifier_threshold": thr_h,
            "catch": {
                "classifier_without_class": {
                    "val": M.catch_rate(y_val, clf_val_alert, h),
                    "test": M.catch_rate(y_test, clf_test_alert, h),
                },
                "anomaly": {
                    "val": M.catch_rate(y_val, ex_val.fired_a, h),
                    "test": M.catch_rate(y_test, ex_test.fired_a, h),
                },
            },
            "variants": {},
        }
        blocks_h = time_blocks(t_val[keep_val], cfg.meta.folds, cfg.meta.gap_ms)
        for v in cfg.meta.candidates:
            fm = _fit_meta(
                v,
                Ph_val[keep_val],
                ex_val.a[keep_val],
                y_val[keep_val],
                cls_h,
                thr_h,
                thr_a,
                cfg.seed,
                blocks_h,
            )
            # Потоки h мета-модель не видела — предсказываем их финальной моделью (а у правил
            # просто применяем правило); остальные строки val берём из OOF
            _, sv_all = combine(v, Ph_val, cls_h, ex_val.a, thr_h, thr_a, fm["stack"])
            sv_all[keep_val] = fm["score"]
            _, st_all = combine(v, Ph_test, cls_h, ex_test.a, thr_h, thr_a, fm["stack"])
            c_val = M.catch_rate(y_val, sv_all >= fm["threshold"], h)
            c_test = M.catch_rate(y_test, st_all >= fm["threshold"], h)
            base_val = row["catch"]["classifier_without_class"]["val"]
            row["variants"][v] = {
                "threshold": fm["threshold"],
                "val": c_val,
                "test": c_test,
                "gain_val": None if c_val is None or base_val is None else c_val - base_val,
            }
        hidden.append(row)
        del copy
        gc.collect()
    del X_train, y_train
    gc.collect()

    unknown_gain: dict[str, float | None] = {}
    for v in cfg.meta.candidates:
        gains = [r["variants"][v]["gain_val"] for r in hidden]
        gains = [g for g in gains if g is not None]
        unknown_gain[v] = float(np.mean(gains)) if gains else None

    # ---- 6. Выбор (только val) и итоговый вариант
    val_macro = {r["name"]: r["val"]["macro_pr_auc"] for r in variants}
    selection = select_variant(
        val_macro,
        unknown_gain,
        min_gain=cfg.selection.min_gain,
        min_unknown_gain=cfg.selection.min_unknown_gain,
        order=cfg.meta.candidates,
    )
    selection.update(
        {
            "min_gain": cfg.selection.min_gain,
            "min_unknown_gain": cfg.selection.min_unknown_gain,
            "unknown_gain": unknown_gain,
            "forced": False,
        }
    )
    if force_variant is not None:
        selection.update(
            {
                "selected": f"ensemble:{force_variant}",
                "condition": "forced",
                "forced": True,
                "text": f"выбор подменён тестом: ensemble:{force_variant} (не для выводов)",
            }
        )
    selected = selection["selected"]
    log.info("Выбор: %s — %s", selected, selection["text"])

    # ---- 7. Аудит мета-слоя (веса стекинга) и MLflow
    audit: dict[str, Any] = {"anomaly": expert.card.get("audit")}
    if "stack_logreg" in fitted_meta:
        names = [f"logp_{c}" for c in classes] + ["anomaly_pct"]
        expert_of = {n: ("anomaly" if n == "anomaly_pct" else "classifier") for n in names}
        audit["meta"] = meta_weights(fitted_meta["stack_logreg"]["stack"], names, expert_of)

    experts_versions = {"classifier": clf.version, "anomaly": expert.version}
    version = ensemble_version(cfg.raw, experts_versions, data)
    unreliable = {
        "val": M.unreliable_classes(y_val, classes, cfg.unreliable_below),
        "test": M.unreliable_classes(y_test, classes, cfg.unreliable_below),
    }
    run_ids: dict[str, str] = {}
    for vr in variants:
        with mlflow.start_run(run_name=vr["name"]) as run:
            mlflow.log_params({"variant": vr["name"], "seed": cfg.seed, "split": cfg.split})
            metrics = {"threshold": vr["threshold"]}
            for part in ("val", "test"):
                ev = vr[part]
                metrics[f"{part}_macro_pr_auc"] = ev["macro_pr_auc"]
                if ev["pr_auc_binary"] is not None:
                    metrics[f"{part}_pr_auc_binary"] = ev["pr_auc_binary"]
                metrics[f"{part}_f1"] = ev["binary"]["f1"]
            mlflow.log_metrics({k: v for k, v in metrics.items() if v == v})
            mlflow.set_tags(
                {
                    "split_hash": data["split_hash"],
                    "schema_version": SCHEMA.version,
                    "ensemble_version": version,
                    "git_commit": commit or "",
                }
            )
        run_ids[vr["name"]] = run.info.run_id

    # ---- 8. Артефакты
    out_ens = Path(cfg.output_ensemble)
    save_anomaly_expert(expert, cfg.output_anomaly)
    chosen = selected.partition(":")[2] if selected != SINGLE else None
    chosen_row = next(r for r in variants if r["name"] == (chosen or "classifier"))
    meta_card = None
    if chosen:
        meta_card = {
            "candidate": chosen,
            "inputs": (
                [f"logp_{c}" for c in classes] + ["anomaly_pct"]
                if chosen == "stack_logreg"
                else ["classifier_score", "anomaly_pct"]
            ),
            "weights": audit.get("meta") if chosen == "stack_logreg" else None,
        }
    data_scheme = {
        "experts": f"обучены на train {cfg.split} (эксперт аномалий — только норма train)",
        "classifier": f"классификатор 002 {clf.version} — без переобучения (FR-002)",
        "anomaly_calibration": (
            f"перцентиль — по отложенной норме train ({cfg.anomaly.calibration_share:.0%}), "
            f"порог — по норме val (≤ {cfg.anomaly.anomaly_fpr:.1%} ложных срабатываний)"
        ),
        "meta": (
            f"мета-слой — на val, out-of-fold по {cfg.meta.folds} последовательным блокам "
            f"времени с зазором {cfg.meta.gap_ms} мс; итоговая мета-модель — на всей val"
        ),
        "threshold": "порог итогового вердикта — максимум F1 на OOF val",
        "selection": "выбор варианта — только по val (FR-010)",
        "test": "test — только отчёт, ни в каком выборе не участвует",
    }
    card = {
        "ensemble_version": version,
        "selected": selected,
        "selection": {
            k: selection[k] for k in ("condition", "text", "min_gain", "min_unknown_gain", "forced")
        }
        | {"best_single": "classifier", "unknown_gain": unknown_gain},
        "experts": [
            {
                "name": "classifier",
                "kind": "classifier",
                "path": Path(cfg.classifier).as_posix(),
                "version": clf.version,
            },
            {
                "name": "anomaly",
                "kind": "anomaly",
                "path": Path(cfg.output_anomaly).as_posix(),
                "version": expert.version,
            },
        ],
        "meta": meta_card,
        "classes": classes,
        "threshold": chosen_row["threshold"],
        "class_rule": {
            "anomaly": (
                "класс anomaly — если алерт поднят, классификатор на своём пороге не "
                "сработал, а детектор аномалий сработал; иначе самый вероятный класс атаки"
            ),
            "classifier_threshold": thr_c,
            "anomaly_threshold": thr_a,
        },
        "schema_version": SCHEMA.version,
        "data_scheme": data_scheme,
        "data": {"split": cfg.split, **data},
        "metrics": {"val": chosen_row["val"], "test": chosen_row["test"]},
        "seed": cfg.seed,
        "libraries": library_versions(),
        "git_commit": commit,
    }
    experiment = {
        "ensemble_version": version,
        "split": cfg.split,
        "seed": cfg.seed,
        "config": cfg.raw,
        "data": card["data"],
        "schema_version": SCHEMA.version,
        "experts": {
            "classifier": {
                "version": clf.version,
                "candidate": clf.card.get("candidate"),
                "threshold": thr_c,
                "val": variants[0]["val"],
                "test": variants[0]["test"],
            },
            "anomaly": anomaly_section,
        },
        "variants": variants,
        "hidden_class": hidden,
        "selection": {**selection, "selected": selected},
        "audit": audit,
        "unreliable_classes": unreliable,
        "data_scheme": data_scheme,
        "oof": {
            "folds": blocks.k,
            "gap_ms": cfg.meta.gap_ms,
            "block_sizes": np.bincount(blocks.block, minlength=blocks.k).tolist(),
        },
        "mlflow_run_ids": run_ids,
        "seconds": round(time.perf_counter() - started_all, 1),
    }
    out_ens.mkdir(parents=True, exist_ok=True)
    meta_path = out_ens / META_FILE
    if chosen == "stack_logreg":
        import joblib

        with atomic_path(meta_path) as tmp:
            joblib.dump(fitted_meta["stack_logreg"]["stack"], tmp)
    elif meta_path.exists():
        # Старый meta.joblib от прошлого выбора не должен лежать рядом с новой карточкой
        meta_path.unlink()
    with atomic_path(out_ens / EXPERIMENT_FILE) as tmp:
        tmp.write_text(
            json.dumps(_jsonable(experiment), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    with atomic_path(out_ens / ENSEMBLE_CARD) as tmp:
        tmp.write_text(
            json.dumps(_jsonable(card), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    with atomic_path(Path(reports_dir) / REPORT_NAME) as tmp:
        tmp.write_text(render_ensemble_report(_jsonable(experiment)), encoding="utf-8")
    log.info("Ансамбль %s сохранён в %s (%s)", version, out_ens, selected)
    return _jsonable(experiment)


# ================================================================ отчёт


def _f(v: float | None) -> str:
    return "—" if v is None else f"{v:.4f}"


def _p(v: float | None) -> str:
    return "—" if v is None else f"{v:.1%}"


VARIANT_TITLES = {
    "classifier": "классификатор 002 (одиночный)",
    "any_fired": "any_fired (правило: сработал любой)",
    "mean_score": "mean_score (правило: среднее скоров)",
    "stack_logreg": "stack_logreg (стекинг, логрег)",
}


def render_ensemble_report(exp: dict) -> str:
    """Markdown-отчёт эксперимента 004 — читается в репозитории без MLflow."""
    classes = exp["variants"][0]["val"]["per_class"].keys()
    unreliable = set(exp["unreliable_classes"]["val"]) | set(exp["unreliable_classes"]["test"])
    below = exp["config"].get("unreliable_below", 50)
    sel = exp["selection"]
    lines = [
        "# Эксперимент «эксперты + мета-слой» (фича 004)",
        "",
        f"- Версия ансамбля: `{exp['ensemble_version']}`",
        f"- Разбиение: `{exp['split']}` (hash `{exp['data']['split_hash'][:12]}…`), "
        f"сид {exp['seed']}",
        "- Выбор — только по val; test — только отчёт",
        f"- Время эксперимента: {exp['seconds']} с",
        "",
        "## Варианты",
        "",
        "| Вариант | macro PR-AUC val | macro PR-AUC test | PR-AUC «атака/не атака» val "
        "| … test | порог | F1 val | F1 test | норма test «только из-за аномалий» |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for v in exp["variants"]:
        lines.append(
            f"| {VARIANT_TITLES.get(v['name'], v['name'])} | {_f(v['val']['macro_pr_auc'])} | "
            f"{_f(v['test']['macro_pr_auc'])} | {_f(v['val']['pr_auc_binary'])} | "
            f"{_f(v['test']['pr_auc_binary'])} | {v['threshold']:.4f} | "
            f"{_f(v['val']['binary']['f1'])} | {_f(v['test']['binary']['f1'])} | "
            f"{_p(v['test'].get('benign_alert_only_anomaly'))} |"
        )
    lines += [
        "",
        "Val у мета-кандидатов — out-of-fold (каждый блок времени предсказан моделью, не "
        "видевшей его). У any_fired порог фиксирован: 0.5 на общей шкале, где порог каждого "
        "эксперта — ровно 0.5.",
        "",
        "## PR-AUC по классам",
        "",
        "| Класс | "
        + " | ".join(f"{v['name']} val | {v['name']} test" for v in exp["variants"])
        + " |",
        "|---|" + "---|" * (2 * len(exp["variants"])),
    ]
    for cls in classes:
        cells = []
        for v in exp["variants"]:
            cells += [_f(v["val"]["per_class"].get(cls)), _f(v["test"]["per_class"].get(cls))]
        mark = f" (ненадёжен: < {below} примеров)" if cls in unreliable else ""
        lines.append(f"| {cls}{mark} | " + " | ".join(cells) + " |")

    an = exp["experts"]["anomaly"]
    lines += [
        "",
        "## Детектор аномалий: кандидаты",
        "",
        "Учится только на нормальных потоках train "
        f"(обучение {an['train']['n_train']}, калибровка {an['train']['n_calibration']} из "
        f"{an['train']['n_benign_total']}); порог — по норме val.",
        "",
        "| Кандидат | PR-AUC «атака/не атака» val | … test | порог (перцентиль) "
        "| норма val выше порога | норма test выше порога | атак test выше порога | обучение, с |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for c in an["candidates"]:
        lines.append(
            f"| {c['name']} | {_f(c['val']['pr_auc_binary'])} | {_f(c['test']['pr_auc_binary'])} | "
            f"{c['threshold']:.4f} | {_p(c['val']['benign_above_threshold'])} | "
            f"{_p(c['test']['benign_above_threshold'])} | "
            f"{_p(c['test']['attacks_above_threshold'])} | {c['train_seconds']} |"
        )
    lines += ["", f"**Выбран `{an['winner']}`** — {an['selection_text']}.", ""]

    lines += [
        "## Скрытый класс (неизвестная атака)",
        "",
        "Классификатор-копия и мета-слой учатся без строк класса; детектор аномалий общий (он "
        "атак не видел вовсе). «Поимка» — доля потоков класса, ставших алертами.",
        "",
        "| Класс | потоков val / test | классификатор без класса val / test | детектор аномалий "
        "val / test | "
        + " | ".join(f"{v} val / test" for v in exp["config"]["meta"]["candidates"])
        + " |",
        "|---|---|---|---|" + "---|" * len(exp["config"]["meta"]["candidates"]),
    ]
    for h in exp["hidden_class"]:
        c = h["catch"]
        cells = [
            f"{_p(h['variants'][v]['val'])} / {_p(h['variants'][v]['test'])}"
            for v in exp["config"]["meta"]["candidates"]
        ]
        lines.append(
            f"| {h['class']} | {h['n_val']} / {h['n_test']} | "
            f"{_p(c['classifier_without_class']['val'])} / "
            f"{_p(c['classifier_without_class']['test'])} | "
            f"{_p(c['anomaly']['val'])} / {_p(c['anomaly']['test'])} | " + " | ".join(cells) + " |"
        )
    ug = sel.get("unknown_gain") or {}
    lines += [
        "",
        "Средний прирост поимки на val над классификатором без класса: "
        + ", ".join(f"{v} {'—' if g is None else f'{g:+.3f}'}" for v, g in ug.items()),
        "",
        "## Выбор",
        "",
        f"Правило (FR-010): ансамбль принимается, если на val лучше классификатора на "
        f"{sel['min_gain']} macro PR-AUC, или ловит скрытые классы на {sel['min_unknown_gain']} "
        f"лучше при падении macro не больше {sel['min_gain']}.",
        "",
        f"**Выбрано: `{sel['selected']}`**, условие `{sel['condition']}` — {sel['text']}.",
        "",
    ]
    if sel["condition"] == "none":
        lines += [
            "**Отрицательный результат.** Ни одно сочетание экспертов не оправдало себя на val по "
            "правилу FR-010. Это тоже вывод: в цепочке остаётся классификатор 002, а "
            "карточка ансамбля честно это фиксирует.",
            "",
        ]
    lines += ["## Аудит артефактов", ""]
    aud = exp["audit"].get("anomaly") or {}
    if aud:
        lines.append(aud.get("text", ""))
        lines.append("")
        if aud.get("probe_top"):
            lines += ["| Признак (в одиночку) | PR-AUC val | знак | помечен |", "|---|---|---|---|"]
            for r in aud["probe_top"]:
                lines.append(
                    f"| {r['feature']} | {r['pr_auc']:.4f} | {r['sign']} | "
                    f"{'да' if r['flagged'] else 'нет'} |"
                )
            lines.append("")
        perm = aud.get("permutation") or {}
        if perm.get("top"):
            lines += [
                f"Перестановочная важность скора эксперта (PR-AUC «атака/не атака» "
                f"{_f(perm.get('base_pr_auc'))} на {perm.get('n_rows')} потоках val):",
                "",
                "| Признак | падение PR-AUC |",
                "|---|---|",
            ]
            lines += [f"| {r['feature']} | {r['drop']:.4f} |" for r in perm["top"]]
            lines.append("")
    meta_aud = exp["audit"].get("meta")
    if meta_aud:
        shares = ", ".join(f"{k} {v:.0%}" for k, v in meta_aud["by_expert"].items())
        lines += [f"Вклад экспертов в стекинг (доля суммы |весов|): {shares}.", ""]
    lines += ["## Схема данных", ""]
    lines += [f"- {v}" for v in exp["data_scheme"].values()]
    lines += ["", "## Ненадёжные классы", ""]
    for part, cls in exp["unreliable_classes"].items():
        lines.append(
            f"- {part}: {', '.join(cls)} — меньше {below} примеров, PR-AUC шумный"
            if cls
            else f"- {part}: нет"
        )
    return "\n".join(lines) + "\n"
