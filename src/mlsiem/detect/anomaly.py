"""Эксперт аномалий: «насколько поток не похож на норму» (фича 004, research R1, R2, R6).

Идея: классификатор 002 знает только те атаки, что видел в train. Детектор аномалий учится
ТОЛЬКО на нормальных потоках train и ничего не знает об атаках вовсе — поэтому может поднять
тревогу и на атаке нового вида (FR-003). Это же и главное правило честности: в обучении и
калибровке нет ни одного потока атаки; код проверяет это явно, а тест — по `flow_uid`.

Кандидаты (R1), оба — «предобработка + модель» внутри одного объекта, чтобы при инференсе
нельзя было забыть log1p или взять другое масштабирование (train = serve, принцип II):
- `iforest` — Isolation Forest на log1p-признаках, бейзлайн. Сырой скор = −score_samples
  (больше — аномальнее);
- `autoencoder` — неглубокий автокодировщик на MLPRegressor (log1p → стандартизация → сеть
  учится восстанавливать свой же вход). Сырой скор — средняя квадратичная ошибка
  восстановления: норму сеть восстанавливает хорошо, «непохожее» — плохо.

Шкала (R2). Сырые скоры у кандидатов в разных единицах, и аналитику «0.43» ничего не говорит.
Поэтому скор переводится в перцентиль нормы: доля нормальных потоков КАЛИБРОВОЧНОЙ выборки
со скором ниже. Калибровочная выборка — 10% нормы train, отложенная ДО обучения (эксперт её
не видел, иначе перцентиль был бы оптимистичным). «0.998» читается как «аномальнее, чем 99.8%
нормы» — у обоих кандидатов одинаково.

Порог — по бюджету ложных срабатываний на норме val: наименьший перцентиль, выше которого
оказывается не больше `anomaly_fpr` (0.5%) нормальных потоков val. Метки атак в выборе порога
не участвуют вообще — порог не подгоняется под известные атаки (clarify Q4).

Артефакт — каталог `models/experts/anomaly/`: `model.joblib`, `calibration.npy`,
`expert_card.json` (data-model «Эксперт аномалий»).
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
from mlsiem.detect.artifact import (
    DetectorInputError,
    DetectorLoadError,
    check_schema_and_features,
    detector_version,
)
from mlsiem.detect.candidates import _log1p_nonneg
from mlsiem.detect.dataset import FEATURES_DTYPE, feature_columns, scan_part
from mlsiem.detect.metrics import BENIGN

log = logging.getLogger("mlsiem")

EXPERT_NAME = "anomaly"
MODEL_FILE = "model.joblib"
CALIBRATION_FILE = "calibration.npy"
CARD_FILE = "expert_card.json"
REQUIRED_CARD_FIELDS = (
    "expert_version",
    "name",
    "kind",
    "candidate",
    "features",
    "schema_version",
    "threshold",
    "anomaly_fpr",
    "train",
)


def anomaly_features(exclude: tuple[str, ...] | list[str] = ()) -> list[str]:
    """Вход эксперта: группа `feature` схемы в её порядке минус исключённые аудитом (FR-005).

    Список не пишется руками — адреса, порты, время и DPI сюда не попадут никогда.
    """
    excluded = set(exclude)
    return [f for f in feature_columns() if f not in excluded]


# ---------------------------------------------------------------- модели-кандидаты


class AnomalyModel:
    """Общий вид кандидата: `fit(X)` на норме и `raw_score(X)` — больше значит аномальнее."""

    name = "base"

    def fit(self, X: np.ndarray) -> AnomalyModel:  # pragma: no cover — интерфейс
        raise NotImplementedError

    def raw_score(self, X: np.ndarray) -> np.ndarray:  # pragma: no cover — интерфейс
        raise NotImplementedError


class IForestModel(AnomalyModel):
    """Isolation Forest на log1p-признаках — простой и быстрый бейзлайн аномалий.

    Лес случайно «режет» пространство признаков; редкий, непохожий на остальных поток
    отрезается за меньшее число разрезов. `score_samples` у sklearn тем больше, чем
    НОРМАЛЬНЕЕ поток, поэтому берём его с минусом.
    """

    name = "iforest"

    def __init__(self, params: dict[str, Any], seed: int) -> None:
        self.params = dict(params)
        self.seed = seed
        self.model = None

    def fit(self, X: np.ndarray) -> IForestModel:
        from sklearn.ensemble import IsolationForest

        params = dict(self.params)
        # На маленькой выборке (тесты) max_samples больше числа строк — sklearn бы ругался
        if isinstance(params.get("max_samples"), int):
            params["max_samples"] = min(params["max_samples"], len(X))
        self.model = IsolationForest(random_state=self.seed, n_jobs=1, **params)
        self.model.fit(_log1p_nonneg(X))
        return self

    def raw_score(self, X: np.ndarray) -> np.ndarray:
        return -self.model.score_samples(_log1p_nonneg(X))


class AutoencoderModel(AnomalyModel):
    """Автокодировщик на MLPRegressor: сеть «58 → 32 → 12 → 32 → 58» учится выдавать свой вход.

    Узкое горлышко (12 нейронов) не даёт сети просто скопировать вход — она вынуждена
    выучить, как устроена норма. Поток, непохожий на норму, восстанавливается с большой
    ошибкой — она и есть сырой скор. MLPRegressor на CPU детерминирован с random_state,
    в отличие от нейросетей на GPU (research R1).
    """

    name = "autoencoder"

    def __init__(self, params: dict[str, Any], seed: int) -> None:
        self.params = dict(params)
        self.seed = seed
        self.scaler = None
        self.model = None

    def _prep(self, X: np.ndarray) -> np.ndarray:
        return self.scaler.transform(_log1p_nonneg(X))

    def fit(self, X: np.ndarray) -> AutoencoderModel:
        from sklearn.neural_network import MLPRegressor
        from sklearn.preprocessing import StandardScaler

        params = dict(self.params)
        hidden = tuple(params.pop("hidden", (32, 12, 32)))
        self.scaler = StandardScaler().fit(_log1p_nonneg(X))
        Z = self._prep(X)
        self.model = MLPRegressor(
            hidden_layer_sizes=hidden,
            random_state=self.seed,
            early_stopping=True,
            **params,
        )
        # Цель = вход: учимся восстанавливать норму
        self.model.fit(Z, Z)
        return self

    def raw_score(self, X: np.ndarray) -> np.ndarray:
        Z = self._prep(X)
        return np.mean((self.model.predict(Z) - Z) ** 2, axis=1)


def build_anomaly_candidate(name: str, params: dict[str, Any], seed: int) -> AnomalyModel:
    if name == "iforest":
        return IForestModel(params, seed)
    if name == "autoencoder":
        return AutoencoderModel(params, seed)
    raise ValueError(
        f"неизвестный кандидат детектора аномалий {name!r}: поддерживаются iforest и autoencoder"
    )


# ---------------------------------------------------------------- шкала и порог


def percentile(raw: np.ndarray, calibration_sorted: np.ndarray) -> np.ndarray:
    """Сырой скор → доля калибровочной нормы со скором СТРОГО ниже, число в [0, 1].

    Монотонна по сырому скору: чем аномальнее поток, тем выше перцентиль. Поток аномальнее
    всей калибровки получает ровно 1.0.
    """
    cal = np.asarray(calibration_sorted, dtype=np.float64)
    if cal.size == 0:
        raise ValueError("калибровочная выборка пуста — перцентиль не определён")
    idx = np.searchsorted(cal, np.asarray(raw, dtype=np.float64), side="left")
    return idx / cal.size


def choose_anomaly_threshold(benign_val_pct: np.ndarray, fpr: float) -> float:
    """Наименьший порог, при котором доля нормы val с перцентилем ≥ порога не больше `fpr`.

    Правило срабатывания — «перцентиль ≥ порога». Кандидаты — сами значения перцентиля:
    между соседними значениями доля не меняется, а наименьший порог из равных по доле —
    ровно значение. Если даже самый высокий перцентиль встречается у слишком многих
    нормальных потоков, порог ставится чуть выше максимума: эксперт молчит, но честно.
    Сюда передаются ТОЛЬКО скоры нормы — меток атак функция не видит в принципе.
    """
    p = np.sort(np.asarray(benign_val_pct, dtype=np.float64))
    n = p.size
    if n == 0:
        raise ValueError(
            "в val нет нормальных потоков — порог по доле ложных срабатываний не выбрать"
        )
    allowed = int(np.floor(fpr * n + 1e-9))
    uniq = np.unique(p)
    # Сколько потоков с перцентилем ≥ u: n − (индекс первого ≥ u)
    at_or_above = n - np.searchsorted(p, uniq, side="left")
    ok = np.flatnonzero(at_or_above <= allowed)
    if ok.size == 0:
        return float(np.nextafter(p[-1], np.inf))
    return float(uniq[ok[0]])


# ---------------------------------------------------------------- данные нормы


@dataclass
class BenignSample:
    """Норма train для эксперта: обучающая подвыборка и отложенная калибровочная."""

    X_train: np.ndarray
    X_cal: np.ndarray
    uid_train: np.ndarray
    uid_cal: np.ndarray
    n_benign_total: int


def load_benign_sample(
    split: str,
    features: list[str],
    *,
    data_dir: Path,
    train_sample: int,
    calibration_share: float,
    seed: int,
) -> BenignSample:
    """Нормальные потоки train → обучающая подвыборка и калибровочная норма (R1, R2).

    Подвыборка стратифицирована по захватам: каждому потоку — случайное число от сида, и
    внутри своего захвата поток попадает в калибровку, если его ранг в первой доле
    `calibration_share`, а в обучение — если в следующей доле, нужной до `train_sample`.
    Так пропорции захватов сохраняются, выборки не пересекаются, а результат зависит только
    от сида и данных (вход отсортирован по flow_uid).
    """
    df = (
        scan_part(split, "train", data_dir=data_dir, columns=[*features, "capture_id", "label"])
        .filter(pl.col("label") == BENIGN)
        .collect()
    )
    if df.height == 0:
        raise ValueError(
            f"в train разбиения {split} нет нормальных потоков — учить эксперта не на чем"
        )
    rng = np.random.default_rng(seed)
    df = df.with_columns(pl.Series("_u", rng.random(df.height)))
    df = df.with_columns(
        pl.col("_u").rank("ordinal").over("capture_id").alias("_rank"),
        pl.len().over("capture_id").alias("_n"),
    )
    # Сколько потоков каждого захвата уходит на калибровку (хотя бы один)
    df = df.with_columns(
        (pl.col("_n") * calibration_share).round().cast(pl.Int64).clip(lower_bound=1).alias("_ncal")
    )
    # Остаток после калибровки по всем захватам — от него считается доля на обучение
    per_cap = df.group_by("capture_id").agg(pl.col("_n").first(), pl.col("_ncal").first())
    rest_total = int((per_cap["_n"] - per_cap["_ncal"]).sum())
    ratio = min(1.0, train_sample / rest_total) if rest_total else 0.0
    df = df.with_columns(
        (pl.col("_rank") <= pl.col("_ncal")).alias("_is_cal"),
        (
            (pl.col("_rank") > pl.col("_ncal"))
            & (
                pl.col("_rank") - pl.col("_ncal")
                <= ((pl.col("_n") - pl.col("_ncal")) * ratio).round()
            )
        ).alias("_is_train"),
    )
    cal = df.filter(pl.col("_is_cal"))
    train = df.filter(pl.col("_is_train"))
    # Самопроверка правила честности: ни одного потока атаки, выборки не пересекаются
    for part in (cal, train):
        if (part["label"] != BENIGN).any():  # pragma: no cover — фильтр выше это исключает
            raise AssertionError("в выборку эксперта аномалий попал поток атаки")
    if train.height == 0 or cal.height == 0:
        raise ValueError(
            f"нормальных потоков train слишком мало ({df.height}) для обучения и калибровки"
        )

    def X(part: pl.DataFrame) -> np.ndarray:
        return part.select(pl.col(features).cast(FEATURES_DTYPE).fill_null(0)).to_numpy()

    return BenignSample(
        X_train=X(train),
        X_cal=X(cal),
        uid_train=train["flow_uid"].to_numpy(),
        uid_cal=cal["flow_uid"].to_numpy(),
        n_benign_total=df.height,
    )


# ---------------------------------------------------------------- эксперт


@dataclass
class AnomalyExpert:
    """Загруженный (или только что обученный) эксперт аномалий."""

    model: AnomalyModel
    calibration: np.ndarray  # отсортированные сырые скоры калибровочной нормы
    card: dict

    @property
    def version(self) -> str:
        return self.card["expert_version"]

    @property
    def features(self) -> list[str]:
        return list(self.card["features"])

    @property
    def threshold(self) -> float:
        return float(self.card["threshold"])

    @property
    def schema_version(self) -> str:
        return self.card["schema_version"]

    def score_matrix(self, X: np.ndarray) -> np.ndarray:
        return percentile(self.model.raw_score(X), self.calibration)

    def score(self, df: pl.DataFrame) -> np.ndarray:
        """Перцентиль нормы для каждого потока. Берутся ТОЛЬКО `features` из карточки."""
        if df.height == 0:
            return np.zeros(0)
        X = df.select(pl.col(self.features).cast(FEATURES_DTYPE).fill_null(0)).to_numpy()
        return self.score_matrix(X)

    def check_input(self, schema_version: str | None, columns: list[str]) -> None:
        check_schema_and_features(
            self.schema_version, self.features, schema_version, columns, "эксперт аномалий"
        )


def expert_version(config_raw: dict, hashes: dict) -> str:
    """`YYYYMMDD-<хеш8>` от настроек эксперта и хешей данных — как версия детектора 002.

    В хеш идут только ключи, влияющие на эксперта (разбиение, сид, раздел anomaly): смена,
    скажем, мета-кандидатов не должна «менять» уже обученного эксперта.
    """
    relevant = {k: config_raw.get(k) for k in ("split", "seed", "anomaly")}
    return detector_version(relevant, hashes)


def save_anomaly_expert(expert: AnomalyExpert, out_dir: Path) -> None:
    """Атомарно пишет три файла эксперта."""
    import joblib

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with atomic_path(out_dir / MODEL_FILE) as tmp:
        joblib.dump(expert.model, tmp)
    with atomic_path(out_dir / CALIBRATION_FILE) as tmp, open(tmp, "wb") as fh:
        np.save(fh, np.asarray(expert.calibration, dtype=np.float64))
    with atomic_path(out_dir / CARD_FILE) as tmp:
        tmp.write_text(
            json.dumps(expert.card, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )


def load_anomaly_expert(path: Path = Path("models/experts/anomaly")) -> AnomalyExpert:
    """Загружает эксперта; нет файла или он битый — `DetectorLoadError` с понятным текстом."""
    import joblib

    path = Path(path)
    files = (path / MODEL_FILE, path / CALIBRATION_FILE, path / CARD_FILE)
    missing = [f.name for f in files if not f.exists()]
    if missing:
        raise DetectorLoadError(
            f"эксперт аномалий: в {path} нет файлов {missing} (ожидались {MODEL_FILE}, "
            f"{CALIBRATION_FILE}, {CARD_FILE}) — обучите его: `uv run mlsiem detect ensemble`"
        )
    card_file = path / CARD_FILE
    try:
        card = json.loads(card_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DetectorLoadError(f"эксперт аномалий: {card_file} повреждён: {exc}") from exc
    if not isinstance(card, dict):
        raise DetectorLoadError(f"эксперт аномалий: {card_file} повреждён: ожидался JSON-объект")
    lacking = [f for f in REQUIRED_CARD_FIELDS if f not in card]
    if lacking:
        raise DetectorLoadError(f"эксперт аномалий: {card_file} повреждён: нет полей {lacking}")
    try:
        model = joblib.load(path / MODEL_FILE)
        calibration = np.load(path / CALIBRATION_FILE, allow_pickle=False)
    except Exception as exc:  # joblib/numpy бросают что угодно на битом файле
        raise DetectorLoadError(
            f"эксперт аномалий: файлы в {path} не загружаются (повреждены?): {exc}"
        ) from exc
    if not isinstance(model, AnomalyModel):
        raise DetectorLoadError(
            f"эксперт аномалий: {path / MODEL_FILE} — внутри не модель аномалий"
        )
    if calibration.ndim != 1 or calibration.size == 0:
        raise DetectorLoadError(f"эксперт аномалий: {path / CALIBRATION_FILE} пуст или не вектор")
    return AnomalyExpert(model=model, calibration=calibration, card=card)


# ---------------------------------------------------------------- обучение и выбор кандидата


def select_anomaly_candidate(
    val_pr_auc: dict[str, float | None], *, baseline: str = "iforest", min_gain: float
) -> tuple[str, str]:
    """Победитель по PR-AUC «атака/не атака» на val (FR-006, research R1).

    Правило то же, что у детектора 002: сложный кандидат выигрывает, только если лучше
    бейзлайна хотя бы на `min_gain`; при равном качестве простое лучше (принцип IV).
    Сюда передаются ТОЛЬКО метрики val — выбор по test был бы подгонкой под test.
    Если на val атак нет (метрика `None`), сравнивать нечем — остаётся бейзлайн.
    """
    if baseline not in val_pr_auc:
        raise ValueError(f"нет результатов бейзлайна детектора аномалий {baseline!r}")
    base = val_pr_auc[baseline]
    if base is None:
        return baseline, "на val нет атак или нормы — сравнивать нечем, оставлен бейзлайн"
    scored = {n: v for n, v in val_pr_auc.items() if v is not None}
    best = max(scored, key=lambda n: (scored[n], n == baseline))
    if best == baseline:
        return baseline, (
            f"бейзлайн {baseline} лучший на val (PR-AUC «атака/не атака» {base:.4f}) — выбран он"
        )
    gain = scored[best] - base
    if gain >= min_gain:
        return best, (
            f"{best} лучше бейзлайна {baseline} на val на {gain:.4f} PR-AUC «атака/не атака» "
            f"({scored[best]:.4f} против {base:.4f}) ≥ {min_gain} — выбран {best}"
        )
    return baseline, (
        f"{best} лучше бейзлайна {baseline} на val всего на {gain:.4f} (< {min_gain}) — "
        f"при равном качестве выбран более простой {baseline}"
    )


def _eval_part(y: np.ndarray, pct: np.ndarray, threshold: float) -> dict:
    """Метрики эксперта на части: PR-AUC «атака/не атака», доля нормы и атак выше порога."""
    from mlsiem.detect.metrics import binary_pr_auc, fpr_on_benign

    y = np.asarray(y)
    fired = pct >= threshold
    attack = y != BENIGN
    return {
        "pr_auc_binary": binary_pr_auc(attack, pct),
        "benign_above_threshold": fpr_on_benign(y, fired),
        "attacks_above_threshold": float(fired[attack].mean()) if attack.any() else None,
        "n_flows": int(len(y)),
    }


def fit_anomaly_expert(
    cfg,
    *,
    data_dir: Path,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    data: dict,
    audit_fn=None,
) -> tuple[AnomalyExpert, dict]:
    """Обучает кандидатов на норме train, калибрует, выбирает порог и победителя (R1, R2).

    `X_val`/`X_test` — матрицы ровно по `anomaly_features(cfg.anomaly.exclude_features)`.
    Метки val используются в двух местах, и оба честные: порог — только по НОРМЕ val (метки
    атак не нужны), выбор кандидата — по PR-AUC на val. Test — только отчёт.
    `audit_fn(expert, X_val, y_val) -> dict` — аудит артефактов (US2), если передан.
    Возвращает (эксперт-победитель, раздел эксперимента с метриками всех кандидатов).
    """
    import time

    from mlsiem.data.schema import SCHEMA
    from mlsiem.detect.artifact import library_versions
    from mlsiem.detect.config import ANOMALY_BASELINE

    a = cfg.anomaly
    features = anomaly_features(a.exclude_features)
    log.info("Эксперт аномалий: загружаю норму train (подвыборка %d)…", a.train_sample)
    benign = load_benign_sample(
        cfg.split,
        features,
        data_dir=data_dir,
        train_sample=a.train_sample,
        calibration_share=a.calibration_share,
        seed=cfg.seed,
    )
    log.info(
        "Норма train: всего %d, обучение %d, калибровка %d",
        benign.n_benign_total,
        len(benign.uid_train),
        len(benign.uid_cal),
    )
    y_val, y_test = np.asarray(y_val), np.asarray(y_test)
    benign_val = y_val == BENIGN

    results: list[dict] = []
    fitted: dict[str, tuple[AnomalyModel, np.ndarray, float]] = {}
    for name, params in a.candidates.items():
        started = time.perf_counter()
        model = build_anomaly_candidate(name, params, cfg.seed).fit(benign.X_train)
        seconds = time.perf_counter() - started
        cal = np.sort(model.raw_score(benign.X_cal))
        pct_val = percentile(model.raw_score(X_val), cal)
        pct_test = percentile(model.raw_score(X_test), cal)
        threshold = choose_anomaly_threshold(pct_val[benign_val], a.anomaly_fpr)
        ev_val, ev_test = (
            _eval_part(y_val, pct_val, threshold),
            _eval_part(y_test, pct_test, threshold),
        )
        log.info(
            "Кандидат %s: %.0f с, PR-AUC «атака/не атака» val %s / test %s, порог %.4f",
            name,
            seconds,
            _fmt(ev_val["pr_auc_binary"]),
            _fmt(ev_test["pr_auc_binary"]),
            threshold,
        )
        results.append(
            {
                "name": name,
                "params": params,
                "threshold": threshold,
                "train_seconds": round(seconds, 1),
                "val": ev_val,
                "test": ev_test,
            }
        )
        fitted[name] = (model, cal, threshold)

    winner, text = select_anomaly_candidate(
        {r["name"]: r["val"]["pr_auc_binary"] for r in results},
        baseline=ANOMALY_BASELINE,
        min_gain=cfg.selection.min_gain,
    )
    model, cal, threshold = fitted[winner]
    win = next(r for r in results if r["name"] == winner)
    card = {
        "expert_version": expert_version(cfg.raw, data),
        "name": EXPERT_NAME,
        "kind": "anomaly",
        "candidate": winner,
        "features": features,
        "schema_version": SCHEMA.version,
        "threshold": threshold,
        "anomaly_fpr": a.anomaly_fpr,
        "train": {
            "split": cfg.split,
            "n_benign_total": benign.n_benign_total,
            "n_train": int(len(benign.uid_train)),
            "n_calibration": int(len(benign.uid_cal)),
            "sampled_by": "capture_id",
            "seed": cfg.seed,
            "benign_only": True,
        },
        "metrics": {"val": win["val"], "test": win["test"]},
        "selection": {
            "baseline": ANOMALY_BASELINE,
            "min_gain": cfg.selection.min_gain,
            "text": text,
        },
        "data": data,
        "libraries": library_versions(),
    }
    expert = AnomalyExpert(model=model, calibration=cal, card=card)
    if audit_fn is not None:
        card["audit"] = audit_fn(expert, X_val, y_val)
    section = {
        "candidates": results,
        "winner": winner,
        "selection_text": text,
        "expert_version": card["expert_version"],
        "train": card["train"],
        "benign_uids": {"train": benign.uid_train, "calibration": benign.uid_cal},
    }
    return expert, section


def _fmt(v: float | None) -> str:
    return "—" if v is None else f"{v:.4f}"


__all__ = [
    "AnomalyExpert",
    "AnomalyModel",
    "BenignSample",
    "DetectorInputError",
    "DetectorLoadError",
    "EXPERT_NAME",
    "anomaly_features",
    "build_anomaly_candidate",
    "choose_anomaly_threshold",
    "expert_version",
    "load_anomaly_expert",
    "load_benign_sample",
    "percentile",
    "save_anomaly_expert",
]
