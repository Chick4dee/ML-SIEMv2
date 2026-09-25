# Data Model: эксперты-детекторы и мета-слой (фича 004)

Сущности спеки ([spec.md](spec.md), Key Entities) в виде файлов, полей и правил. Решения —
в [research.md](research.md) (R1–R15). Всё, что не упомянуто, — как в 002/003.

## Артефакты моделей (каталог `models/`, версионируются DVC)

### Эксперт-классификатор — `models/detector/` (без изменений, FR-002)

Формат 002: `model.joblib`, `model_card.json` (`detector_version`, `candidate`, `classes`,
`threshold`, `features`, `schema_version`, метрики). В ансамбле его имя — `classifier`.

### Эксперт аномалий — `models/experts/anomaly/`

| Файл | Содержимое |
|---|---|
| `model.joblib` | конвейер sklearn «log1p → (стандартизация) → IsolationForest / MLPRegressor» |
| `calibration.npy` | отсортированные сырые скоры калибровочной нормы (10% `benign` train, не в обучении) |
| `expert_card.json` | карточка (ниже) |

`expert_card.json`:

| Поле | Тип | Правило |
|---|---|---|
| `expert_version` | str | `YYYYMMDD-<хеш8>` от конфига и хешей данных |
| `name` | str | `anomaly` |
| `kind` | str | `anomaly` (выход — перцентиль нормы в [0, 1]) |
| `candidate` | str | `iforest` \| `autoencoder` — победитель по PR-AUC «атака/не атака» на val |
| `features` | list[str] | только группа `feature` схемы минус `exclude_features` (FR-005) |
| `schema_version` | str | версия схемы признаков 001 |
| `threshold` | float | порог-перцентиль, выбран на норме val (R2) |
| `anomaly_fpr` | float | бюджет ложных срабатываний на норме val (по умолчанию 0.005) |
| `train` | obj | число потоков обучения и калибровки, сид, `benign_only: true` |
| `metrics` | obj | PR-AUC «атака/не атака» и доля нормы выше порога на val/test, перенос |
| `audit` | obj | однопризнаковый зонд, перестановочная важность, помеченные признаки (R6) |

Правила: в обучении и калибровке **нет ни одного потока атаки** (проверяется при обучении
и тестом); `features ⊆ SCHEMA.feature_columns()`.

### Ансамбль — `models/ensemble/`

| Файл | Содержимое |
|---|---|
| `ensemble_card.json` | что использует цепочка (ниже) |
| `meta.joblib` | мета-модель — только если выбран обучаемый мета-слой |
| `experiment.json` | вся таблица эксперимента (ниже, «Эксперимент ансамбля») |

`ensemble_card.json`:

| Поле | Тип | Правило |
|---|---|---|
| `ensemble_version` | str | `YYYYMMDD-<хеш8>` от конфига, версий экспертов, хешей данных |
| `selected` | str | `ensemble:<мета-кандидат>` \| `single:classifier` (FR-010) |
| `selection` | obj | `condition`: `macro_gain` \| `unknown_gain` \| `none`; цифры и текст правила |
| `experts` | list | `{name, kind, path, version}` — `classifier` (`models/detector`), `anomaly` |
| `meta` | obj \| null | кандидат, входы, веса по экспертам (для объяснения) |
| `classes` | list[str] | 10 классов UNSW (как у классификатора) |
| `threshold` | float | порог итогового вердикта по `1 − P(benign)`, выбран на OOF val |
| `class_rule` | obj | как выбирается класс: `anomaly`, если сработал только детектор аномалий |
| `schema_version` | str | общая мажорная версия схемы экспертов |
| `data_scheme` | obj | кто на чём учится: эксперты — train, мета — val OOF (K блоков, зазор), порог — OOF val, test — только отчёт (FR-008) |

Правила загрузки (FR-014): каждый эксперт из `experts` существует, его версия равна записанной,
мажорная версия схемы у всех одна; `selected = single:*` → `meta.joblib` не нужен; иначе нужен.
Нарушение → `DetectorLoadError` с именем эксперта до начала обработки.

## Эксперимент ансамбля — `models/ensemble/experiment.json`

| Раздел | Содержимое |
|---|---|
| `config`, `seed`, `data` | конфиг, сид, хеши разбиения и захватов, версия схемы |
| `experts` | для каждого: метрики на val/test (классификатор — PR-AUC по классам и macro; аномалии — PR-AUC «атака/не атака», оба кандидата) |
| `variants` | `classifier` (одиночный), `any_fired`, `mean_score`, `stack_logreg`: macro PR-AUC и по классам на val (OOF) и test, PR-AUC «атака/не атака», F1/precision/recall при пороге |
| `hidden_class` | по каждому скрытому классу: поимка на val/test у классификатора без класса, у детектора аномалий, у итогового вердикта; доля нормы test, ставшей алертом только из-за аномалий |
| `selection` | правило, пороги `min_gain` и `min_unknown_gain`, лучший одиночный, какое условие выполнено, выбранный вариант |
| `audit` | вывод аудита артефактов по экспертам и мета-слою (R6) |
| `unreliable_classes` | классы с < 50 примерами в оцениваемой части — PR-AUC помечен «ненадёжен» |
| `mlflow_run_ids` | ссылки на runs эксперимента `ensemble` |

## Вердикт потока — `var/runs/<run_id>/verdicts.parquet` (R11)

| Колонка | Тип | Было в 002 | Смысл |
|---|---|---|---|
| `flow_uid` | str | да | |
| `predicted_class` | str | да | итоговый класс: класс атаки, `anomaly` или `benign` |
| `attack_score` | f64 | да | `1 − P(benign)` итогового вердикта |
| `is_alert` | bool | да | `attack_score ≥ threshold` модели прогона |
| `p_<класс>` | f64 | да | вероятности итогового вердикта (у одиночного эксперта — его) |
| `e_<эксперт>_score` | f64 | нет | скор эксперта: классификатор — `1 − P(benign)`, аномалии — перцентиль |
| `e_<эксперт>_fired` | bool | нет | скор эксперта ≥ его собственного порога |
| `reversed` | bool | нет | правило R8 признало поток ответным |
| `true_label` | str | да | только для размеченного входа, только для сводки |

## Хранилище SQLite — схема 3 (R10)

### Миграция 2 → 3 (одна транзакция)

```text
ALTER TABLE alerts ADD COLUMN attacker_ip   TEXT
ALTER TABLE alerts ADD COLUMN victim_ip     TEXT
ALTER TABLE alerts ADD COLUMN reversed      INTEGER NOT NULL DEFAULT 0
ALTER TABLE alerts ADD COLUMN fired_experts TEXT      -- NULL = прогон до ансамбля
ALTER TABLE alerts ADD COLUMN experts       TEXT      -- JSON, NULL = прогон до ансамбля
ALTER TABLE alerts ADD COLUMN explanation   TEXT
UPDATE alerts SET attacker_ip = src_ip, victim_ip = dst_ip
CREATE INDEX ix_alerts_incident_experts ON alerts(incident_id, fired_experts)
PRAGMA user_version = 3
```

Схема 0 (002) мигрирует цепочкой 0 → 2 → 3. Аудит, решения, история, инциденты не меняются.
`SchemaTooNew` для версии > 3 — как в 003.

### Алерт (новые поля)

| Поле | Правило |
|---|---|
| `attacker_ip` | `dst_ip`, если `reversed`, иначе `src_ip`; ключ группировки вместе с классом |
| `victim_ip` | вторая сторона |
| `reversed` | 1 — поток ответный (R8); `src_*`/`dst_*` остаются как в потоке |
| `experts` | `{"classifier": {"score": .., "threshold": .., "fired": ..}, "anomaly": {...}}` |
| `fired_experts` | сработавшие эксперты через запятую по алфавиту, `""` — никто (алерт поднят мета-слоем) |
| `explanation` | одна-две фразы (ниже) |

Объяснение (детерминированное, по-русски), примеры:
- «сработали классификатор (exploits, 0.99 ≥ 0.986) и детектор аномалий (99.8-й перцентиль нормы ≥ 99.5)»;
- «сработал только детектор аномалий (99.9-й перцентиль ≥ 99.5) — класс атаки неизвестен»;
- «ни один эксперт не превысил свой порог, алерт поднял мета-слой (скор 0.93 ≥ 0.91)»;
- для перевёрнутого потока добавляется «поток ответный: атакующая сторона — <IP> (правило: <какое>)».

### Инцидент

Поля 002/003 без изменений. `src_ip` = атакующая сторона ключа группировки (для прогонов 004 —
`attacker_ip`; для старых — как было). `targets` — уникальные `victim_ip`. Класс `anomaly`
допустим; для него обязателен уровень в `severity.base`.

Сводка по экспертам (вычисляется, не хранится): `SELECT fired_experts, count(*) FROM alerts
WHERE incident_id = ? GROUP BY fired_experts` → «классификатор: N, детектор аномалий: M,
оба: K, только мета-слой: L»; для старых прогонов (`NULL`) — пометка «прогон до ансамбля».

### Прогон — `runs.summary` (JSON, новые ключи)

| Ключ | Содержимое |
|---|---|
| `model` | `{kind: detector|ensemble, version, selected}` |
| `experts` | `{имя: версия}` |
| `experts_meta` | `{имя: {kind, threshold, classes?}}` — для отображения порогов экспертов |
| `alerts_by_expert` | `{classifier: N, anomaly: M, meta_only: L}` (алерт с двумя учитывается у обоих) |
| `n_reversed` | число алертов с `reversed = 1` |
| `direction_mode` | `auto` \| `as_is` |

`detector_version` в таблице `runs` для прогонов 004 = версия ансамбля (`ensemble_version`) —
колонка остаётся, её смысл «версия модели прогона».

## Отчёт разбора источников — `reports/source_review_<run>.{md,json}` (R9)

| Раздел | Содержимое |
|---|---|
| `run_before`, `run_after` | прогоны сравнения |
| `incidents` | инциденты «до» с источником из сетей ролей `victims`/`background`: id, IP, класс, потоки с причинами `response_direction` \| `detector_error` \| `labeled_attack` |
| `counts` | число таких инцидентов до/после; сколько из-за направления, сколько ошибок детектора |
| `attackers_kept` | пары (IP, класс) атакующих «до» и есть ли каждая «после»; `lost: []` — требование SC-007 |

## Конфигурация

`configs/ensemble.yaml` (новый):

```yaml
split: unsw_time
seed: 42
classifier: models/detector          # эксперт 002, не переобучается
anomaly:
  candidates:
    iforest: {n_estimators: 300, max_samples: 4096}
    autoencoder: {hidden: [32, 12, 32], max_iter: 200}
  train_sample: 300000               # нормальных потоков train на обучение
  calibration_share: 0.10            # доля нормы train на калибровку перцентиля
  anomaly_fpr: 0.005                 # бюджет ложных срабатываний на норме val
  exclude_features: []               # по итогам аудита артефактов
meta:
  candidates: [any_fired, mean_score, stack_logreg]
  folds: 5
  gap_ms: 60000
hidden_classes: [exploits, dos]
selection:
  min_gain: 0.01
  min_unknown_gain: 0.10
unreliable_below: 50
output: {anomaly: models/experts/anomaly, ensemble: models/ensemble}
```

`configs/soc.yaml` (добавления): `severity.base.anomaly: medium`; правило плейбука
`unknown_class` сразу после `protected`; `grouping.direction: auto`.
