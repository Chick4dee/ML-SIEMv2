---

description: "Задачи фичи 004 — эксперты-детекторы, мета-слой и атакующая сторона"
---

# Tasks: Несколько экспертов-детекторов и мета-слой

**Input**: Design documents from `specs/004-detection-experts-ensemble/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli.md,
contracts/api-v1-additions.md, contracts/ui.md, quickstart.md

**Tests**: включены. Конституция (принципы III и VI) требует тестов на каждое правило и
отдельно — на отсутствие утечек: эксперт аномалий не видит атак, мета-слой не видит train
экспертов и test, порог и выбор — только по val. Быстрые тесты — на синтетике 002
(`synthetic_split`, `tiny_detector` из `tests/conftest.py`; в синтетике есть классы `exploits`,
`dos`, `reconnaissance`, `fuzzers`), медленные (`-m slow`) — на реальных данных 001 и базе
`var/soc.db`. Тесты пишутся до или вместе с кодом и должны падать до реализации.

**Organization**: задачи сгруппированы по историям спеки. Из-за природы фичи часть общего
кода вынесена в фундамент: базовый эксперт аномалий (Isolation Forest) нужен и US1 (ансамбль),
и US2 (качество эксперта), а схема БД 3 — и US3, и US4.

**Общие правила для всех задач**:
- Комментарии, отчёты, сообщения, объяснения — на русском, подробно и живым языком («почему»,
  а не пересказ кода). Идентификаторы — английские.
- **test не участвует ни в каком выборе**: ни в пороге, ни в выборе кандидата/варианта, ни в
  калибровке. Метрики test считаются в самом конце и только записываются (принцип III).
- На вход любого эксперта — только `SCHEMA.feature_columns()` минус `exclude_features`
  (FR-005); поля `identity`/`time`/`dpi` — никогда. Список признаков не пишется руками.
- Все пороги, доли, сиды, размеры выборок, скрытые классы — из `configs/ensemble.yaml`/
  `configs/soc.yaml`, не в коде.
- Детерминизм (SC-003): сиды во всех генераторах, `IsolationForest(random_state)`,
  `MLPRegressor(random_state)`, LightGBM `deterministic=True` как в 002; входы сортируются по
  `flow_uid`.
- Артефакты пишутся атомарно (`mlsiem.data.captures.atomic_path`), как в 002.
- Правило направления (`soc/direction.py`) не импортирует ничего про сети/метки (FR-023).
- API и консоль — только добавления; существующие поля и ответы 002/003 не меняются (FR-018).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: можно делать параллельно (разные файлы, нет зависимостей от незавершённых задач)
- **[Story]**: к какой истории относится задача (US1…US4)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: конфиги, скелет модулей, правка синтетики, DVC

- [X] T001 [P] Создать `configs/ensemble.yaml` ровно по data-model «Конфигурация»: `split: unsw_time`, `seed: 42`, `classifier: models/detector`, `anomaly.candidates` (`iforest: {n_estimators: 300, max_samples: 4096}`, `autoencoder: {hidden: [32, 12, 32], max_iter: 200}`), `anomaly.train_sample: 300000`, `anomaly.calibration_share: 0.10`, `anomaly.anomaly_fpr: 0.005`, `anomaly.exclude_features: []`, `meta.candidates: [any_fired, mean_score, stack_logreg]`, `meta.folds: 5`, `meta.gap_ms: 60000`, `hidden_classes: [exploits, dos]`, `selection: {min_gain: 0.01, min_unknown_gain: 0.10}`, `unreliable_below: 50`, `output: {anomaly: models/experts/anomaly, ensemble: models/ensemble}` — с комментариями по-русски к каждому ключу (что значит и откуда число: FR-003, FR-010, R2, R3, R5)
- [X] T002 [P] Дополнить `configs/soc.yaml`: `severity.base.anomaly: medium` (комментарий: класс «аномалия» — сработал только детектор аномалий, FR-017); правило плейбука `{id: unknown_class, when: {class_in: [anomaly]}, action: manual_review}` **сразу после** `protected`; `grouping.direction: auto` с комментарием `auto | as_is` (as_is — поведение 002, атакующий = src_ip; R8, R15)
- [X] T003 [P] Создать скелеты модулей с докстрингами назначения (по plan.md): `src/mlsiem/detect/anomaly.py`, `src/mlsiem/detect/meta.py`, `src/mlsiem/detect/ensemble.py`, `src/mlsiem/soc/direction.py`, `src/mlsiem/soc/review.py`
- [X] T004 Правка синтетики (research R15) в `tests/fixtures/make_synthetic_flows.py`: для потоков с `protocol == 6` выставлять `src2dst_syn_packets ≥ 1` и `bidirectional_syn_packets ≥ src2dst_syn_packets + dst2src_syn_packets` (инициатор — `src`, как задумано в синтетике); порты уже «клиент ≥ 1024 → сервис». Прогнать `uv run pytest` — все тесты 002/003 зелёные без изменения их ожиданий (SC-005)
- [X] T005 [P] Добавить в `dvc.yaml` стадию `train_ensemble` (contracts/cli.md «DVC»): `cmd: uv run mlsiem detect ensemble`; deps — `data/flows/unsw`, `data/splits/unsw_time.parquet`, `models/detector`, `src/mlsiem/detect`; params — `configs/ensemble.yaml` (все ключи); outs — `models/experts/anomaly`, `models/ensemble`, и `reports/ensemble_experiment.md` с `cache: false`; комментарий, что MLflow вне DVC, как у `train_detector`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: метрики, конфиг ансамбля, базовый эксперт аномалий (Isolation Forest), общий
интерфейс модели, схема БД 3. Всё, без чего не начинается ни одна история.

**⚠️ CRITICAL**: истории не начинаются, пока фаза не завершена.

### Тесты фундамента

- [X] T006 [P] Тесты новых метрик в `tests/unit/test_detect_metrics.py`: `binary_pr_auc(y_attack, score)` (совпадает с `average_precision_score`; `None`, если в части нет атак или нет нормы); `catch_rate(y, alerts, cls)` — доля потоков класса, ставших алертами (`None` без примеров); `fpr_on_benign(y, alerts)` — доля `benign` выше порога; `unreliable_classes(y, classes, below=50)` — классы с < 50 примерами
- [X] T007 [P] Тесты конфига в `tests/unit/test_detect_config.py` (новый класс тестов `EnsembleConfig`): валидный `configs/ensemble.yaml` читается; ошибки с понятным текстом — неизвестный кандидат аномалий или мета-слоя, `anomaly_fpr` вне (0, 0.5), `calibration_share` вне (0, 0.5), `folds < 2`, `gap_ms < 0`, отрицательные `min_gain`/`min_unknown_gain`, пустой `hidden_classes`, разбиение не UNSW
- [X] T008 [P] Тесты базового эксперта аномалий в `tests/unit/test_detect_anomaly.py` на `synthetic_split`: (а) в обучении и калибровке **нет ни одного потока атаки** — проверка по `flow_uid` против меток; обучающая и калибровочная выборки не пересекаются; (б) перцентиль лежит в [0, 1] и монотонен по сырому скору; (в) порог: доля `benign` val выше порога ≤ `anomaly_fpr` и это наименьший такой порог; метки атак в выборе порога не читаются (тест подменяет метки атак на случайные — порог тот же); (г) повторное обучение с тем же сидом — тот же артефакт (скоры совпадают); (д) карточка содержит все поля data-model `expert_card.json`, `benign_only: true`, `features ⊆ SCHEMA.feature_columns()`; (е) `load_anomaly_expert` отказывает (`DetectorLoadError`) при отсутствии `model.joblib`/`calibration.npy`/карточки или битом JSON
- [X] T009 [P] Тесты общего интерфейса модели в `tests/unit/test_detect_model.py`: `load_model(<каталог детектора 002>)` возвращает объект с `kind == "detector"`, `version`, `classes`, `threshold`, `features`, `experts == ["classifier"]`, `check_input()`, `verdict_frame(flows)`; `verdict_frame` для `tiny_detector` даёт те же `predicted_class`, `attack_score`, `is_alert`, `p_*`, что `soc.verdicts.compute_verdicts` 002, плюс `e_classifier_score`, `e_classifier_fired`; каталог без карточек → `DetectorLoadError` с текстом, какие файлы ожидались
- [X] T010 [P] Тесты миграции 2 → 3 в `tests/unit/test_store_migration.py` (дополнить): база схемы 2 строится из нового снимка `tests/fixtures/soc_schema_v2.sql` (T011) и заполняется прогоном, решением и аудитом; после `init_db` — `user_version == 3`, у `alerts` есть `attacker_ip`, `victim_ip`, `reversed` (`NOT NULL DEFAULT 0`), `fired_experts`, `experts`, `explanation`; `attacker_ip == src_ip` и `victim_ip == dst_ip` у всех старых алертов; `experts IS NULL`; число строк и содержимое `incidents`, `actions`, `incident_history`, `audit_log` (включая `entry_id`) не изменились; триггеры запрета UPDATE/DELETE аудита работают; цепочка 0 → 2 → 3 со снимка `soc_schema_002.sql` проходит; версия 4 → `SchemaTooNew`; сбой посреди миграции → база осталась в схеме 2 целиком

### Реализация фундамента

- [X] T011 [P] Снимок DDL схемы 2 в `tests/fixtures/soc_schema_v2.sql` — копия текущего `DDL` из `src/mlsiem/soc/store.py` с `PRAGMA user_version = 2` и шапкой-комментарием «копия DDL на коммите <текущий HEAD>, нужна тестам миграции 2 → 3» (как у `soc_schema_002.sql`)
- [X] T012 [P] Метрики в `src/mlsiem/detect/metrics.py`: `binary_pr_auc`, `catch_rate`, `fpr_on_benign`, `unreliable_classes` (T006); докстринги — зачем каждая (FR-006, FR-011, SC-002)
- [X] T013 [P] `EnsembleConfig` и `parse_ensemble_config`/`load_ensemble_config` в `src/mlsiem/detect/config.py` по образцу `DetectConfig`: проверки из T007, `KNOWN_ANOMALY_CANDIDATES = ("iforest", "autoencoder")`, `ANOMALY_BASELINE = "iforest"`, `KNOWN_META_CANDIDATES = ("any_fired", "mean_score", "stack_logreg")`, `raw` для хеша версии
- [X] T014 Базовый эксперт аномалий в `src/mlsiem/detect/anomaly.py` (research R1, R2): загрузка `benign` train через `detect.dataset.scan_part` с фильтром по метке; детерминированная стратифицированная по `capture_id` подвыборка `train_sample` и **отложенная** калибровочная норма `calibration_share` до обучения; кандидат `iforest` — конвейер `FunctionTransformer(_log1p_nonneg) → IsolationForest(random_state=seed, **params)`, сырой скор = `-score_samples` (больше — аномальнее); `percentile(raw)` через `np.searchsorted` по отсортированной калибровке; `choose_anomaly_threshold(benign_val_pct, fpr)` — наименьший порог, при котором доля нормы val `≥ порога` ≤ `fpr`; класс `AnomalyExpert` (`version`, `features`, `threshold`, `score(df) → перцентиль`, `check_input`) и `save_anomaly_expert`/`load_anomaly_expert` (файлы `model.joblib`, `calibration.npy`, `expert_card.json` с полями data-model); `expert_version()` — `YYYYMMDD-<хеш8>` от конфига и `data_hashes`, как `detector_version` 002
- [X] T015 Общий интерфейс модели в `src/mlsiem/detect/ensemble.py`: протокол/датакласс `LoadedModel` (`kind`, `version`, `selected`, `classes`, `threshold`, `features`, `experts`, `experts_meta`, `check_input`, `check_parquet`, `verdict_frame(flows) → pl.DataFrame` с колонками data-model «Вердикт потока»); `load_model(path)` — по наличию `ensemble_card.json` или `model_card.json`; для детектора 002 — обёртка над `load_detector` (колонки `e_classifier_*` из его скора и порога). Ветку ансамбля пока — `NotImplementedError` с понятным текстом (реализует T030)
- [X] T016 Схема 3 в `src/mlsiem/soc/store.py` (research R10, data-model «Миграция 2 → 3»): `SCHEMA_VERSION = 3`; новые колонки в `DDL` таблицы `alerts` (`attacker_ip TEXT`, `victim_ip TEXT`, `reversed INTEGER NOT NULL DEFAULT 0`, `fired_experts TEXT`, `experts TEXT`, `explanation TEXT`) и индекс `ix_alerts_incident_experts ON alerts(incident_id, fired_experts)`; `MIGRATION_V3` — шаги `ALTER TABLE … ADD COLUMN`, `UPDATE alerts SET attacker_ip = src_ip, victim_ip = dst_ip`, индекс, `PRAGMA user_version = 3` — одной транзакцией; `init_db` мигрирует 0 → 2 → 3 и 2 → 3; `ALERT_COLUMNS` дополнен новыми полями (значения по умолчанию для вызовов 002 — из `src_ip`/`dst_ip`, `reversed = 0`, остальное `NULL`); комментарий, почему здесь не нужно пересоздавать аудит (новых событий нет)

**Checkpoint**: `uv run pytest` зелёный (тесты 002/003 + фундамент); эксперт аномалий обучается
на синтетике, база 003 мигрирует на схему 3 без потерь.

---

## Phase 3: User Story 1 — Эксперимент «эксперты + мета-слой» против лучшего одиночного эксперта (Priority: P1) 🎯 MVP

**Goal**: `mlsiem detect ensemble` сравнивает классификатор 002, эксперт аномалий, правила
без обучения и стекинг; мета-слой учится на OOF по блокам времени val; эксперимент «скрытый
класс»; выбор по FR-010 только по val; артефакт `models/ensemble/` и отчёт.

**Independent Test**: запустить эксперимент на синтетике — появились `experiment.json` с
таблицей вариантов (macro PR-AUC и по классам на val/test), разделом скрытых классов,
выбором с условием и схемой данных, `ensemble_card.json` и отчёт; повтор даёт то же.

### Тесты для User Story 1

- [X] T017 [P] [US1] Тесты блоков времени и OOF в `tests/unit/test_detect_meta.py`: `time_blocks(first_seen_ms, k, gap_ms)` даёт k последовательных непересекающихся блоков по времени, потоки в зазоре `gap_ms` у границ не попадают в обучение соседнего блока; каждый поток val получает ровно одно OOF-предсказание от модели, **не** обучавшейся на его блоке (проверка подменой: модель-«шпион» запоминает индексы обучения); блоков меньше 2 или блок без примеров класса — понятная ошибка/пометка
- [X] T018 [P] [US1] Тесты мета-кандидатов в `tests/unit/test_detect_meta.py`: `any_fired` — алерт, если сработал хоть один эксперт на своём пороге, скор атаки = `max(1 − P(benign), перцентиль)`; `mean_score` — среднее двух скоров; `stack_logreg` — выход 10 вероятностей в порядке классов классификатора, сумма 1; вход мета-слоя собран только из ответов экспертов (признаки потока в него не попадают); `final_class(...)` — `anomaly`, если алерт поднят, классификатор на своём пороге не сработал, а детектор аномалий сработал; иначе самый вероятный класс атаки мета-выхода; ниже порога — `benign` (FR-017, research R4); объяснение детерминировано и по-русски (все четыре случая data-model «Объяснение»)
- [X] T019 [P] [US1] Тесты правила выбора в `tests/unit/test_detect_ensemble_select.py` (FR-010): (а) ансамбль +0.01 macro PR-AUC val → `ensemble:<мета>`, условие `macro_gain`; (б) macro +0.005, поимка скрытых +0.12, падение macro 0 → `unknown_gain`; (в) поимка +0.12, но macro упал на 0.02 → `single:classifier`, условие `none`; (г) ничего не прошло → `single:classifier`, текст «отрицательный результат»; (д) функция не получает и не читает метрики test (передача test-метрик не меняет выбор); (е) при равенстве вариантов выбирается более простой (правило без обучения раньше `stack_logreg`)
- [X] T020 [P] [US1] Тест скрытого класса в `tests/unit/test_detect_ensemble_hidden.py` на синтетике: классификатор-копия учится **без строк** скрытого класса (не перемаркированных в `benign`) с кандидатом и гиперпараметрами из `experiment.json` детектора; мета-слой скрытого эксперимента не видит строк скрытого класса в val; поимка считается на val и test при порогах, выбранных без скрытого класса; доля нормы test, ставшей алертом **только** из-за аномалий, записана (SC-002); скрытый класс, которого нет у классификатора, — ошибка конфига
- [X] T021 [P] [US1] Интеграционный тест в `tests/integration/test_ensemble_experiment.py` на `synthetic_split` + `tiny_detector` с маленьким конфигом (мало деревьев, `train_sample` ≤ 5000, `folds: 3`): `run_ensemble_experiment` создаёт `models/experts/anomaly/`, `models/ensemble/{ensemble_card.json, experiment.json}` и `reports/ensemble_experiment.md`; в таблице — `classifier`, `any_fired`, `mean_score`, `stack_logreg` с macro PR-AUC и по классам на val/test; у `classifier` метрики val/test равны метрикам карточки `tiny_detector` (FR-002); `data_scheme` описывает train/val-OOF/test (FR-008); `selection.condition` ∈ {`macro_gain`, `unknown_gain`, `none`}; `unreliable_classes` заполнен; повторный запуск в другой каталог — те же метрики, версия ансамбля и выбор (SC-003); тест-«ловушка»: если подменить метки test на случайные, выбор и пороги не меняются
- [X] T022 [P] [US1] Тест CLI в `tests/integration/test_ensemble_experiment.py`: `mlsiem detect ensemble --config <tmp>` — код 0 и в stdout таблица вариантов, скрытые классы, выбранный вариант и условие; без классификатора или с битым конфигом — код 1 и понятное сообщение до обучения

### Реализация User Story 1

- [X] T023 [US1] Блоки времени и OOF в `src/mlsiem/detect/meta.py` (research R3): `time_blocks(first_seen_ms, k, gap_ms)` — границы по квантилям времени, потоки ближе `gap_ms` к границе исключаются из обучения соседнего фолда; `oof_predict(fit_fn, X, y, blocks)` — предсказания каждого блока моделью на остальных; комментарий «почему блоки, а не случайные фолды»
- [X] T024 [US1] Мета-кандидаты в `src/mlsiem/detect/meta.py` (research R4): `meta_input(expert_outputs)` — `log(p + 1e-6)` 10 вероятностей классификатора + перцентиль аномальности; `any_fired`, `mean_score` (без обучения) и `stack_logreg` (`LogisticRegression(class_weight="balanced", random_state=seed, max_iter=1000)`); единый выход — матрица вероятностей в порядке классов классификатора; `final_class()` и `explain()` — детерминированный текст по data-model «Объяснение»
- [X] T025 [US1] Эксперимент скрытого класса в `src/mlsiem/detect/ensemble.py` (research R5): для каждого `hidden_classes` — обучение копии классификатора без строк класса (кандидат и параметры из `<classifier>/experiment.json` → `config.candidates[winner]`, `build_candidate` 002), его порог по F1 на val без класса (`choose_threshold`), мета-слой на OOF val без класса, поимка (`catch_rate`) на val/test у классификатора без класса, эксперта аномалий и итогового вердикта; доля нормы test «только из-за аномалий» (`fpr_on_benign` по алертам, где сработал лишь детектор аномалий)
- [X] T026 [US1] Правило выбора `select_variant(val_results, hidden_results, cfg)` в `src/mlsiem/detect/ensemble.py` (FR-010, T019): лучший одиночный по macro PR-AUC — только эксперт с классами (`classifier`); условия `macro_gain`/`unknown_gain` с порогами из конфига; при равенстве — более простой вариант; человеческий текст решения; сигнатура не принимает метрики test
- [X] T027 [US1] `run_ensemble_experiment(cfg, …)` в `src/mlsiem/detect/ensemble.py`: порядок строго по contracts/cli.md (загрузка и проверка классификатора → эксперт аномалий `iforest` из T014 → вход мета-слоя на val → OOF мета-кандидатов, пороги по F1 на OOF (`choose_threshold`) → скрытые классы → выбор → финальная мета-модель на всей val → метрики test всех вариантов → артефакты); MLflow-эксперимент `ensemble` (по run на вариант, теги `split_hash`, `schema_version`, `ensemble_version`, `git_commit`), `ensemble_version()` от конфига, версий экспертов и хешей данных; атомарная запись `ensemble_card.json` (поля data-model, включая `selected`, `selection.condition`, `data_scheme`, `class_rule`), `meta.joblib` (только если выбран обучаемый мета-слой), `experiment.json`; освобождение памяти train после обучения (как в 002); ключевой аргумент `force_variant: str | None = None` только для тестов — при нём выбор подменяется, а в `experiment.json` и карточке пишется `selection.forced: true` и условие `forced`, CLI такого флага не имеет
- [X] T028 [US1] Отчёт `render_ensemble_report(exp)` в `src/mlsiem/detect/ensemble.py` → `reports/ensemble_experiment.md`: таблица вариантов (macro PR-AUC val/test, PR-AUC «атака/не атака», порог, F1), PR-AUC по классам с пометкой «ненадёжен» для классов из `unreliable_classes`, таблица скрытых классов, выбор и условие словами, схема данных, отрицательный результат — явным абзацем, если ансамбль не прошёл
- [X] T029 [US1] CLI `detect ensemble` в `src/mlsiem/cli.py` (contracts/cli.md): опции `--config configs/ensemble.yaml`, `--reports-dir reports`, общая `--data-dir`; stdout — таблицы вариантов и скрытых классов, выбор и условие; ошибки конфига/данных/классификатора — код 1 до обучения
- [X] T030 [US1] Ветка ансамбля в `load_model()` (`src/mlsiem/detect/ensemble.py`, research R7, FR-014): чтение `ensemble_card.json`, загрузка экспертов по `experts[].path` и сверка версий, одинаковая мажорная версия схемы, `meta.joblib` обязателен для `selected: ensemble:*`; `verdict_frame(flows)` — ответы экспертов, мета-выход, `final_class`, `is_alert` по порогу ансамбля, колонки `e_<эксперт>_score/_fired`; для `selected: single:classifier` — вердикты классификатора, но `version` = версия ансамбля и `selected` в объекте; нарушения → `DetectorLoadError` с именем эксперта. Тесты — в `tests/unit/test_detect_model.py` (дополнить T009: ансамбль из T021 грузится; подмена версии эксперта, удалённый `model.joblib` эксперта, другая мажорная схема, отсутствующий `meta.joblib` — отказ с именем эксперта)

**Checkpoint**: `uv run mlsiem detect ensemble` на синтетике (через тесты) и готов к реальному
прогону (T063) — MVP фичи: решение «ансамбль или нет» с цифрами.

---

## Phase 4: User Story 2 — Детектор аномалий для неизвестных атак (Priority: P2)

**Goal**: второй кандидат (автокодировщик) против бейзлайна Isolation Forest, выбор по
PR-AUC «атака/не атака» на val, аудит артефактов эксперта и мета-слоя, пороги и метрики
эксперта в отчёте.

**Independent Test**: обучение эксперта аномалий на синтетике даёт таблицу кандидатов с
PR-AUC на val/test, выбор по правилу бейзлайна, раздел аудита с однопризнаковым зондом и
перестановочной важностью — без участия мета-слоя.

### Тесты для User Story 2

- [X] T031 [P] [US2] Тесты кандидата `autoencoder` в `tests/unit/test_detect_anomaly.py`: конвейер `log1p → StandardScaler → MLPRegressor(hidden_layer_sizes=hidden, random_state=seed, early_stopping=True)` учится восстанавливать вход (цель = вход), сырой скор = MSE восстановления по признакам; детерминизм с сидом; обучение только на норме
- [X] T032 [P] [US2] Тесты выбора кандидата аномалий в `tests/unit/test_detect_anomaly.py`: по PR-AUC «атака/не атака» на val; `autoencoder` выбирается, только если лучше `iforest` на ≥ `min_gain`, иначе бейзлайн; метрики test в выбор не передаются
- [X] T033 [P] [US2] Тесты аудита в `tests/unit/test_detect_audit_models.py` (research R6): однопризнаковый зонд на искусственных данных, где один признак идеально разделяет норму и атаки, помечает этот признак (PR-AUC ≥ 0.9); перестановочная важность детерминирована с сидом и ранжирует «разделяющий» признак первым; `exclude_features` из конфига реально убирает признак из входа эксперта (признака нет в `features` карточки и во входной матрице)

### Реализация User Story 2

- [X] T034 [US2] Кандидат `autoencoder` в `src/mlsiem/detect/anomaly.py` (research R1) и выбор кандидата `select_anomaly_candidate(val_pr_auc, baseline="iforest", min_gain)`; обучение обоих кандидатов на одной подвыборке нормы, калибровка и порог — одинаково для обоих (T014); метрики каждого кандидата на val/test (PR-AUC «атака/не атака», доля нормы выше порога) — в карточку победителя и `experiment.json`
- [X] T035 [US2] Аудит в `src/mlsiem/detect/audit_models.py` (новый модуль, research R6): `single_feature_probe(X_val, y_attack, features)` — PR-AUC каждого признака и его отрицания, пометка ≥ 0.9; `permutation_importance_score(score_fn, X_val, y_attack, seed, top=10)` — падение PR-AUC «атака/не атака»; `meta_weights(stack_model, input_names)` — вклад экспертов в стекинг; вывод — словарь для карточки/`experiment.json` и абзац текста «что подозрительно и что решено»
- [X] T036 [US2] Встроить US2 в эксперимент: `run_ensemble_experiment` (`src/mlsiem/detect/ensemble.py`) обучает оба кандидата аномалий, выбирает по T034, пишет аудит эксперта и мета-слоя (T035) в `expert_card.json`/`experiment.json`; отчёт `render_ensemble_report` получает разделы «Детектор аномалий: кандидаты» и «Аудит артефактов» (помеченные признаки + решение: исключить через `exclude_features` или оставить с пометкой «завышено»); CLI печатает помеченные признаки
- [X] T037 [US2] Дополнить интеграционный тест `tests/integration/test_ensemble_experiment.py`: в `experiment.json` оба кандидата аномалий с метриками и выбранный; в карточке эксперта раздел `audit`; в отчёте разделы US2; доля нормы val выше порога ≤ `anomaly_fpr`

**Checkpoint**: эксперт аномалий выбран экспериментом и проверен на артефакты; отчёт отвечает
«помогает ли он и не жульничает ли».

---

## Phase 5: User Story 3 — Итоговый вердикт в цепочке и вклад экспертов в консоли (Priority: P3)

**Goal**: `soc run --model` работает с детектором или ансамблем; алерты хранят ответы
экспертов и объяснение; класс `anomaly` → ручной разбор; API и консоль показывают вклад
экспертов; старые прогоны открываются.

**Independent Test**: сквозной прогон на синтетике с ансамблем (`tiny_ensemble`), затем
проверки API и консоли: блок экспертов у алерта, сводка у инцидента, старый прогон без
ошибок, все тесты 002/003 зелёные.

### Тесты для User Story 3

- [X] T038 [P] [US3] Фикстура `tiny_ensemble` в `tests/conftest.py` (scope session): `run_ensemble_experiment` на `synthetic_split` + `tiny_detector` с маленьким конфигом (как в T021) и аргументом `force_variant="stack_logreg"` (только ключевой аргумент функции, не ключ конфига; комментарий «для тестов цепочки, не для выводов») — чтобы у цепочки всегда были два эксперта
- [X] T039 [P] [US3] Тесты плейбука в `tests/unit/test_soc_playbooks.py` (дополнить): инцидент класса `anomaly` при любой серьёзности и числе алертов → `manual_review`, правило `unknown_class`; если правило убрано из конфига или стоит ниже `noisy_attack`, страховка `anomaly_guard` всё равно даёт `manual_review`; прочие классы — как в 002
- [X] T040 [P] [US3] Тесты конфига SOC в `tests/unit/test_soc_config.py` (дополнить): модель с классом `anomaly` без уровня в `severity.base` → понятная ошибка при `soc run` до обработки; `grouping.direction` принимает только `auto`/`as_is`
- [X] T041 [P] [US3] Тесты вердиктов/алертов в `tests/unit/test_soc_verdicts.py` (дополнить): из `verdict_frame` ансамбля алерты получают `experts` (JSON `{имя: {score, threshold, fired}}`), `fired_experts` (по алфавиту через запятую, `""` — только мета-слой), `explanation`; колонки `verdicts.parquet` — все колонки 002 плюс `e_<эксперт>_score/_fired`, `reversed` (data-model); для детектора 002 — один эксперт `classifier`
- [X] T042 [P] [US3] Интеграционный тест цепочки в `tests/integration/test_chain_ensemble.py`: `run_chain(..., model_dir=tiny_ensemble)` на test синтетики — прогон записан; в `runs.summary` ключи `model`, `experts`, `experts_meta`, `alerts_by_expert`, `n_reversed`, `direction_mode`; `runs.detector_version` = версия ансамбля; повторный прогон — те же вердикты, инциденты, серьёзности, действия (SC-003); удалённый `model.joblib` эксперта → отказ до обработки с именем эксперта, в БД и `runs_dir` ничего не появилось (US3 п. 6); `run_chain` с каталогом детектора 002 работает как раньше
- [X] T043 [P] [US3] Тест выбора модели в CLI в `tests/integration/test_chain_ensemble.py`: `soc run --model <ансамбль>`; `--detector <каталог>` — синоним; без `--model` при наличии `models/ensemble/ensemble_card.json` берётся ансамбль, иначе детектор и строка предупреждения (contracts/cli.md); stdout содержит модель прогона, алерты по экспертам, ответные потоки
- [X] T044 [P] [US3] Тесты API в `tests/api/test_api_experts.py` (новый): у алертов прогона ансамбля — `attacker_ip`, `victim_ip`, `reversed`, `experts`, `fired_experts` (список), `explanation`; у прогона 002 (добавлен в базу через `run_chain` с `tiny_detector` до миграции/или вставкой строк без экспертов) — те же поля `null`, кроме `attacker_ip`/`victim_ip`/`reversed`; `experts_summary` карточки: `by_expert`, `combinations`, `available`; для старого прогона — `available: false` и пометка; `GET /runs` → `model`; фильтр `attack_class=anomaly` принимается; существующие поля ответов 002/003 не изменились (сравнение ключей со снимком)
- [X] T045 [P] [US3] Тесты консоли в `tests/ui/test_experts_ui.py` (новый): фрагмент деталей алерта — блок «Эксперты» с объяснением первым, таблицей «эксперт / скор / порог / сработал», итоговым вердиктом (contracts/ui.md); для старого прогона — строка «Прогон сделан до появления ансамбля»; карточка — блок «Кто поднял алерты» с подписью про двойной учёт; таблица алертов — значок «ответный» и колонка экспертов с легендой; фильтр класса содержит «аномалия (класс неизвестен)»; панель — «Модель прогона» и счётчики по экспертам; все данные экранированы, без inline-скриптов (как проверки 003)

### Реализация User Story 3

- [X] T046 [US3] Страховка `anomaly_guard` в `src/mlsiem/soc/playbooks.py` (research R12): после выбора правила, если класс инцидента `anomaly`, а действие `block_source_ip`/`isolate_host`, — заменить на `manual_review` с `rule_id = "anomaly_guard"` и дописанным пояснением; константа имени класса — одна, общая с `detect/meta.py` (например, `ANOMALY_CLASS` в `mlsiem/detect/metrics.py`)
- [X] T047 [US3] `src/mlsiem/soc/config.py`: `grouping.direction` (`auto`|`as_is`, по умолчанию `auto`) в `SocConfig`; проверка уровня серьёзности для всех классов модели, включая `anomaly`, — функция принимает список классов модели (`LoadedModel.classes` + `anomaly`, если в модели есть эксперт аномалий)
- [X] T048 [US3] Вердикты и алерты в `src/mlsiem/soc/verdicts.py`: `compute_verdicts(model, flows)` берёт `model.verdict_frame(flows)` (интерфейс T015/T030), `alerts_from_verdicts` добавляет `experts` (JSON, `ensure_ascii=False`, `sort_keys=True`), `fired_experts`, `explanation`, `reversed`, `attacker_ip`, `victim_ip` (пока `attacker_ip = src_ip` — направление добавит US4, T056); старое поведение для детектора 002 сохранено (T041)
- [X] T049 [US3] Прогон в `src/mlsiem/soc/run.py`: `run_chain(..., model_dir)` через `load_model` (параметр `detector_dir` оставить синонимом), проверки моделей и классов до обработки; `_needed_columns` — из `model.features`; в `summary` — `model`, `experts`, `experts_meta`, `alerts_by_expert` (алерт с двумя экспертами учитывается у обоих, `meta_only` — только мета-слой), `n_reversed`, `direction_mode`; `RunSummary` и `_print_run_summary` в `src/mlsiem/cli.py` печатают модель, алерты по экспертам, ответные потоки, инциденты `anomaly`
- [X] T050 [US3] CLI `soc run`/`soc serve` в `src/mlsiem/cli.py`: опция `--model` (по умолчанию `models/ensemble`, если там есть `ensemble_card.json`, иначе `models/detector` с предупреждением), `--detector` — синоним; `soc serve` печатает строку о миграции до схемы 3; `soc status` показывает версию модели прогона
- [X] T051 [US3] Хранилище в `src/mlsiem/soc/store.py`: `write_run` пишет новые поля алертов; `experts_summary(conn, incident_id)` — `GROUP BY fired_experts` → `{available, by_expert, combinations, note}` (data-model «Сводка по экспертам», contracts/api-v1-additions.md); `NULL` у всех алертов → `available: false`
- [X] T052 [US3] API в `src/mlsiem/soc/api.py` (contracts/api-v1-additions.md): модель `Alert` + `attacker_ip`, `victim_ip`, `reversed`, `experts`, `fired_experts: list[str] | None`, `explanation` (все с `None` по умолчанию); `IncidentCard` + `experts_summary`; `Run` + `model` (для старых прогонов — `{kind: "detector", version: detector_version, selected: None, experts: None}`); фильтр класса допускает `anomaly` (ключи `severity.base`)
- [X] T053 [US3] Консоль: `src/mlsiem/ui/labels.py` — русские имена экспертов («классификатор атак», «детектор аномалий», «мета-слой»), подпись класса `anomaly` «аномалия (класс неизвестен)», короткие метки «К», «А», «К+А», «М», «ответный»; `src/mlsiem/ui/views.py` — `alert_probs` дополняет результат блоком экспертов из SQLite (`experts`, `explanation`, `reversed`, `attacker_ip`) и моделью прогона из `summary.model`, для старых прогонов — пометка; `incident_card` — `experts_summary`; `dashboard` — модель прогона и `alerts_by_expert`
- [X] T054 [US3] Шаблоны консоли в `src/mlsiem/ui/templates/fragments/`: `_probs.html` — блок «Эксперты» (объяснение первым, таблица, итог, направление); новый `_experts_summary.html` в карточке (`incident.html`); `_alerts.html` — значок «ответный» и колонка экспертов с легендой; `_dashboard_counters.html` — «Модель прогона» и счётчики по экспертам; стили — в `src/mlsiem/ui/static/console.css`, без `style=""` и inline-скриптов

**Checkpoint**: цепочка с ансамблем проходит от прогона до консоли; старые прогоны не ломаются;
тесты 002/003 зелёные без изменения ожиданий.

---

## Phase 6: User Story 4 — Разбор ложных инцидентов с адресов жертв и фона (Priority: P4)

**Goal**: правило атакующей стороны по данным потока, группировка по нему, отчёт разбора
14 инцидентов и сравнение «до/после».

**Independent Test**: на синтетике с искусственно перевёрнутыми потоками правило находит
их, инциденты группируются по атакующему, `soc review-sources` даёт отчёт с причинами и
проверкой «атакующие не потеряны».

### Тесты для User Story 4

- [X] T055 [P] [US4] Тесты правила в `tests/unit/test_soc_direction.py` (research R8): TCP, `src2dst_syn_packets == 0` и `dst2src_syn_packets > 0` → перевёрнут (правило `tcp_syn`); TCP с SYN у `src` → прямой, даже если `src_port < 1024`; без SYN: `src_port < 1024` и `dst_port ≥ 1024` → перевёрнут (правило `service_port`); UDP `59.166.0.x:5227 → :53` → прямой; эфемерный ↔ эфемерный без SYN → прямой; векторная функция на кадре даёт то же, что поштучно; модуль не импортирует `mlsiem.soc.config`, `flags`, `review` и не читает колонку `label` (проверка по AST, как тест SOAR 002)
- [X] T056 [P] [US4] Тесты группировки в `tests/unit/test_soc_incidents.py` (дополнить): при `direction: auto` перевёрнутый алерт `149.171.126.17:80 → 175.45.176.0` попадает в инцидент с ключом `175.45.176.0`, `targets` содержит `149.171.126.17`; объект `block_source_ip` — `175.45.176.0`; исходные `src_*`/`dst_*` алерта не изменены, `reversed = 1`; объяснение содержит «поток ответный»; при `direction: as_is` — поведение 002 байт в байт (на синтетике инциденты совпадают со снимком до изменений)
- [X] T057 [P] [US4] Тесты разбора в `tests/unit/test_soc_review.py` (research R9): на базе с прогонами «до» и «после» (фикстура строит их через `run_chain` с `direction: as_is` и `auto` на синтетике с добавленными ответными потоками от `149.171.126.x` и ложными DNS от `59.166.0.x`): причины `response_direction`/`detector_error`/`labeled_attack` по потокам; `counts` до/после; `attackers_kept` — атакующие (IP вне сетей жертв/фона, алерты — атаки по метке) все присутствуют «после», `lost: []`; искусственно удалённый атакующий попадает в `lost`; прогон без `true_label` → понятная ошибка
- [X] T058 [P] [US4] Тест CLI `soc review-sources` в `tests/integration/test_soc_review_cli.py`: код 0, файлы `reports/source_review_<run>.md` и `.json`, строка сводки «было N → стало M…»; при потере атакующих — строка «ПОТЕРЯНЫ АТАКУЮЩИЕ» и код 0; несуществующий прогон → код 1

### Реализация User Story 4

- [X] T059 [US4] `attacker_side(flows) → pl.DataFrame(flow_uid, reversed, direction_rule, attacker_ip, victim_ip)` в `src/mlsiem/soc/direction.py` (research R8): правила `tcp_syn`, `tcp_syn_src` (прямой), `service_port`, `default`; векторно на polars; порог «сервисного» порта 1024 — константа с комментарием; докстринг «почему не по сетям и не по меткам» (FR-023)
- [X] T060 [US4] Встроить направление в цепочку: `src/mlsiem/soc/verdicts.py` — `alerts_from_verdicts` берёт `attacker_ip`/`victim_ip`/`reversed` из `attacker_side` при `direction: auto` (при `as_is` — `src_ip`/`dst_ip`, `reversed = 0`), колонку `reversed` — и в `verdicts.parquet`; в объяснение алерта дописывается «поток ответный: атакующая сторона — <IP> (правило: …)»; `src/mlsiem/soc/incidents.py` — `KEY = ["attacker_ip", "predicted_class"]`, в инцидент `src_ip` пишется `attacker_ip`, `targets` — уникальные `victim_ip`; `incident_id` считается от атакующей стороны; `src/mlsiem/soc/run.py` — передача `cfg.direction`, `n_reversed` в сводку
- [X] T061 [US4] Разбор в `src/mlsiem/soc/review.py` (research R9, data-model «Отчёт разбора»): выбор инцидентов «до» с источником в сетях ролей `victims`/`background` (`configs/soc.yaml` `networks`), причины по потокам (метка из `verdicts.parquet` `true_label` + `attacker_side` по потокам из данных 001/`flows.parquet` прогона), сравнение с прогоном «после», `attackers_kept`/`lost`; `render_review(report)` → Markdown по-русски; запись `.md` и `.json` атомарно; комментарий, что знание сетей здесь — только для оценки
- [X] T062 [US4] CLI `soc review-sources --run --after --reports-dir` в `src/mlsiem/cli.py` (contracts/cli.md): сводка в stdout, коды возврата по контракту

**Checkpoint**: инциденты группируются по атакующей стороне; отчёт разбора получается одной
командой.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: реальные прогоны, производительность, журнал, приёмка по quickstart

- [X] T063 Реальный эксперимент (quickstart §2): копия базы `var/soc.db → var/soc.db.bak-003`; `uv run mlsiem detect ensemble` (или `dvc repro train_ensemble`) на полных данных; проверить: у `classifier` 0.711/0.697 (FR-002), доля нормы val выше порога ≤ 0.5%, время ≤ 30 мин, память ≤ 16 ГБ; разобрать аудит — при подозрительных признаках решить с владельцем, исключать ли (`exclude_features`) и перезапустить
- [X] T064 [P] Медленные тесты в `tests/integration/test_ensemble_real.py` (`@pytest.mark.slow`): карточки реального ансамбля и эксперта валидны; `soc run` на test `unsw_time` с ансамблем ≤ 15 мин (SC-004), повтор — те же инциденты (SC-003); доля нормы test «только из-за аномалий» ≤ 1% (SC-002)
- [X] T065 Реальный разбор источников (quickstart §5): `soc run --model models/detector` (direction auto) и `soc review-sources --run 20260924T110457-1e531f --after <новый>` — проверить SC-007 (0 только из-за направления, < 14, `lost: []`); затем тот же разбор для прогона ансамбля; цифры — в журнал
- [X] T066 [P] Проверка консоли в браузере (quickstart §4) через превью `soc-console` из `.claude/launch.json`: миграция до схемы 3, старые прогоны, блок экспертов, «Кто поднял алерты», фильтр «аномалия», действие «ручной разбор»; скриншот как доказательство; ошибок CSP в консоли браузера нет
- [X] T067 [P] Новый PCAP (quickstart §6): `soc run --pcap A:/datasets/CTU-13/CTU-13-Dataset/7/botnet-capture-20110816-sogou.pcap` с ансамблем — прогон проходит, модель и эксперты в сводке
- [X] T068 [P] `uv run ruff check .` и `uv run pytest` — всё чисто и зелёно; `uv run pytest -m slow` — зелёно
- [X] T069 Запись в `docs/JOURNAL.md` (quickstart §7): таблица вариантов и кандидатов аномалий, скрытые классы (поимка val/test), аудит и решения по нему, выбранный вариант и условие (отрицательный результат — как есть), время эксперимента и прогона, разбор источников (14 → N, причины, `lost`), находки
- [ ] T070 [P] `dvc push` артефактов `models/experts/anomaly`, `models/ensemble` — **только с разрешения владельца** (в 002 push не делался); обновить README/доки, если в них описан `soc run` без `--model`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: без зависимостей; T004 (синтетика) — до любого теста, который гоняет
  группировку.
- **Foundational (Phase 2)**: после Setup; блокирует все истории. T011 → T010; T012, T013 → T014;
  T014 → T015 (эксперт нужен интерфейсу только в ветке ансамбля, T030); T016 независим.
- **US1 (Phase 3)**: после фундамента. Внутри: T023 → T024 → T025 → T026 → T027 → T028 → T029;
  T030 после T027 (нужен сохранённый ансамбль).
- **US2 (Phase 4)**: после фундамента; T034 можно делать параллельно с US1, но T036 встраивается
  в `run_ensemble_experiment` — после T027.
- **US3 (Phase 5)**: после US1 (нужен `load_model` для ансамбля, T030) и T016. Для работы с
  одиночным детектором 002 может начинаться сразу после фундамента (T046–T048 не зависят от
  ансамбля).
- **US4 (Phase 6)**: после фундамента (T016); T060 правит те же файлы, что T048/T049 (`verdicts.py`,
  `run.py`) — делать **после** T048/T049, чтобы не конфликтовать.
- **Polish (Phase 7)**: после всех историй; T065 требует US4, T063/T064 — US1–US3.

### User Story Dependencies

- **US1 (P1)**: только фундамент. MVP.
- **US2 (P2)**: фундамент; встраивание в отчёт — после US1 (T027).
- **US3 (P3)**: US1 (ансамбль как модель); US2 не обязательна (с одним кандидатом `iforest`
  цепочка тоже работает).
- **US4 (P4)**: фундамент; логически независима от ансамбля (работает и с детектором 002);
  по файлам — после US3 (`verdicts.py`, `incidents.py`, `run.py`).

### Within Each User Story

- Тесты пишутся первыми и падают до реализации.
- Чистые функции (метрики, блоки, мета-кандидаты, правило, направление) → оркестрация
  (эксперимент, прогон) → хранилище/API → консоль.
- Каждая история завершается своим checkpoint-ом с зелёными тестами.

### Parallel Opportunities

- Setup: T001, T002, T003, T005 — параллельно; T004 отдельно (гоняет весь набор тестов).
- Фундамент: тесты T006–T010 параллельно; реализация T011, T012, T013, T016 параллельно.
- US1: тесты T017–T022 параллельно.
- US2: T031–T033 параллельно; T034/T035 — в разных файлах, параллельно.
- US3: тесты T038–T045 параллельно; T046, T047, T051, T052 — разные файлы.
- US4: тесты T055–T058 параллельно; T059 и T061 — разные файлы.
- Polish: T064, T066, T067, T068 параллельно после T063.

---

## Parallel Example: User Story 1

```bash
# Сначала все тесты US1 — разные файлы:
Task: "T017 Тесты блоков времени и OOF в tests/unit/test_detect_meta.py"
Task: "T019 Тесты правила выбора в tests/unit/test_detect_ensemble_select.py"
Task: "T020 Тест скрытого класса в tests/unit/test_detect_ensemble_hidden.py"
Task: "T021 Интеграционный тест в tests/integration/test_ensemble_experiment.py"
# Затем реализация по порядку: T023 → T024 → T025 → T026 → T027 → T028 → T029 → T030
```

## Parallel Example: User Story 3

```bash
Task: "T039 Тесты плейбука anomaly в tests/unit/test_soc_playbooks.py"
Task: "T044 Тесты API экспертов в tests/api/test_api_experts.py"
Task: "T045 Тесты консоли в tests/ui/test_experts_ui.py"
# Реализация в разных файлах параллельно:
Task: "T046 anomaly_guard в src/mlsiem/soc/playbooks.py"
Task: "T052 Поля API в src/mlsiem/soc/api.py"
```

---

## Implementation Strategy

### MVP First (User Story 1)

1. Phase 1 (Setup) → Phase 2 (Foundational): эксперт аномалий `iforest`, метрики, схема 3.
2. Phase 3 (US1): эксперимент с мета-слоем, скрытыми классами и правилом выбора.
3. **STOP and VALIDATE**: `detect ensemble` на реальных данных (T063) — ответ на главный вопрос
   фичи «помогает ли ансамбль» с цифрами, даже отрицательный.

### Incremental Delivery

1. US1 → решение «ансамбль или нет» (MVP).
2. US2 → второй кандидат аномалий и аудит артефактов — честность цифр US1.
3. US3 → ансамбль в цепочке, API и консоли — видно аналитику.
4. US4 → группировка по атакующей стороне и отчёт по 14 инцидентам.
5. Polish → реальные прогоны, браузер, журнал.

Если US1 даст отрицательный результат, US3 всё равно делается: цепочка работает с
`single:classifier`, а блок экспертов показывает, что ансамбль не принят и почему.

---

## Notes

- [P] — разные файлы и нет зависимостей от незавершённых задач.
- Скачивать ничего не нужно: новых зависимостей нет.
- Рабочая `var/soc.db` мигрирует при первом `soc serve`/`soc run` — перед этим копия
  (T063), как в 003.
- `dvc push` и любые публикации — только с разрешения владельца (T070).
- После каждой истории — предложить владельцу название коммита; коммитит он сам.
