---

description: "Задачи фичи 002 — сквозная цепочка детекция → инцидент → реагирование → API"
---

# Tasks: Сквозная цепочка «детекция → инцидент → реагирование → API»

**Input**: Design documents from `specs/002-detection-incident-chain/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli.md, contracts/api.md, quickstart.md

**Tests**: включены. Конституция (принцип VI), research R15 и SC-006 требуют тестов на каждый
модуль: модульные — на синтетических таблицах потоков, API — через `TestClient` на временной БД,
интеграционный — «синтетика → обучение → прогон → API», медленные (`-m slow`) — на реальных
данных 001 и PCAP CTU-13 №7. Тесты пишутся до или вместе с кодом модуля и должны падать до
реализации.

**Organization**: задачи сгруппированы по пользовательским историям, чтобы каждую можно было
реализовать и проверить отдельно.

**Общие правила для всех задач**:
- Комментарии, сообщения CLI и тексты ошибок API — на русском, подробно и живым языком.
- Вход детектора — только `SCHEMA.feature_columns()` из `src/mlsiem/data/schema.py`; поля групп
  `identity`/`time`/`dpi`/`label` в модель не попадают никогда (FR-004). Список полей руками не пишется.
- Все пороги, окна, таблицы серьёзности, правила плейбуков и пути — только из
  `configs/detect.yaml` и `configs/soc.yaml`, не в коде.
- Детерминизм (R7): сид из конфига везде; вход сортируется по `flow_uid`; идентификаторы
  инцидентов и действий — хеши, а не счётчики.
- Никаких реальных сетевых действий, команд ОС, вызовов файрвола (FR-019) — только записи в БД.
- Файлы результатов пишутся через `atomic_path` из `src/mlsiem/data/captures.py`.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: можно делать параллельно (разные файлы, нет зависимостей от незавершённых задач)
- **[Story]**: к какой истории относится задача (US1…US5)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: зависимости, конфиги, скелет пакетов, игнор-файлы

- [X] T001 Добавить в `pyproject.toml` зависимости `lightgbm`, `mlflow`, `fastapi`, `uvicorn`, `joblib`; в extra `dev` — `httpx` (для `TestClient`); в `[tool.pytest.ini_options].markers` оставить `slow` с уточнённым описанием («реальные датасеты 001 и PCAP на диске A:»); затем `uv sync --extra dev` для обновления `uv.lock`
- [X] T002 [P] Создать скелет пакетов по plan.md: `src/mlsiem/detect/__init__.py`, `src/mlsiem/soc/__init__.py`, `tests/api/__init__.py` (каталоги `tests/unit/`, `tests/integration/` уже есть)
- [X] T003 [P] Дополнить `.gitignore`: `/var/` (SOC-состояние аналитика — ни в git, ни в DVC), `/mlruns/`, `/models/*` кроме `.gitignore`/`*.dvc`, `mlflow.db`
- [X] T004 [P] Создать `configs/detect.yaml` строго по контракту `contracts/cli.md`: `split: unsw_time`, `transfer_split: unsw_cross_day`, `seed: 42`, `selection.metric: macro_pr_auc_val`, `selection.min_gain: 0.01`, `candidates.logreg: {C: 1.0, max_iter: 1000, class_weight: balanced}`, `candidates.lgbm: {n_estimators: 400, learning_rate: 0.05, num_leaves: 63, class_weight: balanced}`, `output: models/detector`; с комментариями, что значит каждый ключ
- [X] T005 [P] Создать `configs/soc.yaml` строго по контракту `contracts/cli.md`: `db: var/soc.db`, `runs_dir: var/runs`, `api: {host: 127.0.0.1, port: 8000}`, `grouping.window_ms: 900000`, `severity.bump_at: 100`, `severity.base` (low — `reconnaissance`, `analysis`; medium — `fuzzers`, `generic`, `dos`; high — `exploits`, `shellcode`, `backdoor`, `worms`), `protected_ips: []`, `playbook.rules` — шесть правил R11 в порядке `protected`, `intrusion_single_target`, `intrusion_many_targets`, `noisy_attack`, `recon`, `default`; с комментарием «срабатывает первое подходящее правило»

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: чтение конфигов, синтетические потоки для тестов, схема SQLite с аудитом только
на вставку, каркас CLI — то, на что опираются все истории.

**⚠️ CRITICAL**: работа над историями начинается только после этой фазы

### Тесты фундамента

- [X] T006 [P] Добавить в `tests/conftest.py` фикстуру `synthetic_flows` (и вспомогательную функцию в `tests/fixtures/make_synthetic_flows.py`): детерминированная (сид 0) таблица polars со всеми колонками `SCHEMA.names()` — `benign` и 3–4 класса атак, у атак признаки заметно сдвинуты; атаки идут с 2–3 IP-источников сериями с разрывами больше и меньше 15 минут; `schema_version` в метаданных parquet; фикстура `synthetic_split` раскладывает эти потоки в `tmp_path` как `data/flows/unsw/*.parquet` + `data/splits/unsw_time.{parquet,json}` и `unsw_cross_day.*` в формате фичи 001 (train/val/test по времени), чтобы весь код 002 работал на них без реальных данных
- [X] T007 [P] Модульные тесты конфигов в `tests/unit/test_detect_config.py` и `tests/unit/test_soc_config.py`: корректные YAML читаются; нет ключа или неверный тип → понятная ошибка с именем ключа; уровень серьёзности вне `low|medium|high|critical` → ошибка; действие правила плейбука вне `block_source_ip|isolate_host|observe|manual_review` → ошибка; неизвестное условие в `when` → ошибка; `min_gain < 0` → ошибка
- [X] T008 [P] Модульные тесты схемы хранилища в `tests/unit/test_store_schema.py`: `init_db` на пустом файле создаёт таблицы `runs`, `alerts`, `incidents`, `incident_history`, `actions`, `audit_log` и индексы; повторный `init_db` ничего не ломает; режим WAL включён; `UPDATE` и `DELETE` в `audit_log` падают с ошибкой из триггера; `append_audit` пишет запись с `at` в ISO-8601 UTC и `details` в JSON

### Реализация фундамента

- [X] T009 [P] Реализовать `src/mlsiem/detect/config.py`: dataclass `DetectConfig` (`split`, `transfer_split`, `seed`, `selection.metric`, `selection.min_gain`, `candidates` — словарь имя → параметры, `output`), `load_detect_config(path=Path("configs/detect.yaml"))` с проверкой ключей и типов по образцу `src/mlsiem/data/config.py`
- [X] T010 [P] Реализовать `src/mlsiem/soc/config.py`: dataclass `SocConfig` (`db`, `runs_dir`, `api.host`, `api.port`, `grouping.window_ms`, `severity.base`, `severity.bump_at`, `protected_ips`, `playbook.rules` — список `Rule(id, when, action)`), `load_soc_config(path=Path("configs/soc.yaml"))`; допустимые условия `when`: `protected: bool`, `class_in: list`, `max_targets: int`, `min_severity: low|medium|high|critical`; константа `SEVERITY_LEVELS = ("low", "medium", "high", "critical")`
- [X] T011 Реализовать схему хранилища в `src/mlsiem/soc/store.py`: `connect(db_path)` (создаёт каталог, `PRAGMA journal_mode=WAL`, `foreign_keys=ON`, `row_factory`), `init_db(conn)` — DDL всех таблиц строго по `data-model.md` (у `incidents`: `status` CHECK `new|in_progress|closed`, `resolution` CHECK NULL/`confirmed`/`false_positive`, `severity` CHECK из четырёх уровней, `version` INTEGER NOT NULL DEFAULT 1; у `actions`: `action_type` CHECK из четырёх типов, `state` CHECK `proposed|executed|rejected`, UNIQUE(`incident_id`) — ровно одно действие на инцидент; у `alerts`: UNIQUE(`run_id`, `flow_uid`) — поток не попадает в два инцидента прогона; `audit_log.event` CHECK `action_proposed|action_executed|action_rejected|incident_status_changed|run_loaded`), триггеры `BEFORE UPDATE/DELETE ON audit_log → RAISE(ABORT, …)`, индексы на `incidents(run_id)`, `incidents(severity, first_seen_ms)`, `incidents(status)`, `incidents(attack_class)`, `alerts(incident_id, first_seen_ms)`, `audit_log(incident_id)`; функция `append_audit(conn, actor, event, *, run_id, incident_id, action_id, details)`; исключения `NotFound`, `InvalidTransition`, `Conflict`, `BadRequest` (от них API строит ответы) (зависит от T010)
- [X] T012 Добавить в `src/mlsiem/cli.py` группы `detect` (`train`) и `soc` (`run`, `serve`, `status`) с опциями из `contracts/cli.md` — пока заглушки, которые печатают «ещё не реализовано» и возвращают `1`; общий обработчик ошибок конфигов → код `1` и сообщение на русском

**Checkpoint**: `uv run pytest` — тесты T007–T008 зелёные; `uv run mlsiem detect --help` и `uv run mlsiem soc --help` показывают команды

---

## Phase 3: User Story 1 — Детектор, выбранный экспериментом (Priority: P1) 🎯 MVP

**Goal**: `mlsiem detect train` сравнивает `logreg` (бейзлайн) и `lgbm` на `unsw_time` по macro
PR-AUC, выбирает победителя по val, пишет всё в MLflow и отчёт, сохраняет версионированный
детектор с предобработкой, порогом и версией схемы, оценивает перенос на `unsw_cross_day`.

**Independent Test**: `uv run mlsiem detect train` на готовых данных 001 → `models/detector/model.joblib`,
`model_card.json`, `experiment.json`, `reports/detector_experiment.md` с PR-AUC по классам и macro
на val и test у обоих кандидатов и `prior`; повторный запуск — те же метрики и тот же `detector_version`.

### Тесты для User Story 1

- [X] T013 [P] [US1] Модульные тесты метрик в `tests/unit/test_detect_metrics.py`: PR-AUC по классам one-vs-rest совпадает с `average_precision_score`; класс без примеров в части → значение `None` и попадает в `classes_without_examples`, macro считается только по классам с примерами; `attack_score = 1 − P(benign)`; порог — максимум F1 бинарной задачи «атака/не атака» на val, при равенстве F1 выбирается больший порог; много одинаковых скоров → порог и вердикты детерминированы; `prior`-базовая линия даёт macro PR-AUC ≈ доли классов
- [X] T014 [P] [US1] Модульные тесты кандидатов и выбора в `tests/unit/test_detect_candidates.py`: `build_candidate("logreg"|"lgbm", params, seed)` возвращает `sklearn.Pipeline` (у `logreg` — `log1p` + `StandardScaler` + `LogisticRegression(lbfgs)`, у `lgbm` — только `LGBMClassifier(deterministic=True, force_row_wise=True, num_threads` фиксирован`)`); `select_winner`: `lgbm` лучше `logreg` на val на ≥ `min_gain` → `lgbm`, меньше → `logreg`; выбор не зависит от test-метрик (подмена test-чисел не меняет победителя); неизвестный кандидат → ошибка
- [X] T015 [P] [US1] Модульные тесты датасета в `tests/unit/test_detect_dataset.py` (на `synthetic_split`): `load_part(split, part)` отдаёт X ровно с колонками `SCHEMA.feature_columns()` в порядке схемы (нет `src_ip`, `dst_ip`, портов, времени, `dpi`-полей, `label`), пропуски → 0, y — канонические классы; `data_hashes(split)` возвращает `split_hash` и `input_hashes` из манифестов 001; разбиение отсутствует → понятная ошибка
- [X] T016 [P] [US1] Модульные тесты артефакта в `tests/unit/test_detect_artifact.py`: `save_detector` → `load_detector` возвращает тот же конвейер, порог, классы, список признаков; `check_input(parquet)` отказывает с сообщением «ожидалась схема 1.x, получена 2.y», если мажорная версия `mlsiem.schema_version` другая; отказывает, если во входе нет какого-то из `features` (сообщение называет колонку); отсутствующий или повреждённый `model.joblib`/`model_card.json` → `DetectorLoadError` с понятным текстом; `detector_version` имеет вид `YYYYMMDD-<хеш8>` и зависит только от конфига и `input_hashes`
- [X] T017 [US1] Интеграционный тест эксперимента в `tests/integration/test_detect_experiment.py` (на `synthetic_split`, MLflow в `tmp_path`): `run_experiment` создаёт `model.joblib`, `model_card.json`, `experiment.json`, `detector_experiment.md`; в `experiment.json` оба кандидата с macro и по классам PR-AUC на val и test, `prior_baseline`, `selection_rule`, `winner`, `classes_without_examples`; в `model_card.metrics` есть перенос на `unsw_cross_day`; два запуска с тем же сидом дают идентичные метрики и `detector_version` (SC-002); в MLflow по run на кандидата с параметрами, метриками, хешами данных, сидом, `schema_version`

### Реализация User Story 1

- [X] T018 [P] [US1] Реализовать `src/mlsiem/detect/dataset.py`: `load_part(split_name, part, *, data_dir=Path("data"), columns=None)` — ленивый join `data/splits/<split>.parquet` с `data/flows/unsw/*.parquet` (polars, только нужные колонки), сортировка по `flow_uid`, X = `SCHEMA.feature_columns()` как float32 с `fill_null(0)`, y = `label`; `data_hashes(split_name)` — `split_hash` и `input_hashes` из `data/splits/<split>.json`; проверка, что захваты в статусе `done`, иначе ошибка (код `1` по контракту)
- [X] T019 [P] [US1] Реализовать `src/mlsiem/detect/metrics.py`: `attack_score(proba, classes)`, `per_class_pr_auc(y, proba, classes) -> dict[str, float | None]`, `macro_pr_auc(per_class)`, `choose_threshold(y_true_attack, scores) -> float` (максимум F1, при равенстве — больший порог), `binary_report(y, scores, threshold)` (precision/recall/F1/ROC-AUC как вспомогательные, FR-002), `prior_baseline(y_train, y_eval, classes)`
- [X] T020 [P] [US1] Реализовать `src/mlsiem/detect/candidates.py`: `build_candidate(name, params, seed) -> Pipeline` для `logreg` (`FunctionTransformer(np.log1p)` на неотрицательных признаках + `StandardScaler` + `LogisticRegression(solver="lbfgs", random_state=seed, …)`) и `lgbm` (`LGBMClassifier(objective="multiclass", deterministic=True, force_row_wise=True, num_threads=<фикс.>, random_state=seed, …)`); `select_winner(results, baseline="logreg", min_gain) -> (winner, rule_text)` только по `macro_pr_auc_val`
- [X] T021 [US1] Реализовать `src/mlsiem/detect/artifact.py`: `detector_version(config, input_hashes)`, `save_detector(pipeline, card, out_dir)` (атомарно `model.joblib` + `model_card.json` со всеми полями data-model: `detector_version`, `candidate`, `classes`, `threshold`, `features`, `schema_version`, `data`, `metrics`, `seed`, `libraries`, `git_commit`, `mlflow_run_id`), `load_detector(dir) -> Detector` (`DetectorLoadError` при отсутствии/порче), `Detector.check_input(schema_version, columns)` (FR-007: мажорная версия и полнота `features`), `Detector.predict_proba(df)` — берёт только `features` в порядке карточки (зависит от T019)
- [X] T022 [US1] Реализовать `src/mlsiem/detect/experiment.py`: `run_experiment(cfg, *, data_dir, mlflow_uri)` — загрузка train/val/test `unsw_time` → для каждого кандидата обучение, вероятности на val/test, порог на val, метрики, время обучения, отдельный run MLflow (параметры, метрики по классам и macro, `split_hash`, `input_hashes`, `schema_version`, сид, git-коммит); `prior`-базовая линия; `select_winner`; оценка победителя (без переобучения) на test `unsw_cross_day`; запись `experiment.json`, карточки и `reports/detector_experiment.md` (таблица кандидатов, `prior`, правило выбора и победитель, перенос на другой день, классы без примеров, замечание R4 о переобучении на `unsw_cross_day`) (зависит от T018–T021)
- [X] T023 [US1] Подключить `mlsiem detect train [--config]` в `src/mlsiem/cli.py`: прогресс в stderr, в stdout — таблица кандидатов (macro PR-AUC val/test, порог, F1), `prior`, победитель и причина выбора, строка переноса на `unsw_cross_day`; код `1` при отсутствии разбиений 001
- [X] T024 [US1] Добавить стадию `train_detector` в `dvc.yaml`: `cmd: uv run mlsiem detect train`, deps — `data/flows/unsw`, `data/splits/unsw_time.parquet`, `data/splits/unsw_cross_day.parquet`, `src/mlsiem/detect`; params — `configs/detect.yaml`; outs — `models/detector`, `reports/detector_experiment.md`; комментарий, что MLflow `mlruns/` — вне DVC
- [X] T025 [US1] Добавить в `tests/conftest.py` фикстуру `tiny_detector` (scope `session`): обучает детектор через `run_experiment` на `synthetic_split` в `tmp_path_factory` и возвращает путь к каталогу — её используют тесты US2–US5
- [X] T026 [US1] Медленный тест `tests/integration/test_detect_real.py` (`@pytest.mark.slow`): `run_experiment` на реальных `unsw_time`/`unsw_cross_day`; macro PR-AUC победителя на test выше `prior` и не хуже бейзлайна-кандидата (SC-001); во входе модели нет полей `identity`/`time`/`dpi`
- [X] T027 [US1] Запустить `uv run mlsiem detect train` на реальных данных (`uv run dvc repro train_detector`), проверить повтор с тем же сидом; записать в `docs/JOURNAL.md` метрики кандидатов, `prior`, победителя, порог, перенос на `unsw_cross_day`, время обучения

**Checkpoint**: детектор выбран и сохранён; `uv run pytest` зелёный; эксперимент воспроизводим

---

## Phase 4: User Story 2 — От потоков к инцидентам одной командой (Priority: P2)

**Goal**: `mlsiem soc run --split unsw_time --part test [--limit N]` выносит вердикты, создаёт
алерты и инциденты с серьёзностью и статусом `new`, пишет прогон в `var/soc.db` одной
транзакцией и печатает сводку.

**Independent Test**: `uv run mlsiem soc run --split unsw_time --part test` → у каждого инцидента есть
алерты, серьёзность, статус `new`; инцидентов минимум в 10 раз меньше, чем алертов; каждый алерт
ровно в одном инциденте; повторный прогон — те же инциденты и серьёзности под новым `run_id`.

### Тесты для User Story 2

- [X] T028 [P] [US2] Модульные тесты вердиктов в `tests/unit/test_soc_verdicts.py` (на `tiny_detector`): у каждого потока есть `predicted_class`, `attack_score`, `is_alert`; `is_alert ⇔ attack_score ≥ threshold`; класс алерта — самый вероятный среди атакующих (не `benign`); алерт несёт контекст `flow_uid`, `capture_id`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `first_seen_ms`, `last_seen_ms`; `true_label` при наличии попадает только в вердикты, а в детектор не подаётся; перемешанный вход даёт те же вердикты
- [X] T029 [P] [US2] Модульные тесты группировки и серьёзности в `tests/unit/test_soc_incidents.py`: алерты одного `(src_ip, attack_class)` с разрывами ≤ `window_ms` → один инцидент, разрыв > `window_ms` → новый (граница ровно `window_ms` — тот же инцидент); один источник с двумя классами → два инцидента; каждый алерт ровно в одном инциденте; `targets` — уникальные отсортированные `dst_ip`; `first_seen_ms`/`last_seen_ms`/`n_alerts`/`max_score`/`mean_score` верны; `incident_id` = `inc-<хеш12>` и стабилен при перестановке входа; серьёзность: базовый уровень из `severity.base`, `+1` при `n_alerts ≥ bump_at`, `high` + повышение → `critical`, `critical` не растёт; `severity_reason` содержит базовый уровень и причину повышения; уверенность на серьёзность не влияет
- [X] T030 [P] [US2] Модульные тесты записи прогона в `tests/unit/test_store_runs.py`: `write_run` пишет `runs`, `alerts`, `incidents` одной транзакцией; исключение посреди записи (подменённая вставка) → в БД нет ни строки этого прогона (FR-028); `run_id` имеет вид `YYYYMMDDTHHMMSS-<хеш6>`; два прогона на одном входе различимы и не смешиваются; `run_loaded` в аудите с `actor = system`
- [X] T031 [US2] Интеграционный тест прогона в `tests/integration/test_soc_run_split.py` (на `synthetic_split` + `tiny_detector`, БД и `runs_dir` в `tmp_path`): `run_chain(source="split:unsw_time/test")` создаёт `var/runs/<run_id>/verdicts.parquet` и записи в БД; инцидентов меньше, чем алертов; все инциденты `new`; `--limit N` берёт первые N потоков по времени; повторный прогон → те же наборы `(src_ip, attack_class, first_seen_ms, n_alerts, severity)`; отсутствующий детектор → ошибка до начала обработки, БД не тронута

### Реализация User Story 2

- [X] T032 [P] [US2] Реализовать `src/mlsiem/soc/verdicts.py`: `compute_verdicts(detector, flows) -> pl.DataFrame` (сортировка по `flow_uid`, `predict_proba` только по `features`, `attack_score`, `predicted_class` среди атакующих классов, `is_alert`, вероятности по классам, `true_label` при наличии), `alerts_from_verdicts(verdicts, flows) -> pl.DataFrame` с контекстом по data-model (Alert)
- [X] T033 [P] [US2] Реализовать `src/mlsiem/soc/incidents.py`: `group_alerts(alerts, window_ms, run_id) -> (alerts_with_incident, incidents)` векторно на polars (сортировка по `first_seen_ms`, `flow_uid` внутри ключа → `diff` → признак разрыва → `cum_sum` → номер инцидента; R9), вычисление полей инцидента; `incident_id` = `inc-` + sha1(`run_id`, `src_ip`, класс, `first_seen_ms` первого алерта)[:12]; `severity(attack_class, n_alerts, base, bump_at) -> (level, reason)` (FR-013)
- [X] T034 [US2] Дописать в `src/mlsiem/soc/store.py` `new_run_id(input_hash)`, `write_run(conn, run, alerts, incidents, actions=None)` — одна транзакция `BEGIN IMMEDIATE … COMMIT`, откат при любой ошибке; `status = new`, `version = 1`, `created_at`/`updated_at`; запись `run_loaded` в аудит; `list_runs(conn)` (новые сверху) (зависит от T011)
- [X] T035 [US2] Реализовать `src/mlsiem/soc/run.py`: `load_split_flows(split, part, limit)` (join разбиения с потоками 001, все нужные колонки `identity`/`time`/`feature`, `--limit` — первые N по `bidirectional_first_seen_ms`), `run_chain(source, cfg, *, detector_dir, limit=None) -> RunSummary` — загрузка детектора и `check_input` до любой обработки → вердикты → запись `verdicts.parquet` атомарно в `runs_dir/<run_id>/` → алерты → инциденты → `write_run`; сводка: потоков, алертов, инцидентов по серьёзности, доля верных алертов для размеченного входа (зависит от T032–T034)
- [X] T036 [US2] Подключить `mlsiem soc run --split … --part … [--limit N]` и `mlsiem soc status` в `src/mlsiem/cli.py`: прогресс в stderr по этапам («вердикты…», «группировка…», «запись…»), итог в stdout на русском (FR-029); `status` — прогоны с источником, временем, детектором, числом инцидентов по статусам
- [X] T037 [US2] Медленный тест `tests/integration/test_soc_run_real.py` (`@pytest.mark.slow`): прогон полного test `unsw_time` с реальным детектором — время ≤ 15 мин и пиковая память ≤ 16 ГБ (через `psutil`) (SC-003); инцидентов ≥ в 10 раз меньше алертов, каждый алерт ровно в одном инциденте (SC-004); повторный прогон — те же вердикты и инциденты (SC-002)

**Checkpoint**: одна команда даёт инциденты в `var/soc.db`; US1 и US2 проверяются отдельно

---

## Phase 5: User Story 3 — Реагирование с подтверждением аналитика (Priority: P3)

**Goal**: для каждого инцидента плейбук предлагает ровно одно действие с сработавшим правилом;
подтверждение аналитиком = симулированное выполнение; отклонение с комментарием; всё в
аудит-журнале, который нельзя изменить.

**Independent Test**: для заранее созданного инцидента — предложено действие по правилу; без
подтверждения не выполнено; после подтверждения есть `simulation` и записи
`action_proposed` / `action_executed` в аудите с автором и временем.

### Тесты для User Story 3

- [X] T038 [P] [US3] Модульные тесты плейбуков в `tests/unit/test_soc_playbooks.py`: каждое из шести правил R11 срабатывает на своём инциденте (`exploits` с одной целью → `isolate_host` цели; с несколькими → `block_source_ip`; `dos`/`generic`/`fuzzers` → `block_source_ip`; `reconnaissance` `low` → `observe`, `medium` → `block_source_ip`); источник или единственная цель в `protected_ips` → `manual_review` с `rule_id = protected`; срабатывает первое подходящее правило; ровно одно действие на инцидент; повторное применение к тому же инциденту даёт то же действие; `action_id = act-<incident_id>`; `rule_text` понятен человеку; `target` null у `observe`/`manual_review`
- [X] T039 [P] [US3] Модульные тесты машины состояний действия в `tests/unit/test_store_actions.py`: `confirm_action` переводит `proposed → executed`, заполняет `simulation`, `decided_by`, `decided_at`, увеличивает `version` и пишет `action_executed` в аудит — всё атомарно; `reject_action` без комментария → `BadRequest`; с комментарием → `rejected` + `action_rejected`; подтверждение/отклонение `executed` или `rejected` → `InvalidTransition`; устаревший `expected_version` → `Conflict`, данные не изменены; пустой `analyst` → `BadRequest`; `simulation` — только описание (тип, объект, текст «было бы сделано …»), модуль не импортирует `subprocess`, `socket`, `os.system` (проверка по AST/импортам)

### Реализация User Story 3

- [X] T040 [P] [US3] Реализовать `src/mlsiem/soc/playbooks.py`: `propose_action(incident, rules, protected_ips) -> Action` — проход по упорядоченным правилам, первое совпадение; условия `protected` (источник или единственная цель в списке), `class_in`, `max_targets`, `min_severity`; объект действия: `isolate_host` → единственная цель, `block_source_ip` → `src_ip`; `simulate(action) -> dict` — описание «что было бы сделано» (тип, объект, правило, текст на русском, для `observe` — «наблюдение продолжено», для `manual_review` — «передано на ручной разбор»); никаких команд ОС и сетевых вызовов (FR-019, FR-020)
- [X] T041 [US3] Дописать в `src/mlsiem/soc/store.py` `confirm_action(conn, action_id, analyst, expected_version, comment)` и `reject_action(conn, action_id, analyst, expected_version, comment)`: `UPDATE … WHERE action_id = ? AND version = ? AND state = 'proposed'`, 0 строк → различить `NotFound` / `InvalidTransition` / `Conflict`; симуляция и запись аудита в той же транзакции; `get_action(conn, action_id)` (зависит от T040)
- [X] T042 [US3] Встроить плейбуки в прогон в `src/mlsiem/soc/run.py`: после группировки `propose_action` для каждого инцидента, действия передаются в `write_run`, на каждое — запись `action_proposed` с `actor = system`, правилом и объектом в той же транзакции; в сводку прогона и stdout `soc run` — «действия по типам»
- [X] T043 [US3] Интеграционный тест `tests/integration/test_soc_response.py` (на `tiny_detector`): после прогона у каждого инцидента ровно одно действие `proposed` и запись `action_proposed` в аудите; ни одно действие не `executed` без вызова `confirm_action` (SC-005); подтверждение одного и отклонение другого видны в аудите с автором и временем; повторный прогон даёт те же `(action_type, target, rule_id)` для тех же инцидентов

**Checkpoint**: инциденты получают предложения; решения аналитика и аудит работают на уровне хранилища

---

## Phase 6: User Story 4 — Доступ к инцидентам через API (Priority: P4)

**Goal**: `mlsiem soc serve` поднимает на `127.0.0.1` API из `contracts/api.md`: список с
фильтрами и страницами, карточка с алертами, историей и действием, смена статуса,
подтверждение/отклонение действия, аудит, прогоны, health.

**Independent Test**: `uv run pytest tests/api` — `TestClient` на временной БД проходит все операции
FR-022 и все коды ошибок контракта.

### Тесты для User Story 4

- [X] T044 [P] [US4] Модульные тесты статусов инцидента в `tests/unit/test_store_incidents.py`: допустимы `new → in_progress`, `new → closed`, `in_progress → closed`; `closed` без `resolution` → `BadRequest`; из `closed` любой переход → `InvalidTransition`; каждое изменение пишет строки в `incident_history` (`field`, `old`, `new`, `analyst`, `at`, `comment`) и `incident_status_changed` в аудит; устаревший `expected_version` → `Conflict` без изменений; `version` растёт на 1
- [X] T045 [P] [US4] API-тесты чтения в `tests/api/test_api_read.py` (фикстура в `tests/api/conftest.py`: временная БД с прогоном на `tiny_detector` и `TestClient(create_app(cfg))`): `GET /api/v1/incidents` — фильтры `status`, `severity` (несколько через запятую), `attack_class`, `run_id`, `from_ms`/`to_ms` (пересечение интервалов); порядок: серьёзность по убыванию, `first_seen_ms`, `incident_id`; `limit` по умолчанию 50, максимум 500, `offset`, `total`; `GET /incidents/{id}` — все поля карточки, действие, история; `GET /incidents/{id}/alerts` постранично в порядке `first_seen_ms`, `flow_uid`; `GET /audit` с фильтрами `incident_id`, `actor`, `event`, порядок по `entry_id`; `GET /runs` новые сверху; `GET /health`; несуществующий инцидент/действие → 404 `not_found`
- [X] T046 [P] [US4] API-тесты изменений в `tests/api/test_api_write.py`: любой `POST` без `X-Analyst` или с пустым → 400 `bad_request`; `POST /incidents/{id}/status` `in_progress`, затем `closed` + `false_positive` → 200, история в карточке; `closed` без резолюции → 400; из `closed` в `in_progress` → 409 `invalid_transition`; `POST /actions/{id}/confirm` → 200 с `simulation`, в `/audit` появились записи; повторный confirm → 409 `invalid_transition`; `reject` без комментария → 400; устаревший `expected_version` → 409 `conflict`; все ошибки — JSON `{"error", "message"}` с русским текстом; методов `PUT`/`PATCH`/`DELETE` на `/audit` нет (405)
- [X] T047 [P] [US4] Тест скорости списка в `tests/api/test_api_perf.py`: БД с ~1000 инцидентов и ~100 тыс. алертов (сгенерированных напрямую через `write_run`) — `GET /incidents?severity=critical,high` отвечает быстрее 1 секунды (SC-006)

### Реализация User Story 4

- [X] T048 [US4] Дописать в `src/mlsiem/soc/store.py` `change_status(conn, incident_id, analyst, status, resolution, comment, expected_version)` (FR-014, FR-015, FR-024) и запросы чтения: `list_incidents(conn, filters, limit, offset) -> (total, rows)` с действием в каждой строке, `get_incident(conn, incident_id)` с действием и историей, `list_alerts(conn, incident_id, limit, offset)`, `list_audit(conn, filters, limit, offset)`
- [X] T049 [US4] Реализовать `src/mlsiem/soc/api.py`: `create_app(cfg) -> FastAPI` с префиксом `/api/v1`, pydantic-модели запросов и ответов строго по `contracts/api.md`; зависимость `X-Analyst` для всех `POST`; обработчики исключений `NotFound` → 404, `InvalidTransition` → 409, `Conflict` → 409, `BadRequest` и ошибки валидации FastAPI → 400/422 — все в формате `{"error": …, "message": "по-русски"}`; соединение с БД на запрос; `/health` с `detector_version` из карточки (зависит от T048)
- [X] T050 [US4] Подключить `mlsiem soc serve [--port]` в `src/mlsiem/cli.py`: `uvicorn.run(create_app(cfg), host=cfg.api.host, port=…)`; host принудительно `127.0.0.1` — отказ, если в конфиге другой адрес; сообщение с адресом и ссылкой на `/docs`

**Checkpoint**: API проходит все тесты контракта; аналитик может работать с инцидентами

---

## Phase 7: User Story 5 — Новый неразмеченный PCAP через всю цепочку (Priority: P5)

**Goal**: `mlsiem soc run --pcap FILE` извлекает признаки экстрактором 001 с той же схемой и
проводит их тем же путём до API.

**Independent Test**: прогнать `tests/fixtures/synthetic.pcap` через `soc run --pcap` → прогон с источником
`pcap:synthetic.pcap` есть в API, признаки совпадают с `extract_flows` для того же файла на 100%.

### Тесты для User Story 5

- [X] T051 [P] [US5] Интеграционный тест `tests/integration/test_soc_pcap.py` (на `tiny_detector`): `run_chain(source="pcap:<synthetic.pcap>")` пишет `var/runs/<run_id>/flows.parquet`, чьи колонки `SCHEMA.feature_columns()` побайтно совпадают с `extract_flows` 001 для того же файла (SC-007); `schema_version` совпадает с карточкой детектора; если алертов нет — сводка «инцидентов нет», код `0`, прогон записан в `runs` с нулями; `truncated.pcap` → прогон выполнен, предупреждение экстрактора в `runs.warnings` и в stdout; прогон виден в `GET /api/v1/runs`
- [X] T052 [P] [US5] Медленный тест `tests/integration/test_soc_pcap_real.py` (`@pytest.mark.slow`, имя содержит `soc_pcap`): PCAP CTU-13 №7 из `configs/data.yaml` проходит цепочку одной командой; признаки совпадают с потоками 001 этого захвата (SC-007)

### Реализация User Story 5

- [X] T053 [US5] Добавить в `src/mlsiem/soc/run.py` источник `pcap`: `load_pcap_flows(path, run_dir)` вызывает `extract_flows(pcap, capture_id=<имя файла>, workdir=run_dir)` из `src/mlsiem/data/extract.py`, пишет `flows.parquet` с метаданными схемы через `write_flows_parquet`, предупреждения `ExtractResult` → `runs.warnings`; дальше тот же путь `run_chain`, без `true_label` и без «доли верных алертов»; явное сообщение «атак не найдено, инцидентов нет» (FR-027, US5 сценарии 2–3)
- [X] T054 [US5] Подключить `--pcap FILE` в `mlsiem soc run` в `src/mlsiem/cli.py` (взаимоисключающе с `--split/--part`); несуществующий файл → код `1` и понятное сообщение; предупреждения — в stdout сводки

**Checkpoint**: все пять историй работают независимо и вместе

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: сквозная проверка, документация, журнал

- [X] T055 Сквозной интеграционный тест `tests/integration/test_chain_synthetic.py`: `synthetic_split` → `run_experiment` → `run_chain` split → API (`TestClient`): список, карточка, подтверждение действия, смена статуса, аудит; повторный прогон даёт те же инциденты, серьёзности и предложения (SC-002); это тот тест, который quickstart §1 называет «синтетика → обучение → прогон → API»
- [X] T056 [P] Обновить `README.md`: раздел фичи 002 — команды `detect train`, `soc run` (split и pcap), `soc serve`, `soc status`, где лежат `models/detector`, `var/soc.db`, `mlruns/`, как открыть `mlflow ui` и `/docs`
- [X] T057 [P] Прогнать `uv run ruff check src tests` и `uv run ruff format --check src tests`, исправить замечания
- [X] T058 Пройти `quickstart.md` целиком на реальных данных (разделы 1–5), включая ручную проверку API из §4 и PCAP CTU-13 №7 из §5; зафиксировать время прогона test, число потоков/алертов/инцидентов, распределение по серьёзности и действиям, долю верных алертов, скорость списка
- [X] T059 Записать итоги фичи 002 в `docs/JOURNAL.md`: метрики кандидатов и победителя (если не записаны в T027), перенос на `unsw_cross_day`, результаты сквозного прогона и PCAP, проверка SC-001…SC-008, что отложено (MLP-кандидат, переобучение на `unsw_cross_day`, CTU-13 как основная проверка)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: без зависимостей
- **Foundational (Phase 2)**: после Setup — блокирует все истории
- **US1 (Phase 3)**: после Foundational
- **US2 (Phase 4)**: после Foundational и US1 (нужен артефакт детектора и фикстура `tiny_detector` из T025)
- **US3 (Phase 5)**: после US2 (плейбуки встраиваются в `run_chain`, действия пишутся в `write_run`); тесты T038, T039 и модуль `playbooks.py` можно делать параллельно с US2
- **US4 (Phase 6)**: после US2 для чтения инцидентов и после US3 для операций над действиями; тесты статусов (T044) и `change_status` не зависят от US3
- **US5 (Phase 7)**: после US2 (тот же `run_chain`); от US3/US4 зависит только проверка «виден в API» в T051
- **Polish (Phase 8)**: после всех историй

### User Story Dependencies

```text
Setup → Foundational → US1 → US2 → US3 → US4
                              └──→ US5
```

Цепочка по смыслу последовательная: каждое звено потребляет выход предыдущего. Независимость
историй — в проверке: каждая проверяется своим тестом на синтетике (`synthetic_split`, `tiny_detector`)
без реальных данных и без следующих звеньев.

### Within Each User Story

- Тесты пишутся первыми и падают до реализации
- Модули без взаимных зависимостей ([P]) → сборка (`experiment.py`, `run.py`, `api.py`) → CLI
- Медленные тесты и запуск на реальных данных — в конце истории

### Parallel Opportunities

- Setup: T002–T005 параллельно
- Foundational: T006–T008 параллельно, T009 и T010 параллельно
- US1: тесты T013–T016 параллельно; модули T018–T020 параллельно
- US2: тесты T028–T030 параллельно; T032 и T033 параллельно
- US3: T038, T039, T040 параллельно (и параллельно с US2)
- US4: тесты T044–T047 параллельно
- US5: T051 и T052 параллельно
- Polish: T056 и T057 параллельно

---

## Parallel Example: User Story 1

```bash
# Тесты US1 одновременно:
Task: "Модульные тесты метрик в tests/unit/test_detect_metrics.py"
Task: "Модульные тесты кандидатов и выбора в tests/unit/test_detect_candidates.py"
Task: "Модульные тесты датасета в tests/unit/test_detect_dataset.py"
Task: "Модульные тесты артефакта в tests/unit/test_detect_artifact.py"

# Независимые модули US1 одновременно:
Task: "Реализовать src/mlsiem/detect/dataset.py"
Task: "Реализовать src/mlsiem/detect/metrics.py"
Task: "Реализовать src/mlsiem/detect/candidates.py"
```

## Parallel Example: User Story 2

```bash
Task: "Модульные тесты вердиктов в tests/unit/test_soc_verdicts.py"
Task: "Модульные тесты группировки и серьёзности в tests/unit/test_soc_incidents.py"
Task: "Модульные тесты записи прогона в tests/unit/test_store_runs.py"

Task: "Реализовать src/mlsiem/soc/verdicts.py"
Task: "Реализовать src/mlsiem/soc/incidents.py"
```

---

## Implementation Strategy

### MVP First (User Story 1)

1. Phase 1 Setup → Phase 2 Foundational
2. Phase 3 US1: детектор выбран экспериментом, сохранён, результаты в журнале
3. **STOP and VALIDATE**: `uv run mlsiem detect train` дважды — те же метрики; победитель выше `prior`

Сам по себе детектор — ещё не «показуемый SIEM»; первый показуемый срез — US1 + US2
(инциденты одной командой).

### Incremental Delivery

1. Setup + Foundational → фундамент
2. US1 → детектор (MVP по ML)
3. US2 → инциденты одной командой (первый показуемый SIEM)
4. US3 → предложения действий и решения аналитика (SOAR)
5. US4 → API для будущей SOC-консоли
6. US5 → живой PCAP тем же путём
7. Polish → сквозной тест, quickstart, журнал

---

## Notes

- [P] — разные файлы, нет зависимостей от незавершённых задач
- `src/mlsiem/soc/store.py` и `src/mlsiem/cli.py` правятся в нескольких историях — задачи над
  ними не параллелятся между собой
- Коммитит владелец; после каждой логической группы задач — готовое название коммита
- На каждой контрольной точке история проверяется отдельно
