---

description: "Задачи фичи 007 — детектор на окнах потоков (нейросеть против бустинга)"
---

# Tasks: Детектор на окнах потоков (нейросеть против бустинга)

**Input**: Design documents from `specs/007-flow-window-detector/`

**Prerequisites**: plan.md, spec.md, research.md (R1–R18), data-model.md, contracts/cli.md,
contracts/api-ui-additions.md, quickstart.md

**Tests**: включены (конституция, принцип VI). Быстрые тесты работают на синтетике 002
(`synthetic_split`, `synthetic_flows`, `tiny_detector`, `tiny_ensemble` из `tests/conftest.py`)
и новой фикстуре `tiny_windows`, на `MemoryBroker` 005, без видеокарты. Тесты, которым нужен
PyTorch, помечаются `@pytest.mark.nn` и пропускаются через `pytest.importorskip("torch")`.
Реальные данные — маркер `slow`, настоящий брокер — `stand`. Тесты пишутся до кода или вместе с
ним и должны падать до реализации.

**Organization**: задачи сгруппированы по историям спеки. В фундаменте — построение окон и
признаков: одна функция для обучения, пакетного прогона и потребителя (FR-003) нужна всем
историям. Схема БД 5 нужна только US3 и живёт там.

**Общие правила для всех задач**:
- Комментарии, сообщения и отчёты — по-русски, подробно, объясняют «почему», а не
  пересказывают код.
- Все числа (длина окна 60 000 мс, `seq_max` 128, сдвиги, `min_class_windows` 20, `min_gain`
  0.01, `max_drop` 0.10, гиперпараметры) берутся из `configs/windows.yaml` или
  `configs/soc.yaml`, в коде их нет (FR-019).
- Логика не дублируется: окна строит только `mlsiem.detect.windows.build_windows`; правило
  направления — `soc/direction.py:sides`; метрики — `detect/metrics.py`; модель прогона —
  `load_model` (004); группировка — `group_alerts` и `plan_batch` без изменения их логики.
- Test участвует только в итоговых цифрах: функции выбора модели и порога test на вход не
  получают.
- Файлы пишутся атомарно (`mlsiem.data.captures.atomic_path`).
- Пакетный `soc run`, консоль, API и потребитель 002–005 без эксперта окон ведут себя как
  раньше (SC-008): только добавления.
- `dvc push`, установка пакетов вне `uv sync` проекта и любые действия на машине владельца вне
  репозитория — только с его явного разрешения в чате.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: можно делать параллельно (разные файлы, нет зависимостей от незавершённых задач)
- **[Story]**: к какой истории относится задача (US1…US4)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: зависимости, конфиги, скелеты модулей, маркер тестов

- [ ] T001 В `pyproject.toml`:
  - добавить extra `nn = ["torch>=2.4,<3"]`;
  - в `[tool.uv.sources]` указать `torch` из индекса `pytorch-cu128`
    (`https://download.pytorch.org/whl/cu128`, `explicit = true`) — колёса CUDA 12.8 для RTX
    3060 Ti, драйвер 610.74;
  - добавить маркер pytest `nn: тесты, которым нужен PyTorch` (в `addopts` не выключать, пропуск
    через `importorskip`);
  - выполнить `uv sync --extra dev --extra nn` и проверить `torch.cuda.is_available()`;
  - `uv run pytest` должен остаться зелёным.
- [ ] T002 [P] Создать `configs/windows.yaml` ровно по contracts/cli.md «Конфиг
  `configs/windows.yaml`» (`split`, `transfer_split`, `seed`, `window`, `current_model`,
  `current_aggregate`, `selection`, `audit`, `candidates.lgbm`, `candidates.gru`, `output`). К
  каждому ключу — комментарий по-русски: что значит и откуда число (R1, R4, R5, R6, R8, R9,
  R10, замер окон в research.md).
- [ ] T003 [P] Дополнить `configs/soc.yaml` разделом `windows: {model: models/windows, mode:
  auto}` с комментарием: `auto` — включать только принятый артефакт (`accepted: true`), `off` —
  как в 005, `force` — только флагом CLI (R12).
- [ ] T004 [P] Создать скелеты модулей с докстрингами назначения по plan.md:
  `src/mlsiem/detect/windows.py`, `windows_nn.py`, `windows_expert.py`,
  `windows_experiment.py`, `windows_audit.py`, `src/mlsiem/stream/windows_online.py`.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: конфиг окон, построение окон, признаки, последовательности, метрика выбора

**⚠️ CRITICAL**: истории не начинаются, пока фаза не завершена.

### Тесты фундамента

- [ ] T005 [P] Тесты конфига в `tests/unit/test_windows_config.py`:
  - `load_windows_config` читает `configs/windows.yaml`;
  - отказ с понятным сообщением при `length_ms ≤ 0`, `seq_max < 1`, сдвиге вне
    `[0, length_ms)`, `min_gain < 0`, неизвестном кандидате;
  - `SocConfig.windows` читает `model`/`mode`, `mode` только `auto|off`.
- [ ] T006 [P] Тесты окон в `tests/unit/test_windows_build.py` на `synthetic_flows`:
  - сетка от эпохи: `window_start_ms = floor(first_seen_ms / L) · L`, «`window_start_ms ≤
    first_seen_ms(потока) < window_end_ms`»;
  - `window_id = "w-" + digest(attacker_ip, window_start_ms, L)[:16]` детерминирован и не
    зависит от порядка строк входа;
  - ключ — `attacker_ip` правила направления (ответный поток попадает в окно клиента);
  - при обучении «все потоки окна принадлежат одной части разбиения» (SC-004);
  - `n_flows` считает все потоки, `truncated = n_flows > seq_max`;
  - `targets` отсортированы по убыванию числа потоков;
  - сдвиги `shift_ms` 15/30/45 с строятся только когда их просят (train) и перекрываются
    правильно.
- [ ] T007 [P] Тесты меток и признаков в `tests/unit/test_windows_features.py`:
  - метка R2: «атака, если есть хотя бы один атакующий поток»; класс — самый частый, при
    равенстве — раньше в таксономии; `n_attack_classes`, `attack_share`;
  - сводные признаки R3 считаются правильно на ручном примере (mean/max/std, `w_n_targets`,
    `w_n_dst_ports`, доли протоколов, интервалы, `w_share_reversed`, `w_share_low_port`);
  - std окна из одного потока — не NaN после предобработки;
  - последовательность R4: форма `[n, 128, 62]`, маска, порядок (`first_seen_ms`, `flow_uid`),
    `new_target`/`new_dst_port`, `t_from_start_s`, `log_gap_s`, 4 скаляра окна.
- [ ] T008 [P] Тест запрещённых входов (FR-004, SC-004) в
  `tests/unit/test_windows_forbidden.py`: ни одно имя в `summary_feature_names()` и
  `seq_feature_names()` не совпадает и не содержит «`*_ip`, `src_port`, `dst_port` как
  значения, `flow_uid`, `capture_id`, `id`, `expiration_id`, `*_first_seen_ms`,
  `*_last_seen_ms`, DPI-поля» (список DPI-полей и идентичностей — из `SCHEMA` групп, не руками).
- [ ] T009 [P] Тесты метрики в `tests/unit/test_detect_metrics.py` (дополнить):
  - `reliable_classes(y_val, classes, min_windows)` возвращает классы с не меньше чем
    `min_windows` примерами (benign включается по тому же правилу);
  - `macro_pr_auc_reliable` усредняет PR-AUC только по ним и совпадает с `macro_pr_auc`, если
    надёжны все.

### Реализация фундамента

- [ ] T010 `WindowsConfig` (dataclass, проверки T005) и `load_windows_config(path)` в
  `src/mlsiem/detect/windows.py`; раздел `windows` в `SocConfig`
  (`src/mlsiem/soc/config.py`) с `model: Path`, `mode: Literal["auto","off"]`.
- [ ] T011 `build_windows(flows, sides, *, length_ms, seq_max, shift_ms=0, part=None)` →
  кадр окон по data-model «Окно» в `src/mlsiem/detect/windows.py`:
  - векторно в polars (R18);
  - `window_id` через `mlsiem.soc.store.input_digest`;
  - `assign_windows(flows, sides, …)` отдельно возвращает соответствие `flow_uid → window_id`
    (его переиспользует потребитель, R13);
  - `window_labels(windows, labels)` по R2.
- [ ] T012 Сводные признаки `summary_features(flows, assignment)` и
  `summary_feature_names()` (R3) в `src/mlsiem/detect/windows.py`. Имена строятся из
  `SCHEMA.feature_columns()` и фиксированного перечня `w_*`.
- [ ] T013 Последовательности `sequences(flows, assignment, seq_max, scaler)` → `(X[n,128,62]
  float32, mask[n,128] bool, scalars[n,4])` и `seq_feature_names()` (R4) в
  `src/mlsiem/detect/windows.py`. Функция `fit_seq_scaler(train_flows)` — `log1p` для
  неотрицательных, стандартизация по train; сохраняется в артефакт (конституция II).
- [ ] T014 `build_part_windows(split, part, cfg, *, data_dir, shifts)` в
  `src/mlsiem/detect/windows.py`:
  - читает часть через `scan_part` (колонки: признаки, контекст, `DIRECTION_COLUMNS`,
    `label`);
  - применяет `sides(…, direction из soc.yaml)` и строит окна, метки, признаки;
  - `train_holdout_split(windows, share, gap_ms)` — хвост train по времени с зазором в одно
    окно (R5).
- [ ] T015 [P] `reliable_classes` и `macro_pr_auc_reliable` в `src/mlsiem/detect/metrics.py`
  (T009).

**Checkpoint**: окна и признаки строятся одной функцией, тесты T005–T009 зелёные.

---

## Phase 3: User Story 1 — Эксперимент «бустинг против нейросети» (Priority: P1) 🎯 MVP

**Goal**: одна команда строит окна, обучает `lgbm` и `gru`, считает текущую модель на окнах,
выбирает по R8 и пишет отчёт, карточку и MLflow.

**Independent Test**: `mlsiem detect windows` на `synthetic_split` →
- `models/windows/window_card.json`, `experiment.json`, `reports/windows_experiment.md`;
- три MLflow-запуска;
- решение по шагам;
- test не влияет на выбор;
- повтор с тем же сидом даёт те же цифры бустинга.

### Тесты для User Story 1

- [ ] T016 [P] [US1] Тесты выбора в `tests/unit/test_windows_select.py`:
  - шаг 1: `gru` побеждает только при `≥ lgbm + min_gain`;
  - шаг 2: принятие только при `≥ current + min_gain`;
  - отрицательный результат — `accepted: false` с понятным `reason`;
  - `--skip-nn` пропускает шаг 1 с пометкой;
  - сигнатуры `select_*` и `choose_threshold` не принимают test (проверка по `inspect`), а
    подмена test-меток не меняет решение и порог (SC-002).
- [ ] T017 [P] [US1] Тесты текущей модели на окнах в `tests/unit/test_windows_current.py`: на
  `tiny_detector` оценка окна по классу — максимум `p_<класс>` по потокам окна, скор —
  максимум `attack_score`, порядок классов как у модели (R7).
- [ ] T018 [P] [US1] Тесты артефакта в `tests/unit/test_windows_artifact.py`:
  - `save_window_expert`/`load_window_expert` для `lgbm`: круговая запись, все поля карточки по
    data-model «Модель окон»;
  - отказы: нет файлов, битый JSON, нет обязательного поля, чужая мажорная версия схемы,
    классы модели ≠ карточке;
  - `accepted: false` без `force` → `WindowExpertNotAccepted`;
  - `kind: gru` без PyTorch → сообщение «установите `uv sync --extra nn`».
- [ ] T019 [P] [US1] Тесты нейросети в `tests/unit/test_windows_nn.py` (`@pytest.mark.nn`):
  - прямой проход на CPU с маской (паддинг не влияет на выход);
  - обучение 2 эпохи на синтетике уменьшает потерю;
  - ранняя остановка по хвосту train;
  - сохранение и загрузка state_dict дают те же вероятности;
  - с тем же сидом на CPU результат воспроизводится.
- [ ] T020 [P] [US1] Интеграционный тест в `tests/integration/test_windows_experiment.py`:
  - `run_windows_experiment` на `synthetic_split` с `--skip-nn` (быстрый) и с `gru`
    (`@pytest.mark.nn`, CPU, 2 эпохи);
  - созданы артефакт, отчёт, `experiment.json`, запуски MLflow во временном каталоге;
  - отчёт содержит всех участников, macro надёжных и всех классов, «атака/нет», per-class с
    пометкой ненадёжных, доли усечённых и смешанных окон, устройство, допуск
    воспроизводимости;
  - повтор с тем же сидом даёт macro бустинга с разницей до 0.001 (SC-003).

### Реализация User Story 1

- [ ] T021 [US1] Кандидат `lgbm` окон в `src/mlsiem/detect/windows_experiment.py`: конвейер
  «медиана-заполнение → LGBMClassifier» с параметрами из конфига, `deterministic=True`,
  `LGBM_THREADS` из `detect/candidates.py`, ранняя остановка по хвосту train (R6).
- [ ] T022 [US1] Нейросеть в `src/mlsiem/detect/windows_nn.py` (import torch — только внутри
  функций):
  - `WindowGRU`: проекция 62→64, biGRU 96, маскированные mean+max, склейка со скалярами, MLP
    196→128→классы, dropout 0.2;
  - `train_gru(X, mask, scalars, y, holdout, cfg, seed, device)`: AdamW, веса классов
    balanced с потолком `class_weight_cap`, AMP на CUDA, ранняя остановка по хвосту train,
    `torch.manual_seed`, `use_deterministic_algorithms(True, warn_only=True)`;
  - `predict_gru(...)` батчами;
  - `resolve_device("auto|cuda|cpu")`.
- [ ] T023 [US1] Текущая модель на окнах `current_on_windows(model, flows, assignment,
  classes)` в `src/mlsiem/detect/windows_experiment.py` (R7, T017): `verdict_frame` потоков
  части и агрегат максимумом по окну.
- [ ] T024 [US1] Выбор `select_nn_vs_boosting(val_metrics, cfg)`, `select_vs_current(...)`,
  порог `choose_threshold` по val в `src/mlsiem/detect/windows_experiment.py` (R8, T016). Test
  считается один раз после решений функцией `final_test_metrics`.
- [ ] T025 [US1] Артефакт в `src/mlsiem/detect/windows_expert.py`:
  - `window_version(config, data)` по образцу `detector_version`;
  - `save_window_expert(...)` и `load_window_expert(path, *, force=False)` по data-model;
  - класс `WindowExpert` с `verdicts(windows) -> DataFrame` (поля data-model «Вердикт окна»:
    `predicted_class` по правилу `final_class`/`top_attack` 002, `attack_score = 1 −
    p_benign`, `is_alert`, `p_<класс>`) и `explain(windows, verdicts)` (для `lgbm` —
    `pred_contrib`, топ-5);
  - общие проверки через `check_schema_and_features`.
- [ ] T026 [US1] `run_windows_experiment(cfg, *, device, skip_nn, output, mlflow_dir, data_dir)`
  в `src/mlsiem/detect/windows_experiment.py`:
  - окна train (сдвиги R9) / хвост / val / test;
  - обучение, текущая модель, выбор, порог, итоговый test;
  - артефакт победителя (всегда, `audit_verdict: not_run`), `experiment.json`;
  - MLflow `windows`: три запуска с конфигом, хешами разбиения (`data_hashes`), сидом,
    устройством, временем;
  - `render_windows_report` → `reports/windows_experiment.md`.
- [ ] T027 [US1] Команда `detect windows` в `src/mlsiem/cli.py` по contracts/cli.md: флаги
  `--config`, `--device`, `--skip-nn`, `--output`, `--no-mlflow`; сводка в stdout; код 1 без
  PyTorch и без `--skip-nn`.
- [ ] T028 [US1] Фикстура `tiny_windows` в `tests/conftest.py`: модель окон `lgbm` на
  `synthetic_split` (быстрый путь `--skip-nn`), карточка с `accepted: false` — для тестов US3
  через `force`, как `force_variant` в 004.
- [ ] T029 [US1] Медленный тест `tests/integration/test_windows_real.py` (`@pytest.mark.slow`):
  - на `unsw_time` число окон по частям близко к замеру research.md (train ≈14.5 тыс., val
    ≈2.3 тыс., test ≈2.6 тыс., допуск 10% — ключ окна другой);
  - ни одно окно не пересекает части;
  - эксперимент `--skip-nn` укладывается в 30 мин.
- [ ] T030 [US1] Реальный эксперимент: `uv run mlsiem detect windows` (видеокарта).
  - Зафиксировать время, пиковую память (RAM/VRAM) и цифры всех участников.
  - Выполнить повтор для SC-003.
  - Записать результат (в том числе отрицательный) в `docs/JOURNAL.md`.

**Checkpoint**: MVP — ответ на вопрос фичи с честным отчётом.

---

## Phase 4: User Story 2 — Проверка на артефакты и перенос (Priority: P2)

**Goal**: вердикт `clean` / `relies_on_artifacts` для победителя, перенос на
`unsw_cross_day`, итоговое `accepted` в карточке.

**Independent Test**: `mlsiem detect windows-audit` для модели `tiny_windows` → отчёт со всеми
разделами R10, карточка обновлена, версия модели не изменилась.

### Тесты для User Story 2

- [ ] T031 [P] [US2] Тесты аудита в `tests/unit/test_windows_audit.py`:
  - подозрительные признаки = поля аудита 001 со статусом не `ok` (фикстура
    `data/audit/*.parquet` во временном каталоге) плюс одиночные признаки с долей ≥
    `single_feature_share`;
  - вердикт `relies_on_artifacts` при падении ≥ `max_drop`, иначе `clean`;
  - итоговое `accepted` = шаг 2 пройден **и** аудит `clean` (FR-012);
  - групповая перестановка канала для `gru` (`@pytest.mark.nn`).
- [ ] T032 [P] [US2] Интеграционный тест в `tests/integration/test_windows_audit_cli.py`: `detect
  windows-audit` на `tiny_windows` → `reports/windows_audit.md` (состав входов, важности,
  одиночные признаки, повтор без подозрительных, перенос, полнота по атакующим адресам,
  вердикт); код 1 без `experiment.json`.

### Реализация User Story 2

- [ ] T033 [US2] `audit_window_model(...)` в `src/mlsiem/detect/windows_audit.py` (R10):
  - переиспользует `single_feature_probe` и `permutation_importance_score` из
    `detect/audit_models.py`;
  - групповая перестановка для `gru`;
  - повтор без подозрительных признаков (переобучение тем же протоколом R5/R6);
  - полнота атакующих окон по каждому `attacker_ip`;
  - то же для текущей модели на окнах (для сравнения).
- [ ] T034 [US2] Перенос `transfer_eval(expert, cfg)` в `src/mlsiem/detect/windows_audit.py`:
  победитель без переобучения на test `unsw_cross_day`, с оговоркой 002 о пересечении частей.
- [ ] T035 [US2] Обновление решения `update_decision(card_path, audit)` в
  `src/mlsiem/detect/windows_expert.py`: `audit_verdict`, `accepted`, `reason`; версия не
  меняется; запись атомарная. Метрики аудита идут в MLflow-запуск победителя.
- [ ] T036 [US2] Отчёт `render_audit_report` → `reports/windows_audit.md` и команда `detect
  windows-audit` в `src/mlsiem/cli.py` (contracts/cli.md).
- [ ] T037 [US2] Реальный аудит: `uv run mlsiem detect windows-audit`. Вердикт, падение
  метрики, перенос и итоговое `accepted` — в `docs/JOURNAL.md` (SC-005).

**Checkpoint**: принятие модели окон подтверждено или снято аудитом.

---

## Phase 5: User Story 3 — Эксперт окон в цепочке (Priority: P3)

**Goal**: пакетный прогон и онлайн-потребитель выдают алерты окон, группируют их в инциденты по
правилам 002/004 и показывают в консоли и API. Онлайн-результат совпадает с пакетным.

**Independent Test**: `soc run --windows force` и `stream consume --windows force` на
синтетике/`MemoryBroker` с `tiny_windows` →
- алерты окон с `window_info`;
- инциденты;
- `stream compare` — «эквивалентно»;
- при `off` и при непринятой модели в `auto` — результат как в 005.

### Тесты для User Story 3

- [ ] T038 [P] [US3] Снимок схемы 4 `tests/fixtures/soc_schema_v4.sql` (до правки store).
  Тесты миграции в `tests/unit/test_store_migration_v5.py`:
  - 4 → 5 и 3 → 5;
  - у старых алертов `alert_kind = 'flow'`;
  - «`alert_kind TEXT NOT NULL DEFAULT 'flow' CHECK (alert_kind IN ('flow','window'))`»;
  - «`window_pending(run_id, flow_uid, window_id, window_start_ms, attacker_ip, payload,
    PRIMARY KEY (run_id, flow_uid))`» с индексом `(run_id, window_start_ms)`;
  - «`window_closed(run_id, window_id, closed_at, n_flows, PRIMARY KEY (run_id,
    window_id))`»;
  - `user_version = 5`; база новее — отказ.
- [ ] T039 [P] [US3] Тесты алертов окон в `tests/unit/test_soc_window_alerts.py`:
  - `alerts_from_window_verdicts` даёт строки по data-model «Алерт окна»: `flow_uid =
    window_id`, `src_ip = attacker_ip`, `dst_ip` — самая частая цель, «`src_port/dst_port/
    protocol = NULL`», `fired_experts = 'windows'`, `experts`, `explanation`, `window_info` с
    `top_flows` ≤ 20 и `top_features` ≤ 5;
  - группировка вместе с алертами потоков: один инцидент на (атакующий, класс), разные
    классы — разные инциденты; алерт окна = 1 в `n_alerts`.
- [ ] T040 [P] [US3] Тесты сборщика окон в `tests/unit/test_stream_windows_online.py`:
  - окно закрывается ровно при `window_start_ms + L ≤ max_first_seen_ms −
    allowed_lateness_ms`;
  - не опоздавший поток никогда не попадает в закрытое окно (property-тест на случайных
    порядках в пределах опоздания);
  - поток закрытого окна → `n_window_late_dropped`;
  - `end` и `stream close` закрывают все окна;
  - остановка без `end` оставляет `window_pending`;
  - повторный поток (уже в `stream_seen`) не добавляется.
- [ ] T041 [P] [US3] Интеграционные тесты в `tests/integration/test_chain_windows.py`:
  - `soc run --windows force` на `synthetic_split` с `tiny_windows` → `windows.parquet`,
    алерты окон в БД, раздел `summary.windows`;
  - `--windows auto` при `accepted: false` → те же инциденты, что без эксперта (SC-008);
  - несовпадение длины окна или режима направления с `soc.yaml` → код 1, ничего не записано.
- [ ] T042 [P] [US3] Интеграционные тесты в `tests/integration/test_stream_windows.py` на
  `MemoryBroker`:
  - проигрывание синтетики + `consume --windows force --once` → `compare` с пакетным
    прогоном «эквивалентно», включая раздел «окна» (SC-006);
  - перемешивание в пределах опоздания — эквивалентно;
  - прерывание потребителя посреди потока (как тесты надёжности 005) и перезапуск — те же
    окна и алерты, дублей 0;
  - перезапуск с другой версией эксперта окон — `ModelMismatch`.
- [ ] T043 [P] [US3] Тесты API и консоли в `tests/api/test_api_windows.py` и
  `tests/ui/test_windows_ui.py`:
  - `*_KEYS_007` (строгие наборы ключей);
  - `kind`, `window` у алерта (`null` у потоков), фильтр `kind`, `n_window_alerts` и
    `has_window_alerts` у инцидентов, `windows` у прогона, поля окон в `stream/status`;
  - карточка: метка «окно», блок с интервалом (UTC), целями, числом портов, таблицей
    подозрительных потоков, «усечено»;
  - значок и фильтр в списке, панель «эксперт окон»;
  - прогон до 007 открывается без ошибок (FR-017).

### Реализация User Story 3

- [ ] T044 [US3] Схема 5 в `src/mlsiem/soc/store.py` (R14, T038): `SCHEMA_VERSION = 5`;
  миграция только добавлениями — `ALTER TABLE alerts ADD COLUMN alert_kind …`, `ADD COLUMN
  window_info TEXT`, `CREATE TABLE window_pending`, `window_closed`, индекс; функции
  `pending_add`, `pending_take(run_id, window_ids)`, `pending_windows(run_id)`,
  `mark_closed`, `closed_windows`. `write_run` и потоковое дописывание пишут `alert_kind` и
  `window_info`.
- [ ] T045 [US3] `alerts_from_window_verdicts(window_verdicts, windows, flow_verdicts,
  expert)` в `src/mlsiem/soc/verdicts.py` (T039): строки для `ALERT_ROW_COLUMNS` + `alert_kind`,
  `window_info`. Добавить `alert_kind`/`window_info` в `ALERT_ROW_COLUMNS`
  (`src/mlsiem/soc/run.py`); алертам потоков — `'flow'`/`NULL`.
- [ ] T046 [US3] Включение эксперта `resolve_window_expert(soc_cfg, mode, path)` в
  `src/mlsiem/detect/windows_expert.py`: `auto`/`off`/`force`; `WindowExpert.check(soc_cfg)` —
  длина окна и `direction` против `soc.yaml`, классы против таблицы серьёзности
  (`check_model_classes`).
- [ ] T047 [US3] Пакетный прогон в `src/mlsiem/soc/run.py` (R12):
  - проверки эксперта окон до обработки;
  - после вердиктов потоков: `build_windows` по всем потокам, `WindowExpert.verdicts`,
    `windows.parquet` в каталоге прогона, алерты окон, объединение с алертами потоков,
    `group_alerts`;
  - `summary.windows` (data-model «Прогон / сеанс»); строка сводки CLI;
  - флаги `--windows`/`--windows-model` у `soc run` в `src/mlsiem/cli.py`.
- [ ] T048 [US3] `WindowAssembler` в `src/mlsiem/stream/windows_online.py` (R13, T040):
  - `add(conn, run_id, flows, assignment)` пишет в `window_pending` payload orjson только
    колонок, нужных `build_windows` и эксперту;
  - `due(watermark, lateness)` возвращает окна, готовые к закрытию;
  - `close(conn, run_id, window_ids, expert)` читает pending, вызывает `build_windows` + эксперта
    той же функцией, что пакетный режим;
  - `close_all` — для `end`/`close`;
  - учёт `n_window_late_dropped`;
  - всё — внутри транзакции потребителя.
- [ ] T049 [US3] Встраивание в потребитель `src/mlsiem/stream/consumer.py`:
  - в `_prepare` — назначение окон новым потокам и выбор закрываемых окон по водяному знаку
    после пачки;
  - алерты окон передаются в `plan_batch` вместе с алертами потоков;
  - в `_write` — pending/closed и части `windows/part-*.parquet` в той же транзакции, что
    позиция;
  - сеанс запоминает режим и версию эксперта окон (`ModelMismatch` при расхождении);
  - `stream close` в `src/mlsiem/cli.py` закрывает окна перед завершением;
  - флаги `--windows`/`--windows-model` у `stream consume`.
- [ ] T050 [US3] Показатели окон в `src/mlsiem/stream/stats.py` и строка `stream consume`/`stream
  status`: открыто, закрыто, алертов окон, опоздавших-вне-окна.
- [ ] T051 [US3] Сравнение в `src/mlsiem/stream/compare.py` (R16): вердикты окон (`windows.parquet`
  против `windows/part-*`), подпись инцидентов с разбивкой `n_alerts` по видам, причина
  `window_late_dropped` в `KNOWN_REASONS`.
- [ ] T052 [US3] API в `src/mlsiem/soc/api.py` по contracts/api-ui-additions.md: поля `kind`,
  `window` у алерта, `?kind=` у `/incidents/{id}/alerts`, `n_window_alerts` и
  `has_window_alerts` у `/incidents`, `windows` у `/runs`, поля окон в `/stream/status`;
  нужные выборки и фильтры — в `src/mlsiem/soc/store.py`.
- [ ] T053 [US3] Консоль в `src/mlsiem/ui/views.py`, `src/mlsiem/ui/routes.py`, шаблонах
  `src/mlsiem/ui/templates/incident.html`, `incidents.html`, `dashboard.html`,
  `fragments/*`:
  - метка и переключатель «все / потоки / окна», раскрывающийся блок алерта окна;
  - раскраска алертов окон в гистограмме;
  - значок и фильтр в списке, панель «эксперт окон» и блок «Окна» у онлайн-сеанса.
  - CSRF и безопасность страниц 003 не трогаются.

**Checkpoint**: эксперт окон работает в обоих режимах, эквивалентность подтверждена тестами.

---

## Phase 6: User Story 4 — Разбор ошибок окон (Priority: P4)

**Goal**: отчёт о том, что ловят окна и чего не ловят, в сравнении с моделью потоков.

**Independent Test**: `mlsiem detect windows-errors` на `tiny_windows` →
`reports/windows_errors.md` со всеми разделами.

- [ ] T054 [P] [US4] Тесты в `tests/unit/test_windows_errors.py`:
  - матрица ошибок по классам;
  - корзины размера окна (1, 2–10, 11–64, 65–128, >128) с PR-AUC «атака/нет» и числом окон;
  - таблица «только окна / только потоки / обе / никто» по классам на ручном примере — окно
    «поймано потоками», если хоть один его поток — алерт текущей модели;
  - до 20 примеров пропусков.
- [ ] T055 [US4] `error_analysis(expert, current, part, cfg)` и `render_errors_report` в
  `src/mlsiem/detect/windows_audit.py`; команда `detect windows-errors` (`--model`, `--part`) в
  `src/mlsiem/cli.py`.
- [ ] T056 [US4] Реальный разбор: `uv run mlsiem detect windows-errors`; выводы и цифры — в
  `docs/JOURNAL.md`.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: DVC, производительность, приёмка по quickstart, документация, журнал

- [ ] T057 [P] DVC-стадия `train_windows` в `dvc.yaml` (R17):
  - `cmd: uv run mlsiem detect windows`;
  - `deps`: `data/flows/unsw`, `data/splits/unsw_time.parquet`, `models/detector`,
    `models/ensemble`, `src/mlsiem/detect/windows*.py`;
  - `params`: `configs/windows.yaml`;
  - `outs`: `models/windows`;
  - `reports/windows_experiment.md` с `cache: false`.
  - `dvc repro train_windows` должен давать ту же версию модели.
- [ ] T058 [P] Медленный тест производительности `tests/integration/test_stream_windows_real.py`
  (`@pytest.mark.slow` + `stand`):
  - test `unsw_time` `--speed max` с `--windows force` обрабатывается ≤ 10 мин (SC-007);
  - хвост потребителя записан;
  - `compare` эквивалентно (SC-006).
  - Если хвост SC-002 005 превышает 30 с — сократить `payload` до колонок эксперта (R18) и
    повторить замер.
- [ ] T059 Приёмка quickstart §5–§7 на брокере 005, в приёмочной базе `var/acceptance/`:
  - пакет и онлайн с окнами, `compare`, прерывание потребителя;
  - реальное время ×60 на 100 000 потоках — задержка алерта окна (SC-006);
  - консоль в превью `soc-console-acceptance` со скриншотом блока алерта окна.
  - Перед первым запуском новой версии на рабочей базе — копия `var\soc.db` →
    `var\soc.db.bak-005`.
- [ ] T060 [P] `uv run ruff check .`, `uv run ruff format --check .`, `uv run pytest`,
  `uv run pytest -m "slow"`, `uv run pytest -m nn`, `uv run pytest -m stand` (если брокер
  поднят) — всё чисто и зелёно. Тесты 002–005 меняются только там, где прямо зависят от версии
  схемы БД или строгих наборов ключей (SC-008), и каждое такое изменение перечисляется в
  журнале.
- [ ] T061 [P] README: раздел «Детектор на окнах (фича 007)»:
  - команды `detect windows|windows-audit|windows-errors`, флаги `--windows`;
  - установка `--extra nn`;
  - где лежат модель и отчёты;
  - как читать решение эксперимента.
- [ ] T062 Итоговая запись в `docs/JOURNAL.md`:
  - победитель и цифры по шагам, аудит, перенос, разбор ошибок;
  - производительность цепочки с окнами;
  - отклонения от плана и находки;
  - вывод для магистерской («дают ли окна и нейросеть прирост на UNSW-NB15»).
- [ ] T063 `dvc push` моделей `models/windows` — **только после явного разрешения владельца** в
  чате.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: без зависимостей. T001 нужен только задачам с `nn`: быстрые тесты
  фундамента от него не зависят.
- **Foundational (Phase 2)**: после Setup; блокирует все истории. T010 → T011 → T012, T013 → T014;
  T015 независим.
- **US1 (Phase 3)**: после фундамента.
  - T021, T022, T023 — параллельно после T014.
  - T024 → T025 → T026 → T027.
  - T028 после T026.
  - T030 после T027 (реальный запуск на видеокарте).
- **US2 (Phase 4)**: после US1 (нужен артефакт и `experiment.json`). T033 → T034 → T035 → T036
  → T037.
- **US3 (Phase 5)**: после фундамента и T025, T028 (артефакт, `tiny_windows`); от результата
  T030/T037 **не зависит** (режим `force`).
  - T038 до T044 (снимок схемы 4 до правки store).
  - T044 → T045 → T046 → T047.
  - T048 → T049 → T050, T051.
  - T052, T053 после T044/T047.
- **US4 (Phase 6)**: после US1 (T026); реальный запуск T056 — после T030.
- **Polish (Phase 7)**: T057 после T027; T058, T059 после US3 и нужен брокер 005; T062 — в конце;
  T063 — только по разрешению.

### User Story Dependencies

- **US1 (P1)**: только фундамент — MVP.
- **US2 (P2)**: US1.
- **US3 (P3)**: фундамент + артефакт US1 (T025, T028). Реальное включение в рабочую цепочку
  зависит от итогового `accepted` (US2); интеграция и тесты — нет.
- **US4 (P4)**: US1.

### Within Each User Story

- Тесты первыми, падают до реализации.
- Чистые функции (окна, признаки, выбор) → артефакт → эксперимент/цепочка → CLI → API/консоль.

### Parallel Opportunities

- Setup: T002, T003, T004.
- Фундамент: тесты T005–T009 параллельно; T015 параллельно с T010–T014.
- US1: тесты T016–T020 параллельно; T021, T022, T023 параллельно.
- US2: T031, T032.
- US3: тесты T038–T043 параллельно; T048 параллельно с T045–T047 (разные файлы); T052, T053
  параллельно.
- US4: T054 параллельно с US2/US3.
- Polish: T057, T058, T060, T061.

---

## Parallel Example: User Story 1

```bash
Task: "T016 Тесты выбора в tests/unit/test_windows_select.py"
Task: "T017 Тесты текущей модели на окнах в tests/unit/test_windows_current.py"
Task: "T018 Тесты артефакта в tests/unit/test_windows_artifact.py"
Task: "T019 Тесты нейросети в tests/unit/test_windows_nn.py"
# затем параллельно: T021 (lgbm), T022 (GRU), T023 (текущая модель)
# и последовательно: T024 → T025 → T026 → T027
```

## Parallel Example: User Story 3

```bash
Task: "T039 Тесты алертов окон в tests/unit/test_soc_window_alerts.py"
Task: "T040 Тесты сборщика окон в tests/unit/test_stream_windows_online.py"
Task: "T043 Тесты API и консоли в tests/api/test_api_windows.py и tests/ui/test_windows_ui.py"
# затем: T044 → (T045 → T046 → T047) ∥ T048 → T049 → T050/T051; T052 ∥ T053
```

---

## Implementation Strategy

### MVP First

1. Setup → фундамент (окна и признаки одной функцией).
2. US1 — эксперимент и отчёт.
3. **STOP and VALIDATE**: реальный запуск T030 — ответ на вопрос фичи.

### Incremental Delivery

1. US1 → честное сравнение «бустинг против нейросети против текущей модели».
2. US2 → аудит подтверждает или снимает принятие.
3. US3 → эксперт окон в цепочке (включается в рабочую цепочку, только если принят; иначе
   интеграция проверена в режиме `force`, цепочка не меняется).
4. US4 → разбор ошибок для магистерской.
5. Polish → DVC, производительность, приёмка, журнал.

Если эксперимент дал отрицательный результат, US3 всё равно делается: интеграция проверяется
тестами и приёмкой в режиме `force` в приёмочной базе, рабочая цепочка остаётся как в 005
(SC-008).

---

## Notes

- [P] — разные файлы и нет зависимостей от незавершённых задач.
- PyTorch с CUDA (~2.5 ГБ) ставится через `uv sync --extra nn` в окружение проекта.
- База мигрирует на схему 5 при первом `soc serve`/`soc run`/`stream consume`. Перед этим —
  копия `var\soc.db.bak-005`.
- После каждой истории — предложить владельцу название коммита; коммитит он сам.
