---
description: "Task list for feature 006 lab stand and live sensor"
---

# Tasks: Лабораторный стенд и живой сенсор

**Input**: Design documents from `specs/006-lab-stand-live-sensor/`

**Prerequisites**: plan.md, spec.md, research.md (R1–R18), data-model.md, contracts/cli.md, quickstart.md

**Tests**: включены — конституция VI (фича не готова, пока тесты не проходят). Быстрые тесты не
требуют ВМ и прав администратора (захват = записанный pcap, брокер = MemoryBroker 005). Живые
проверки — маркер `lab`, запускаются только на поднятом стенде.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: можно делать параллельно (разные файлы, нет зависимостей)
- **[Story]**: к какой истории относится задача (US1–US5)
- У каждой задачи — точный путь к файлу

## Path Conventions

Единый пакет `mlsiem`: `src/mlsiem/`, тесты `tests/`, скрипты стенда `stand/hyperv/`, конфиг
`configs/stream.yaml`. Числа стенда — только в конфиге (стиль 005).

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: заготовки пакета и конфига под 006.

- [X] T001 Создать подпакет `src/mlsiem/lab/__init__.py` (сценарии, норма, набор, оценка) и пустой `src/mlsiem/stream/sensor.py` с docstring по research R7/R8.
- [X] T002 Добавить в `configs/stream.yaml` разделы `lab` (подсеть 10.88.0.0/24, victim/attacker/sensor, clock_skew_max_s, lab_mac.*) и `scenarios` (пустой список-заготовка) — по data-model; все значения с комментариями, как в 005.
- [X] T003 [P] Добавить маркер `lab` в `pyproject.toml` (`[tool.pytest.ini_options] markers`) рядом с `slow`/`stand`/`nn`.
- [X] T004 [P] Завести в `stand/hyperv/README.md` раздел-заготовку «Машины стенда и сенсор (006)» со ссылкой на quickstart.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: схема хранилища, конфиг-модели, фикстуры — без них ни одна история не собирается.

**⚠️ CRITICAL**: до завершения фазы истории не начинать.

### Тесты фундамента

- [X] T005 [P] Тест миграции схемы 5 → 6 в `tests/unit/test_store_migration_v6.py` (новые колонки `stream_stats`, `runs.lossy`, `user_version=6`); зафиксировать слепок схемы 5 в `tests/fixtures/soc_schema_v5.sql`.
- [X] T006 [P] Тест разбора конфига `lab`/`scenarios` в `tests/unit/test_lab_config.py` (обязательные поля из data-model, дефолты sensor.buffer_flows=3000, pcap_limit_gb=5, clock_skew_max_s=1).

### Реализация фундамента

- [X] T007 Миграция SQLite 5 → 6 в `src/mlsiem/soc/store.py` (одна транзакция: `ALTER TABLE stream_stats ADD COLUMN packets_per_s REAL/flows_per_s REAL/drops INTEGER/buffer_fill REAL/liveness INTEGER`; `ALTER TABLE runs ADD COLUMN lossy INTEGER DEFAULT 0`; `user_version=6`).
- [X] T008 [P] Модели конфига `lab` и `scenarios` в `src/mlsiem/stream/config.py` (dataclass-разделы, проверка подсети и обязательных полей по data-model).
- [X] T009 [P] Фикстуры `tests/fixtures/small_configs.py`: `lab_scenarios` (минимальный набор сценариев) и ссылка на `lab_pcap` (маленький записанный pcap трафика стенда для подмены захвата).
- [X] T010 [P] Записать крошечный `tests/fixtures/lab_sample.pcap` (норма + одна узнаваемая атака с адресами 10.88.0.x) и хелпер его чтения.

**Checkpoint**: `uv run pytest` зелёный (001–005, 007 + фундамент 006); рабочая база мигрирует 5 → 6 без потери данных (копия `bak-005` вручную перед первым запуском).

---

## Phase 3: User Story 1 — Машины жертвы и атакующего поднимаются по инструкции (Priority: P1) 🎯 MVP

**Goal**: по воспроизводимой инструкции со скриптами поднять жертву и атакующего в `mlsiem-lab`, проверить связность и изоляцию, пересоздать с тем же результатом.

**Independent Test**: выполнить инструкцию → обе машины подняты; `mlsiem stand check` перечисляет их, службы жертвы отвечают с атакующего, изоляция подтверждена, часы сходятся ≤ 1 с; удалить и повторить → тот же результат.

### Тесты для User Story 1

- [X] T011 [P] [US1] Тест сборки seed-ISO по ролям в `tests/unit/test_seed_iso_roles.py` (victim → службы R4 + тестовая SSH-учётка; attacker → инструменты R5 + раннер; MAC и адрес из конфига).
- [X] T012 [P] [US1] Тест формирования отчёта `stand check` для машин стенда в `tests/unit/test_stand_check_lab.py` (разбор состояния: адреса, службы, изоляция, расхождение часов — на подставных данных, без ВМ).

### Реализация User Story 1

- [X] T013 [US1] Расширить `src/mlsiem/data/` или `stand/broker/` шаблоны автоустановки ролями victim/attacker (cloud-init: пакеты, статический адрес по MAC, службы/инструменты, тестовая учётка) — по research R3/R4/R5.
- [X] T014 [US1] Команда `mlsiem stand seed-iso --role broker|victim|attacker` в `src/mlsiem/cli.py` (сборка ISO по роли из шаблонов, контракт cli.md).
- [X] T015 [US1] Расширить `mlsiem stand check` в `src/mlsiem/cli.py`: наличие и адреса машин стенда, доступность служб жертвы с атакующего, изоляция (хост/брокер/служебная/интернет недоступны из стенда), расхождение часов ≤ `clock_skew_max_s`, канал управления атакующим (R6), а также свободную память хоста при всех поднятых машинах (предупреждение, если запас < 4 ГБ — SC-009).
- [X] T016 [P] [US1] Скрипт `stand/hyperv/40-vm-victim.ps1` (ВМ жертвы Gen2 Secure Boot, адаптер в `mlsiem-lab`, установочный Default Switch; идемпотентно, подтверждения, `-WhatIf`, UTF-8 BOM).
- [X] T017 [P] [US1] Скрипт `stand/hyperv/50-vm-attacker.ps1` (ВМ атакующего, аналогично T016).
- [X] T018 [US1] Скрипт `stand/hyperv/45-post-install.ps1 -Role victim|attacker` (отключить установочный адаптер, вызвать `mlsiem stand check`).
- [X] T019 [US1] Скрипт `stand/hyperv/91-remove-lab.ps1` (удалить ВМ стенда и сенсорный адаптер; брокер и сети 005 не трогать).
- [X] T020 [US1] Раздел инструкции в `stand/hyperv/README.md`: порядок шагов, ресурсы каждого шага (FR-002), таблица «что создаётся и сколько займёт».

**Checkpoint**: жертва и атакующий подняты, `stand check` зелёный, изоляция и часы в норме; пересоздание даёт тот же адрес.

---

## Phase 4: User Story 2 — Живой сенсор: трафик стенда превращается в потоки в брокере (Priority: P2)

**Goal**: сенсор слушает `mlsiem-lab` (зеркало портов), извлекает потоки тем же экстрактором 001 и шлёт их в брокер как источник `sensor:live`.

**Independent Test**: включить сенсор, сгенерировать трафик → в брокере сообщения `sensor:live` с адресами стенда и схемой 001; остановка и повторный запуск продолжают сеанс.

### Тесты для User Story 2

- [X] T021 [P] [US2] Тест train = serve в `tests/integration/test_sensor_train_serve.py`: прогнать `lab_sample.pcap` через сенсор (на записи) и через экстрактор 001 офлайн, сверить признаки по ключу потока (допуск на округление) — FR-007, SC-003.
- [X] T022 [P] [US2] Тест буфера и учёта потерь в `tests/unit/test_sensor_buffer.py`: ронять MemoryBroker ≤ 5 мин модельного времени → 0 потерь; переполнение буфера → потери считаются и флаг `lossy` (R10, SC-006).
- [X] T023 [P] [US2] Тест исключения служебной сети из захвата в `tests/unit/test_sensor_scope.py` (кадры не из зеркала `mlsiem-lab` в потоки не попадают — FR-006).

### Реализация User Story 2

- [X] T024 [US2] Живой захват в `src/mlsiem/stream/sensor.py`: `NFStreamer(source=<iface>, **SCHEMA.extractor)`, завершённый поток → `encode_flow` (005) → брокер; источник `sensor:live`; idle/active-таймауты не менять (R8).
- [X] T025 [US2] Буфер отправки и учёт потерь в `src/mlsiem/stream/sensor.py` (ограниченная очередь `sensor.buffer_flows`, досылка после восстановления брокера, счётчики потерь пакетов/потоков, флаг `lossy` сеанса) — R10.
- [X] T026 [US2] Параллельная запись pcap сеанса с ротацией по `sensor.pcap_limit_gb` в `src/mlsiem/stream/sensor.py` (вход для набора и проверки train=serve) — FR-011/R12.
- [X] T027 [P] [US2] Показатели сенсора в `src/mlsiem/stream/stats.py` (packets_per_s, flows_per_s, drops, buffer_fill, liveness) и запись в `stream_stats` рядом с 005 — R17.
- [X] T028 [US2] Команды `mlsiem stream sensor start|stop|status` в `src/mlsiem/cli.py` (сеанс `sensor:live`, перезапуск продолжает сеанс по FR-018 005, stop = `completed`).
- [X] T029 [US2] Скрипт `stand/hyperv/60-sensor-adapter.ps1`: добавить брокерной ВМ адаптер в `mlsiem-lab` без IP с `-PortMirroring Destination`, жертве/атакующему — `Source`, +1 ГБ RAM брокеру; флаг `-Standalone` для fallback R7a (отдельная ВМ-сенсор).
- [X] T030 [US2] Скрипт `stand/hyperv/70-sensor.ps1 start|stop|status` — вызывает команды сенсора на машине через PowerShell Direct, возвращает вывод на хост (FR-010/R6).

**Checkpoint**: сенсор шлёт в брокер правильные потоки (на записи в тестах, вживую на стенде); показатели видны в `stream status`; зеркало проверено (quickstart §1).

---

## Phase 5: User Story 3 — Сценарии атак и живая цепочка до консоли (Priority: P3)

**Goal**: запуск именованного сценария с хоста → журнал → через минуты инцидент в консоли с атакующим адресом стенда; контрольный сценарий гарантирует демо.

**Independent Test**: запущены сенсор и потребитель, выполняется контрольный сценарий → в консоли инцидент с атакующей машиной как атакующей стороной ≤ 3 мин после конца сценария; отчёт сценария показывает «обнаружен».

### Тесты для User Story 3

- [X] T031 [P] [US3] Тест реестра и проверки целей в `tests/unit/test_scenarios.py`: сценарий с целью вне `lab`-подсети отклоняется до запуска; параллельный запуск отклоняется (FR-013).
- [X] T032 [P] [US3] Тест журнала сценариев в `tests/unit/test_journal.py` (JSONL: run_uid, name/version, attacker_ip, targets, expected_class, started/ended UTC, outcome/reject_reason) — FR-014.
- [X] T033 [P] [US3] Тест отчёта по запуску в `tests/unit/test_lab_report.py` (число потоков сценария, доля с алертом, классы, сработавшие эксперты вкл. окна 007, инциденты, задержки) — FR-016.
- [X] T034 [US3] Интеграционный тест живой цепочки в `tests/integration/test_lab_chain.py` (маркер `lab`): контрольный сценарий на записи → потребитель → инцидент с атакующей стороной стенда.

### Реализация User Story 3

- [X] T035 [US3] Реестр сценариев в `src/mlsiem/lab/scenarios.py` (чтение из конфига, проверка целей в подсети, запуск инструмента с лимитами скорости/длительности, один сценарий за раз) — R11.
- [X] T036 [US3] Журнал сценариев в `src/mlsiem/lab/journal.py` (запись/чтение JSONL по data-model; норма пишет запись с `expected_class=benign`).
- [X] T037 [US3] Контрольный сценарий в `src/mlsiem/lab/scenarios.py` + артефакт: отбор узнаваемого фрагмента test `unsw_time`, `tcprewrite` подмена адресов на `lab`, `tcpreplay` с атакующего — R9; проверка, что переписанные адреса в `lab`-подсети.
- [X] T038 [US3] Отчёт по запуску сценария в `src/mlsiem/lab/report.py` (FR-016).
- [X] T039 [US3] Команды `mlsiem lab scenario list|run`, `mlsiem lab demo`, `mlsiem lab report` в `src/mlsiem/cli.py` (контракт cli.md; demo = готовность → control_replay → остальные → сводка).
- [X] T040 [US3] Скрипт `stand/hyperv/80-scenario.ps1` — запуск сценария/демо на атакующей машине через PowerShell Direct, забор журнала на хост (`Copy-VMFile`); fallback COM-канал по R6.
- [X] T041 [P] [US3] Проверить, что действия SOAR по инцидентам стенда только симулируются (FR-018): тест в `tests/integration/test_lab_chain.py` подтверждает отсутствие реальных изменений (конституция V).

**Checkpoint**: `lab demo` на поднятом стенде даёт инцидент в консоли по контрольному сценарию; инциденты стенда отличаются только источником сеанса.

---

## Phase 6: User Story 4 — Фоновая норма и собственный размеченный набор (Priority: P4)

**Goal**: генерировать фоновую норму и собрать размеченный набор потоков стенда (benign/класс/ambiguous) со схемой 001 под DVC.

**Independent Test**: включить норму без сценариев → набор только benign, отчёт показывает ложные алерты/инциденты на норме; затем сценарий → его потоки помечены классом.

### Тесты для User Story 4

- [X] T042 [P] [US4] Тест фоновой нормы в `tests/unit/test_lab_normal.py` (состав web/ssh/ftp/dns и интенсивность из конфига, запись интервалов в журнал как benign) — FR-019.
- [X] T043 [P] [US4] Тест разметки набора в `tests/unit/test_lab_dataset.py`: по записи + журналу поток атакующего на цель в окне → класс; пересекающий границу окна → `ambiguous` (исключается из метрик, считается); остальное → benign (FR-020); схема признаков 001.

### Реализация User Story 4

- [X] T044 [US4] Фоновая норма в `src/mlsiem/lab/normal.py` (раннер web/ssh/ftp/dns с правильным паролем тестовой учётки, интенсивность из конфига, start/stop) — R14.
- [X] T045 [US4] Построение набора в `src/mlsiem/lab/dataset.py`: забор pcap сеанса и журнала (Copy-VMFile), прогон экстрактором 001, разметка по журналу, сохранение `data/lab/<версия>/` (flows.parquet + label, manifest.json, report.md) — R12/data-model.
- [X] T046 [US4] Команды `mlsiem lab normal start|stop` и `mlsiem lab dataset build` в `src/mlsiem/cli.py` (контракт cli.md).
- [X] T047 [US4] Стадия DVC набора стенда в `dvc.yaml` (отдельный output `data/lab`); в README/quickstart отметить: `dvc repro` этой стадии только `--single-item` (инцидент 007, чтобы не каскадить на train_detector/train_windows).

**Checkpoint**: набор `data/lab/<версия>/` собран, метки корректны, доля ambiguous ≤ 5% потоков сценариев (SC-007), отчёт содержит потери сенсора и ложные алерты на норме.

---

## Phase 7: User Story 5 — Честная оценка модели на стенде (Priority: P5)

**Goal**: отчёт о переносе модели 2015 года на трафик стенда — PR-AUC, поимка по сценариям, FPR на норме, с разбором непойманного; запись в MLflow и журнал даже при плохом результате.

**Independent Test**: на наборе стенда построить отчёт → PR-AUC «атака/нет» и по классам, поимка по сценариям, FPR на норме, порог с валидации 001; запись в эксперименты.

### Тесты для User Story 5

- [X] T048 [P] [US5] Тест оценки в `tests/unit/test_lab_evaluate.py`: порог берётся из артефакта (не подбирается на стенде), PR-AUC macro и «атака/нет», поимка по сценариям, FPR и ложные инциденты на норме (FR-022).
- [X] T049 [P] [US5] Тест разбора непойманного в `tests/unit/test_lab_evaluate.py`: для слабого сценария причина из трёх — вне таксономии / признаки вне диапазона train 001 / потери сенсора (FR-023/R16).

### Реализация User Story 5

- [X] T050 [US5] Оценка в `src/mlsiem/lab/evaluate.py`: модель и порог из артефакта прогона, метрики FR-022, разбор R16; запись в MLflow (эксперимент `lab`) версии модели/набора/конфига; отчёт `reports/lab_eval_<версия>.{md,json}`.
- [X] T051 [US5] Команда `mlsiem lab evaluate --dataset <версия> --run <run_id>` в `src/mlsiem/cli.py` (контракт cli.md).
- [X] T052 [US5] Запись итога оценки в `docs/JOURNAL.md` (цифры и вывод, даже плохой) — FR-024/конституция VI.

**Checkpoint**: отчёт оценки записан в MLflow и журнал; для каждого непойманного сценария есть разбор.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: наблюдаемость в консоли, документация, регрессия, приёмка.

- [X] T053 [P] Показатели сенсора на панели консоли в `src/mlsiem/ui/` (пакеты/с, потери, буфер, живость, признак «с потерями») рядом с показателями 005; для источников 005 отображение не меняется (FR-025).
- [X] T054 [P] UI-тест панели сенсора в `tests/ui/test_sensor_panel.py` (видны показатели сенсора для `sensor:live`, прочие источники без изменений).
- [X] T055 [P] Обновить `README.md` (раздел про стенд 006, команды `lab`, сенсор) и финализировать `stand/hyperv/README.md`.
- [X] T056 Прогнать весь `uv run pytest -q` — 001–007 зелёные без изменения ожиданий, кроме `test_store_migration_*` и мест, прямо завязанных на источники/схему (FR-027).
- [X] T057 Приёмка на поднятом стенде по quickstart §§1–7 (маркер `lab`): зеркало, изоляция (SC-002), запас памяти ≥ 4 ГБ (SC-009), train=serve (SC-003), контрольный инцидент 10/10 ≤ 3 мин (SC-004), задержка сенсора (SC-005, см. T057a), набор (SC-007), оценка (SC-008); цифры — в `var/acceptance/acceptance-006.json`.
- [X] T057a Замер задержки живого сенсора на поднятом стенде (маркер `lab`): для 95% потоков задержка от завершения потока до появления в брокере — не больше 5 с сверх idle-таймаута экстрактора (SC-005); цифры — в `var/acceptance/acceptance-006.json`.
- [X] T058 Записать итоги захода в `docs/JOURNAL.md` (что сделано, решения, цифры приёмки).
- [ ] T059 DVC push набора `data/lab` — **только с разрешения владельца** (как T063 в 007).

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: без зависимостей.
- **Foundational (Phase 2)**: после Setup; БЛОКИРУЕТ все истории (схема 6, конфиг-модели, фикстуры).
- **User Stories (Phase 3–7)**: после фундамента. US1 — фундамент стенда; US2 зависит от US1 (нужны машины для живого сенсора, но тесты US2 идут на записи без ВМ); US3 зависит от US1+US2; US4 зависит от US2 (запись сеанса) + US3 (журнал); US5 зависит от US4 (набор).
- **Polish (Phase 8)**: после нужных историй.

### User Story Dependencies

- **US1 (P1)**: только фундамент — MVP (машины по инструкции).
- **US2 (P2)**: быстрые тесты независимы (запись + MemoryBroker); живой сенсор требует US1.
- **US3 (P3)**: быстрые тесты независимы; живая цепочка требует US1+US2.
- **US4 (P4)**: требует записи сеанса (US2) и журнала (US3).
- **US5 (P5)**: требует набора (US4).

### Within Each User Story

- Тесты пишутся и падают до реализации.
- Конфиг-модели → сервисы (lab/*) → CLI → скрипты Hyper-V.

### Parallel Opportunities

- Setup: T003, T004 параллельны.
- Foundational: тесты T005, T006 параллельны; реализация T008, T009, T010 параллельны (разные файлы), T007 — отдельно (store.py).
- US1: T011, T012 (тесты) и T016, T017 (скрипты victim/attacker) параллельны.
- US2: тесты T021–T023 параллельны; T027 (stats) параллелен реализации sensor.py.
- US3: тесты T031–T033 параллельны; T041 параллелен.
- US4/US5: тесты каждой истории параллельны.

---

## Parallel Example: User Story 2

```bash
# Тесты US2 (на записи, без ВМ) — параллельно:
Task: "train=serve в tests/integration/test_sensor_train_serve.py"
Task: "буфер и потери в tests/unit/test_sensor_buffer.py"
Task: "исключение служебной сети в tests/unit/test_sensor_scope.py"
```

---

## Implementation Strategy

### MVP First (User Story 1)

1. Phase 1 Setup → 2. Phase 2 Foundational (схема 6, конфиг, фикстуры) → 3. Phase 3 US1 →
4. STOP и проверить: машины поднимаются по инструкции, `stand check` зелёный, изоляция и часы.

### Incremental Delivery

1. Setup + Foundational → фундамент.
2. US1 → машины стенда (MVP, демонстрируемо).
3. US2 → живой сенсор шлёт потоки (главный риск — зеркало — снять первым, quickstart §1).
4. US3 → сценарии + живой инцидент в консоли (сквозной результат фичи).
5. US4 → норма и размеченный набор.
6. US5 → честная оценка переноса.
7. Polish → консоль, регрессия, приёмка.

---

## Notes

- Главные риски и порядок их снятия — в plan.md «Основные риски»: зеркало портов (R7, первым),
  PowerShell Direct к Linux-гостю (R6), слабый перенос модели (находка US5, не сбой).
- Быстрые тесты не требуют ВМ и прав админа; живые — маркер `lab`.
- Перед первым запуском с миграцией 5 → 6 — копия рабочей `var/soc.db` (`bak-005`).
- Heredoc с кириллицей в Bash ломается — патч-скрипты через Write в scratchpad (опыт 005/007).
- Коммитит владелец; Claude не автор (конституция VII).
