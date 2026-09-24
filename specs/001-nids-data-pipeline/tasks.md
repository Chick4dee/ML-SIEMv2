---

description: "Задачи фичи 001 — пайплайн данных NIDS"
---

# Tasks: Пайплайн данных NIDS

**Input**: Design documents from `specs/001-nids-data-pipeline/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli.md, quickstart.md

**Tests**: включены. Конституция (принцип VI) и research R12 требуют тестов на каждый модуль:
модульные — на синтетических таблицах, интеграционный — на синтетическом PCAP (scapy),
медленные (`-m slow`) — на реальном сценарии CTU-13 №7. Тесты пишутся до или вместе с кодом
модуля и должны падать до реализации.

**Organization**: задачи сгруппированы по пользовательским историям, чтобы каждую можно было
реализовать и проверить отдельно.

**Общие правила для всех задач**:
- Комментарии и сообщения CLI — на русском, подробно и живым языком.
- Пути к датасетам — только из `configs/data.yaml`, не в коде.
- Бинарники `*.exe` в папках CTU-13 не открывать, не копировать, не запускать (R11):
  файлы выбираются только по явным шаблонам `*.pcap`, `*.pcapng`, `*.binetflow`, CSV разметки.
- Любой результат пишется во временный файл и атомарно переименовывается (FR-011).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: можно делать параллельно (разные файлы, нет зависимостей от незавершённых задач)
- **[Story]**: к какой истории относится задача (US1…US5)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: окружение, пакет, конфиг, DVC

- [X] T001 Создать `pyproject.toml`: Python 3.11, пакет `mlsiem` в `src/`, entry point `mlsiem = "mlsiem.cli:main"`; зависимости `nfstream==6.6.*`, `polars`, `pyarrow`, `scikit-learn`, `matplotlib`, `jinja2`, `pyyaml`, `psutil`, `dvc>=3,<4`; extra `dev`: `pytest`, `ruff`, `scapy`; секции `[tool.ruff]` (line-length 100) и `[tool.pytest.ini_options]` с `testpaths = ["tests"]`, маркером `slow` и `addopts = "-m 'not slow'"`; затем `uv sync --extra dev` для создания `uv.lock`
- [X] T002 [P] Создать скелет пакета по plan.md: `src/mlsiem/__init__.py`, `src/mlsiem/data/__init__.py`, `src/mlsiem/data/sources/__init__.py`, `src/mlsiem/data/report/__init__.py`, `src/mlsiem/data/report/templates/`, `tests/unit/`, `tests/integration/`, `tests/fixtures/`, `tests/conftest.py`
- [X] T003 [P] Дополнить `.gitignore`: `/data/*` кроме `.gitignore`/`*.dvc`, `/reports/*` (отчёты — выход DVC), `/tmp/`, `*.exe`, `*.parquet`, `*.pcap`, `*.pcapng` кроме `tests/fixtures/*.pcap`, `.dvc/cache`, `.dvc/tmp`
- [X] T004 [P] Создать `configs/data.yaml` строго по контракту из `contracts/cli.md` (datasets.unsw.root/gt_csv/pcap_glob, datasets.ctu13.root/timezone `Europe/Prague`, `v1_processed_dir`, split.quantiles `[0.70, 0.85]`, split.gap_ms `600000`, split.ctu13_parts, audit.sample_per_part `500000`, audit.tree_depth `4`, audit.dangerous_lift `0.10`, audit.suspicious_pr_auc `0.90`, seed `42`) и пустой `configs/v1_diff_notes.yaml` с комментарием-примером формата `<capture_id>: "объяснение"`
- [X] T005 Инициализировать DVC: `uv run dvc init`, `uv run dvc remote add -d local A:/dvc-remote-v2`; создать заготовку `dvc.yaml` с комментарием о будущих стадиях (`flows_unsw`, `flows_ctu13`, `split_*`, `audit_*`, `compare_v1`, `report`)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: конфиг, схема признаков, таксономия, захваты/манифесты, экстрактор и каркас CLI —
всё, на что опираются US1 и US4.

**⚠️ CRITICAL**: работа над историями начинается только после этой фазы

### Тесты фундамента

- [X] T006 [P] Сгенерировать синтетический PCAP скриптом `tests/fixtures/make_synthetic_pcap.py` (scapy, фиксированные временные метки): несколько TCP-сессий (с SYN/FIN), UDP (DNS), ICMP echo; записать `tests/fixtures/synthetic.pcap` (< 100 КБ, коммитится), `tests/fixtures/synthetic.pcapng` (тот же трафик в pcapng) и `tests/fixtures/truncated.pcap` (`synthetic.pcap`, обрезанный посередине пакета); в `tests/conftest.py` — фикстуры путей к ним
- [X] T007 [P] Модульные тесты конфига в `tests/unit/test_config.py`: корректный YAML читается; отсутствующий ключ или неверный тип → понятная ошибка с именем ключа; сумма частей `ctu13_parts` покрывает сценарии 1–13 ровно по одному разу
- [X] T008 [P] Модульные тесты схемы в `tests/unit/test_schema.py`: версия `1.0.0`; каждая колонка ровно в одной группе из `key`/`identity`/`time`/`feature`/`dpi`/`label`; в группе `feature` ровно 58 полей; `id` отсутствует; `feature_columns()` не содержит полей групп `identity`/`time`; экспорт в JSON и обратное чтение дают ту же схему
- [X] T009 [P] Модульные тесты таксономии в `tests/unit/test_taxonomy.py`: `" Backdoors "` и `"backdoor"` → `backdoor`; все категории UNSW сводятся к одноимённым классам; CTU-13 `normal`/`background`/`botnet` → `benign`/`background`/`botnet`; незнакомая подпись → исключение, в сообщении есть исходное значение
- [X] T010 [P] Модульные тесты захватов в `tests/unit/test_captures.py`: отпечаток меняется при изменении размера/mtime/первых или последних 16 МБ; манифест пишется и читается; атомарная запись не оставляет итогового файла при исключении посреди записи; `needs_processing` истинно при другом отпечатке, другой `schema_version` или `labeling_version`, другом `label_source_fingerprint` или `labeling_params_hash` (смена `timezone` в конфиге → пересчёт) и ложно для совпадающего `done`
- [X] T011 [P] Интеграционный тест экстрактора в `tests/integration/test_extract_synthetic.py`: на `synthetic.pcap` получаются потоки со всеми колонками схемы (без `label`), строки отсортированы по ключу R3, `flow_uid` = `<capture_id>/<номер>` уникален, `bidirectional_first_seen_ms ≤ bidirectional_last_seen_ms`, `schema_version` в метаданных parquet; два прогона дают одинаковый `content_hash`; pcapng даёт те же потоки, что pcap; функция сортировки на синтетической таблице с двумя строками, равными по 8 полям ключа R3 и различающимися остальными колонками, при перемешанном входе всегда даёт один и тот же порядок; `truncated.pcap` не роняет экстрактор — возвращаются потоки до места обрыва и предупреждение

### Реализация фундамента

- [X] T012 [P] Реализовать `src/mlsiem/data/config.py`: dataclass-конфиг, чтение `configs/data.yaml` (PyYAML), проверка ключей и типов, разрешение относительных путей датасетов от `root`
- [X] T013 [P] Реализовать `src/mlsiem/data/schema.py`: `FeatureSchema` с `version="1.0.0"`, блоком `extractor` (`nfstream==6.6.x`, `statistical_analysis=True`, `splt_analysis=0`, `n_dissections=20`, `idle_timeout=120`, `active_timeout=1800`, `accounting_mode=0`) и упорядоченным списком колонок (имя, polars-тип, группа) ровно по таблице Flow из `data-model.md`; функции `feature_columns()`, `columns_of(group)`, `to_json(path)` (экспорт в `data/flows/schema.json`)
- [X] T014 [P] Реализовать `src/mlsiem/data/taxonomy.py`: канонические классы (`benign`, `background`, `botnet`, `dos`, `exploits`, `fuzzers`, `generic`, `reconnaissance`, `backdoor`, `analysis`, `shellcode`, `worms`, `unlabeled`), таблицы соответствий UNSW и CTU-13 по `data-model.md`, нормализация trim + lower, `LABELING_VERSION = "1.0.0"`, исключение `UnknownLabelError` с исходным значением
- [X] T015 Реализовать `src/mlsiem/data/captures.py`: dataclass `Capture` (поля `capture_id`, `source` ∈ `unsw|ctu13|adhoc`, `day`, `scenario`, `family`, `path`, `fingerprint`, `status` ∈ `pending|done|failed`); поиск захватов UNSW по `pcap_glob` с `capture_id` вида `unsw_22-1-2015_01` и CTU-13 по папкам `1..13` с `capture_id` `ctu13_07` (только `*.pcap`/`*.pcapng`, семейства из research R7); `capture_id` без двоеточий; отпечаток (размер + mtime + SHA-256 первых/последних 16 МБ, флаг полного SHA-256); манифест `data/flows/<source>/<capture_id>.json` со всеми полями из `data-model.md`; атомарная запись (tmp + `os.replace`); `needs_processing()` по правилам переходов статуса
- [X] T016 Реализовать `src/mlsiem/data/extract.py` (зависит от T013): `NFStreamer` с настройками только из `FeatureSchema.extractor` → `to_csv` во временный файл → `polars.scan_csv` с типами из схемы → отбросить `id` → сортировка по (`bidirectional_first_seen_ms`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `bidirectional_last_seen_ms`, `bidirectional_packets`), затем по всем остальным колонкам схемы как финальный тай-брейк → `flow_uid` → запись parquet с метаданными `mlsiem.schema_version`/`mlsiem.capture_id` атомарно; функция `content_hash(df)` по содержимому (не по байтам файла); повреждённый/обрезанный PCAP — обработать читаемое и вернуть предупреждение; временный CSV удалять в `finally`
- [X] T017 Реализовать каркас `src/mlsiem/cli.py`: `argparse`, группа `data` с подкомандами из `contracts/cli.md` (пока заглушки), логирование прогресса в stderr, итог в stdout, коды возврата `0`/`1`/`2`; перехват `MemoryError` и `OSError` с `errno.ENOSPC` (нет места) — прогон прерывается целиком с понятным сообщением на русском и кодом `1`

**Checkpoint**: `uv run pytest` — тесты T007–T011 зелёные; экстрактор работает на синтетике

---

## Phase 3: User Story 1 — Размеченный набор потоков из PCAP одной командой (Priority: P1) 🎯 MVP

**Goal**: `mlsiem data flows --dataset {unsw,ctu13} [--capture ID]` даёт размеченные parquet,
манифесты и сводку, с возобновлением и детерминизмом.

**Independent Test**: `uv run mlsiem data flows --dataset ctu13 --capture 7` → `data/flows/ctu13/ctu13_07.parquet`
+ манифест, 51 поток, доля сопоставления ≈ 0.86, несопоставленные — `unlabeled`;
повторный запуск с `--force` даёт тот же `content_hash` (quickstart шаги 2–3).

### Тесты US1

- [X] T018 [P] [US1] Модульные тесты сопоставления в `tests/unit/test_labeling.py` на синтетических таблицах: совпадение 5-кортежа в прямой и обратной ориентации; ICMP (без портов) — по 3-кортежу; поток, стартующий внутри интервала записи и до 60 с после её конца, сопоставляется, на 61 с — нет; из нескольких кандидатов выбирается ближайший по времени, при равенстве — по началу записи, затем по метке; результат не зависит от порядка строк разметки
- [X] T019 [P] [US1] Модульные тесты источников в `tests/unit/test_sources.py`: мини-GT UNSW в `tests/fixtures/mini_gt.csv` (колонки `Start time, Last time, Attack category, Attack subcategory, Protocol, Source IP, Source Port, Destination IP, Destination Port, Attack Name, Attack Reference`, включая `Backdoors` с пробелами) читается, время — epoch-секунды UTC; мини-binetflow CTU-13 в `tests/fixtures/mini.binetflow` (`StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label`) читается, `StartTime` из `Europe/Prague` переводится в UTC (проверить зимнее и летнее время), подписи `flow=From-Botnet-…`/`flow=…Normal…`/`flow=Background…` → `botnet`/`normal`/`background`
- [X] T020 [P] [US1] Интеграционный тест конвейера в `tests/integration/test_pipeline_synthetic.py`: синтетический PCAP + мини-разметка через подменённый конфиг; UNSW-режим — несопоставленное → `benign`, нет `unlabeled`; CTU-режим — несопоставленное → `unlabeled`, нет `benign` по умолчанию; повторный запуск пропускает захват; `--force` пересчитывает с тем же `content_hash`; исключение на середине второго захвата оставляет первый `done`, второй `failed` без итогового parquet, код возврата `2`
- [X] T021 [P] [US1] Медленный тест в `tests/integration/test_ctu13_real.py` (`@pytest.mark.slow`, пропуск если датасета нет): сценарий 7 — 51 поток, доля сопоставления ≥ 0.85

### Реализация US1

- [X] T022 [US1] Реализовать `src/mlsiem/data/labeling.py`: векторизованное (polars join) сопоставление потоков с записями разметки — ключ 5-кортежа в обеих ориентациях, 3-кортеж для протоколов без портов, расстояние от `bidirectional_first_seen_ms` до интервала записи с допуском 60 000 мс, тай-брейк: ближайший → раньше начало записи → метка лексикографически; колонки `label_raw`, `label_detail`, `label`; параметр «метка по умолчанию» (`benign` для UNSW, `unlabeled` для CTU-13); память — обработка по одному захвату, разметка фильтруется по временному окну захвата
- [X] T023 [P] [US1] Реализовать `src/mlsiem/data/sources/unsw.py`: чтение `NUSW-NB15_GT.csv` (polars, типы явно), нормализация категорий через `taxonomy`, `label_detail` = `Attack Name`; время — epoch-секунды UTC → мс; несопоставленное → `benign`
- [X] T024 [P] [US1] Реализовать `src/mlsiem/data/sources/ctu13.py`: поиск `*.binetflow` в папке сценария (только этот шаблон), чтение, `StartTime` + `Dur` → интервал в UTC из `datasets.ctu13.timezone`, сведение подписи к `botnet`/`normal`/`background`, `label_detail` = исходная подпись; несопоставленное → `unlabeled`
- [X] T025 [US1] Реализовать `src/mlsiem/data/pipeline.py` (зависит от T015, T016, T022–T024): прогон списка захватов по одному — `needs_processing` → extract → разметка → атомарная запись parquet (метаданные `mlsiem.schema_version`, `mlsiem.labeling_version`, `mlsiem.capture_id`) и манифеста (`label_source_fingerprint` — отпечаток GT CSV или `.binetflow`, `labeling_params_hash` — хеш `timezone`, допуска и метки по умолчанию, `n_flows`, `n_matched`, `label_counts`, `content_hash`, `warnings`, `started_at`, `finished_at`, `status`, `error`); ошибка чтения одного захвата → `failed` с причиной, остальные продолжаются; `MemoryError`/`ENOSPC` → текущий захват `failed`, исключение пробрасывается дальше и прогон останавливается (следующие упали бы так же); пик памяти процесса вместе с дочерними процессами nfstream (`psutil`, опрос в фоновом потоке раз в секунду) → поле манифеста `peak_rss_mb`; пропущенный захват манифест не перезаписывает; прогресс «[i/N] capture_id: пропущен/готово/ошибка»; итог `data/flows/<dataset>/summary.csv` (capture_id, status, n_flows, n_matched, match_rate, классы, peak_rss_mb) без отметок времени, строки отсортированы по `capture_id` — чтобы DVC не перезапускал зависимые стадии, когда данные не менялись; экспорт `data/flows/schema.json`
- [X] T026 [US1] Подключить подкоманду `flows` в `src/mlsiem/cli.py`: `--dataset {unsw,ctu13}`, `--capture ID ...` (формы `22-1-2015:1` и `7` → `capture_id`), `--full-hash`, `--force`; сводка в stdout (всего потоков, сопоставлено, распределение классов); коды `0`/`1`/`2`
- [X] T027 [US1] Добавить стадии `flows_unsw` и `flows_ctu13` в `dvc.yaml`: `cmd: uv run mlsiem data flows --dataset …`, deps — код `src/mlsiem/data` и `configs/data.yaml`, outs — `data/flows/<dataset>` (`persist: true`, чтобы работало возобновление)
- [X] T028 [US1] Прогнать quickstart шаги 2–3 на CTU-13 №7 и записать итог (число потоков, доля сопоставления, хеш) в `docs/JOURNAL.md`
- [X] T028a [US1] Проверить память заранее: прогнать `flows --dataset unsw --capture <самый большой PCAP>`, записать `peak_rss_mb` и время в `docs/JOURNAL.md`; если пик > 12 ГБ — вернуться к T016 и сортировать частями (research R2)

**Checkpoint**: US1 работает сама по себе — размеченный набор для любого датасета/захвата

---

## Phase 4: User Story 2 — Разбиение train/val/test без утечек (Priority: P2)

**Goal**: `mlsiem data split --name {unsw_time,unsw_cross_day,ctu13_scenario}` строит
воспроизводимые разбиения с зазором и автоматической проверкой инвариантов.

**Independent Test**: построить три разбиения; проверка инвариантов даёт 0 потоков в двух частях
и 0 пересечений интервалов; повторный запуск даёт тот же `hash`.

### Тесты US2

- [X] T029 [P] [US2] Модульные тесты в `tests/unit/test_split.py` на синтетических таблицах двух «дней»: `unsw_time` — границы по квантилям 0.70/0.85 числа потоков внутри каждого дня, поток, чей `[first_seen, last_seen]` пересекает зону ±600 000 мс вокруг границы, исключается и учитывается в `excluded` по классам; `unsw_cross_day` — день `22-1-2015` целиком → train, `17-2-2015`: первые 15% → val, остальное → test с зазором (пересмотрено после полного прогона, см. research R7); `ctu13_scenario` — сценарий целиком в одной части по `ctu13_parts`; класс, отсутствующий в части, попадает в сводку `missing_classes`; проверка инвариантов ловит специально подброшенный дубль `flow_uid` и пересечение интервалов; два запуска → одинаковый `hash`

### Реализация US2

- [X] T030 [US2] Реализовать `src/mlsiem/data/split.py`: ленивое чтение `data/flows/<dataset>/*.parquet` только колонок `flow_uid`, `capture_id`, времени и `label`; три стратегии из research R7; манифест `data/splits/<name>.json` с полями `split_name`, `dataset`, `parts` (захваты/сценарии и интервалы `[start_ms, end_ms)`), `params` (квантили, `gap_ms` `600000`, сид, распределение сценариев), `excluded`, `input_hashes` (`content_hash` из манифестов захватов), `hash` (хеш таблицы `flow_uid → part`), `missing_classes`; таблица `data/splits/<name>.parquet` (`flow_uid`, `part`); для `ctu13_scenario` — проверка, что в test есть семейство, отсутствующее в train (FR-016a); отказ, если какие-то захваты датасета не `done`
- [X] T031 [US2] Реализовать проверку инвариантов `check_invariants()` в `src/mlsiem/data/split.py`: интервалы частей внутри дня не пересекаются, ни один `flow_uid` не встречается дважды, поток из зоны зазора ни в одной части, сценарий CTU-13 целиком в одной части; нарушение → исключение со списком нарушений, файлы не пишутся
- [X] T032 [US2] Подключить подкоманду `split --name` в `src/mlsiem/cli.py` (нарушение инвариантов → код `1`); в stdout — размер частей, исключено зазором, классы, отсутствующие в части
- [X] T033 [US2] Добавить стадии `split_unsw_time`, `split_unsw_cross_day`, `split_ctu13_scenario` в `dvc.yaml` (deps — `data/flows/<dataset>`, `src/mlsiem/data/split.py`, секция `split` конфига через `params`)

**Checkpoint**: US1 + US2 работают — есть честные разбиения

---

## Phase 5: User Story 3 — Отчёт о качестве данных с проверкой на артефакты (Priority: P3)

**Goal**: `mlsiem data audit` и `mlsiem data report` дают список опасных полей с числами
и самостоятельный HTML/MD-отчёт.

**Independent Test**: для готового набора и разбиения `reports/data_quality.html` открывается
двойным кликом без сети, содержит все разделы из data-model и список `dangerous`/`suspicious`
полей с PR-AUC, базовой линией и порогом.

### Тесты US3

- [X] T034 [P] [US3] Модульные тесты аудита в `tests/unit/test_audit.py`: синтетика, где `src_ip` однозначно определяет класс → `dangerous` (и вариант `subnet24` тоже посчитан); шумовой признак → `ok`; признак модели с одиночным PR-AUC ≥ 0.90 → `suspicious`, а не `dangerous`; базовая линия = средняя доля классов; выборка стратифицирована и воспроизводима при сиде 42
- [X] T035 [P] [US3] Тест отчёта в `tests/integration/test_report.py`: на синтетических манифестах, разбиении и аудите собирается HTML без внешних ссылок (`http` в `src`/`href` отсутствует, картинки — `data:image/png;base64`), в нём есть заголовки всех разделов; Markdown-сводка создаётся; при отсутствии данных сверки с v1 раздел показывает «сверка не выполнялась», а не падает

### Реализация US3

- [X] T036 [US3] Реализовать `src/mlsiem/data/audit.py`: для каждого поля групп `feature`, `identity`, `time`, `dpi` — дерево решений глубины `audit.tree_depth` только на этом поле, обучение на train, macro PR-AUC на val (one-vs-rest, `average_precision_score`); выборка до `audit.sample_per_part` потоков на часть стратифицированно, сид из конфига; категориальные поля — частотное кодирование по train; IP — варианты `raw` и `subnet24`; статусы: `dangerous` — поле групп `identity`/`time`/`dpi` с `lift ≥ 0.10`, `suspicious` — поле группы `feature` с `pr_auc_macro ≥ 0.90`, иначе `ok`; выход `data/audit/<split>.parquet` с колонками `field`, `group`, `variant`, `pr_auc_macro`, `baseline`, `lift`, `status`; читать parquet лениво только нужные колонки
- [X] T037 [US3] Подключить подкоманду `audit --split NAME` в `src/mlsiem/cli.py` (в stdout — поля `dangerous`/`suspicious` с числами) и стадии `audit_unsw_time`, `audit_unsw_cross_day`, `audit_ctu13_scenario` в `dvc.yaml`
- [X] T038 [P] [US3] Создать Jinja2-шаблоны `src/mlsiem/data/report/templates/data_quality.html.j2` (встроенные стили, светлая/тёмная тема, таблицы читаются на узком экране) и `data_quality.md.j2` с разделами по data-model: обзор (объёмы, версии схемы и разметки, хеши) → сопоставление по захватам → классы по частям разбиения и отсутствующие классы → исключённое зазором → аудит артефактов (порог и значения) → сверка с v1 (включая таблицу долей сопоставления CTU-13 v1/v2) → известные ограничения источников (CTU-13: normal ≈ 0, background не равно benign; UNSW: benign = фон генератора)
- [X] T039 [US3] Реализовать `src/mlsiem/data/report/build.py`: сбор данных из `data/flows/*/summary.csv` и манифестов, `data/splits/*.json`, `data/audit/*.parquet`, `data/compare_v1.csv` (если есть); графики matplotlib (доля сопоставления по захватам, классы по частям, lift по полям) в PNG base64; рендер HTML и MD в `reports/`, атомарная запись
- [X] T040 [US3] Подключить подкоманду `report [--output reports/]` в `src/mlsiem/cli.py` и стадию `report` в `dvc.yaml` (deps — summary, splits, audit, `compare_v1.csv`; outs — `reports/data_quality.html`, `reports/data_quality.md`)

**Checkpoint**: US1–US3 — набор, разбиения и показуемый отчёт

---

## Phase 6: User Story 4 — Те же признаки для нового неразмеченного PCAP (Priority: P4)

**Goal**: `mlsiem data extract PCAP --output PATH` даёт parquet той же схемы и версии, без меток.

**Independent Test**: один PCAP в режимах «с разметкой» и «без разметки» даёт на 100% совпадающие
колонки групп `feature`/`identity`/`time`/`dpi`; колонок `label` нет (SC-007).

### Тесты US4

- [X] T041 [P] [US4] Интеграционный тест в `tests/integration/test_train_serve.py`: на синтетическом PCAP результат `extract` и результат `flows` (с мини-разметкой) совпадают по всем колонкам, кроме группы `label` и `capture_id`/`flow_uid`-префикса; в `extract` нет колонок `label_raw`, `label_detail`, `label`; `schema_version` в метаданных одинаковая; вариант `@pytest.mark.slow` (`-k train_serve`) — то же на реальном PCAP сценария CTU-13 №7 против `data/flows/ctu13/ctu13_07.parquet`

### Реализация US4

- [X] T042 [US4] Подключить подкоманду `extract PCAP --output PATH` в `src/mlsiem/cli.py`: `capture_id` = `adhoc_<имя файла без расширения>` (без двоеточий), вызов того же `extract.py` без разметки, атомарная запись, `schema_version` в метаданных; проверка расширения `.pcap`/`.pcapng`
- [X] T043 [US4] Прогнать quickstart шаг 5 на CTU-13 №7 и отметить результат в `docs/JOURNAL.md`

**Checkpoint**: train = serve доказано на файле

---

## Phase 7: User Story 5 — Сверка с v1 (Priority: P5)

**Goal**: `mlsiem data compare-v1` строит сверку по каждому захвату и показывает
необъяснённые расхождения > 5%.

**Independent Test**: таблица сверки по всем захватам; каждая строка с `rel_diff > 0.05`
имеет непустое `explained` из `configs/v1_diff_notes.yaml`, иначе она выводится в stdout.

### Тесты US5

- [X] T044 [P] [US5] Модульные тесты в `tests/unit/test_compare_v1.py`: на синтетических таблицах v1/v2 считаются `n_flows_v1`, `n_flows_v2`, `rel_diff`, доли классов; объяснение подтягивается из YAML по `capture_id`; строка с `rel_diff > 0.05` без объяснения попадает в список «необъяснённых»; захват, которого нет в v1, помечается, а не роняет сверку; `max_class_share_diff_pp` считается в процентных пунктах, и строка с ним > 5 без объяснения тоже «необъяснённая»; для CTU-13 строка с `match_rate_v2 < match_rate_v1` без объяснения — «необъяснённая»

### Реализация US5

- [X] T045 [US5] Изучить формат таблиц v1 в `F:/GitHubRepos/ML-SIEM/data/processed` (только чтение: имена файлов, колонки, как записаны захват и метка) и зафиксировать соответствие идентификаторов v1 ↔ `capture_id` и меток v1 ↔ канонические классы комментарием в начале `src/mlsiem/data/compare_v1.py`; найти, откуда брать долю сопоставления v1 по сценариям CTU-13 (из таблиц v1, если там есть несопоставленные потоки, иначе из журнала v1 → `configs/v1_match_rates.yaml`)
- [X] T046 [US5] Реализовать `src/mlsiem/data/compare_v1.py`: чтение таблиц v1 лениво (только колонки захвата и метки), агрегаты по захватам v2 из манифестов, строки V1Comparison (`capture_id`, `n_flows_v1`, `n_flows_v2`, `rel_diff`, доли классов v1/v2, `max_class_share_diff_pp`, `match_rate_v1`, `match_rate_v2`, `explained`), объяснения из `configs/v1_diff_notes.yaml`; выход `data/compare_v1.csv` атомарно
- [X] T047 [US5] Подключить подкоманду `compare-v1 [--v1-dir PATH]` в `src/mlsiem/cli.py` (по умолчанию `v1_processed_dir` из конфига; в stdout — захваты с необъяснённым расхождением по правилам data-model V1Comparison) и стадию `compare_v1` в `dvc.yaml`; убедиться, что раздел сверки в отчёте (T038/T039) заполняется из `data/compare_v1.csv`

**Checkpoint**: все истории работают независимо

---

## Phase 8: Polish & Cross-Cutting Concerns

- [X] T048 Реализовать подкоманду `all` в `src/mlsiem/cli.py` как вызов `dvc repro` (flows оба датасета → три split → audit → compare-v1 → report) с понятным сообщением, если DVC не инициализирован; проверить `dvc.yaml` целиком (`uv run dvc dag`)
- [X] T049 [P] Прогнать `uv run ruff check src tests` и `uv run ruff format --check src tests`, исправить замечания
- [X] T050 Полный прогон `uv run mlsiem data all` (quickstart шаг 6): проверить `max(peak_rss_mb)` по манифестам < 12 288 (SC-001), проверить 93 захвата `done`, инварианты разбиений, долю сопоставления CTU-13 против v1 (SC-004)
- [X] T051 Проверить возобновление (quickstart шаг 4, SC-002): прервать `flows --dataset unsw` после 2–3 захватов, перезапустить, убедиться, что готовые пропущены и нет полуготовых parquet
- [X] T052 Разобрать необъяснённые расхождения из `data/compare_v1.csv` и `suspicious`-поля аудита; вписать объяснения в `configs/v1_diff_notes.yaml`, перестроить отчёт; убедиться, что по отчёту за 5 минут понятно: сколько данных, какие классы, где дисбаланс, какие признаки опасны (SC-008)
- [X] T053 Версионирование (quickstart шаг 7): `uv run dvc status`, `uv run dvc push` в `A:/dvc-remote-v2`; `git status` не содержит parquet/PCAP/отчётов
- [X] T054 [P] Итоговая запись в `docs/JOURNAL.md`: что сделано в 001, цифры полного прогона (время, пик памяти, объёмы, доли сопоставления), опасные поля, отличия от v1, известные ограничения

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: без зависимостей
- **Foundational (Phase 2)**: после Setup — блокирует все истории
- **US1 (Phase 3)**: после Foundational
- **US2 (Phase 4)**: код и тесты — после Foundational (работают на синтетике); реальный прогон — после US1
- **US3 (Phase 5)**: код и тесты — после Foundational; реальный прогон — после US1 и US2
- **US4 (Phase 6)**: после Foundational (использует `extract.py`); медленный тест — после US1 (нужен `ctu13_07.parquet`)
- **US5 (Phase 7)**: код — после Foundational; реальный прогон — после US1; раздел отчёта — после T039
- **Polish (Phase 8)**: после всех историй

### Within Each User Story

- Тесты пишутся первыми и падают до реализации
- Источники/модели → сервис (pipeline/split/audit) → CLI → стадия DVC → проверка по quickstart
- `src/mlsiem/cli.py` и `dvc.yaml` правятся многими задачами — эти правки выполняются последовательно, не параллельно

### Parallel Opportunities

- Setup: T002, T003, T004 параллельно после T001
- Foundational: все тесты T006–T011 параллельно; T012, T013, T014 параллельно; затем T015 → T016 → T017
- US1: T018–T021 параллельно; T023 и T024 параллельно после T022
- После Foundational US2, US3, US4, US5 можно писать параллельно на синтетике (разные модули: `split.py`, `audit.py` + `report/`, `extract`-подкоманда, `compare_v1.py`)

---

## Parallel Example: User Story 1

```text
# Тесты US1 одновременно:
Task: "T018 Модульные тесты сопоставления в tests/unit/test_labeling.py"
Task: "T019 Модульные тесты источников в tests/unit/test_sources.py"
Task: "T020 Интеграционный тест конвейера в tests/integration/test_pipeline_synthetic.py"
Task: "T021 Медленный тест в tests/integration/test_ctu13_real.py"

# Источники разметки одновременно (после labeling.py):
Task: "T023 sources/unsw.py"
Task: "T024 sources/ctu13.py"
```

## Parallel Example: Foundational

```text
Task: "T012 config.py"
Task: "T013 schema.py"
Task: "T014 taxonomy.py"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1: Setup
2. Phase 2: Foundational
3. Phase 3: US1
4. **STOP and VALIDATE**: quickstart шаги 1–3 на CTU-13 №7
5. Можно запускать полную экстракцию UNSW на ночь, пока пишутся US2/US3

### Incremental Delivery

1. Setup + Foundational → экстрактор на синтетике
2. US1 → размеченные потоки (MVP)
3. US2 → честные разбиения
4. US3 → отчёт и аудит (показуемый результат)
5. US4 → доказательство train = serve
6. US5 → сверка с v1 и объяснения расхождений
7. Polish → полный прогон, DVC push, журнал

---

## Notes

- [P] — разные файлы и нет зависимостей от незавершённых задач
- Коммитит владелец после каждой задачи или логической группы; Claude в авторах не указывается
- Большие файлы (`data/`, `reports/`, PCAP) — только через DVC
- Останавливаться на каждом checkpoint и проверять историю отдельно
