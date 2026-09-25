---

description: "Задачи фичи 005 — потоковая обработка через Kafka"
---

# Tasks: Потоковая обработка через Kafka

**Input**: Design documents from `specs/005-kafka-streaming-chain/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli.md,
contracts/messages.md, contracts/api-ui-additions.md, quickstart.md

**Tests**: включены (конституция, принцип VI). Все быстрые тесты — на брокере-заглушке
`MemoryBroker` и синтетике 002 (`synthetic_split`, `synthetic_flows`, `tiny_detector`,
`tiny_ensemble` из `tests/conftest.py`), без ВМ. Тесты на настоящем брокере — маркер
`@pytest.mark.stand` (выключен по умолчанию, как `slow`); полный test `unsw_time` — `slow`.
Тесты пишутся до или вместе с кодом и должны падать до реализации.

**Organization**: задачи сгруппированы по историям спеки. Транспорт (конфиг, интерфейс брокера,
формат сообщений) и схема БД 4 — в фундаменте: они нужны всем историям.

**Общие правила для всех задач**:
- Комментарии, сообщения, инструкции — по-русски, подробно, «почему», а не пересказ кода.
- Все числа (адреса, топики, пачки, опоздание, тайм-ауты, память ВМ) — из `configs/stream.yaml`
  (`StreamConfig`), не в коде.
- Логика SOC не дублируется: потребитель вызывает `load_model` (004), `compute_verdicts`,
  `alerts_from_verdicts`, `severity`, `propose_action`, правило направления. Новое — только
  транспорт и инкрементальная группировка (`stream/incremental.py`).
- Любой скрипт, меняющий систему владельца, — с подтверждением (`SupportsShouldProcess`,
  `-WhatIf`) и заранее печатает, что сделает и сколько ресурсов займёт (FR-002). Скрипты
  идемпотентны. Ничего не скачивается и не создаётся на машине владельца во время реализации без
  его явного разрешения в чате.
- Пакетный `soc run`, API и консоль 002–004 не меняют поведения (SC-008): только добавления.
- Файлы пишутся атомарно (`mlsiem.data.captures.atomic_path`).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: можно делать параллельно (разные файлы, нет зависимостей от незавершённых задач)
- **[Story]**: к какой истории относится задача (US1…US5)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: зависимости, конфиг, скелеты, маркер тестов

- [ ] T001 Добавить в `pyproject.toml` зависимости `confluent-kafka` и `orjson` (runtime), extra `stand = ["pycdlib"]`, маркер pytest `stand: тесты на настоящем брокере Kafka (машина mlsiem-broker)` и `addopts = "-m 'not slow and not stand'"`; `uv sync --extra dev --extra stand`; убедиться, что `uv run pytest` зелёный (скачивание пакетов — через `uv`, это не действие на машине владельца вне проекта)
- [ ] T002 [P] Создать `configs/stream.yaml` ровно по data-model «Конфигурация» (разделы `broker`, `topics`, `consumer`, `replay`, `stand`) с комментарием по-русски к каждому ключу (что значит, откуда число: R1, R2, R5, R7, R8, R11)
- [ ] T003 [P] Создать скелеты модулей с докстрингами назначения по plan.md: `src/mlsiem/stream/__init__.py`, `config.py`, `broker.py`, `messages.py`, `replay.py`, `consumer.py`, `incremental.py`, `stats.py`, `compare.py`; `src/mlsiem/stand/__init__.py`, `seed.py`, `check.py`; каталоги `stand/hyperv/`, `stand/broker/` с `README.md` (что здесь лежит и порядок запуска)
- [ ] T004 [P] Добавить в `.gitignore` `var/stand/` (seed-ISO, образы) и `*.iso`; убедиться, что `stand/` (скрипты и шаблоны) в git не игнорируется

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: конфиг, интерфейс брокера и заглушка, формат сообщений, схема БД 4, общие функции SOC

**⚠️ CRITICAL**: истории не начинаются, пока фаза не завершена.

### Тесты фундамента

- [ ] T005 [P] Тесты конфига в `tests/unit/test_stream_config.py`: репозиторный `configs/stream.yaml` читается; понятные ошибки с именем ключа — неверный `bootstrap` (нет порта), `partitions < 1`, `batch_max_messages < 1`, `allowed_lateness_ms < 0`, `lease_ttl_s ≤ 5`, адреса хоста и брокера не в одной сети `/prefix`, `memory_mb < 1024`, `kafka_heap_mb ≥ memory_mb`
- [ ] T006 [P] Тесты заглушки в `tests/unit/test_stream_broker.py`: `MemoryBroker` — produce с ключом и заголовками → poll возвращает сообщения по порядку в партиции ключа; `commit(offsets)` и `committed()`; `end_offsets()` для отставания; `seek(topic, partition, offset)` для старта с позиции из SQLite; «сбой» (`crash()`) — непотверждённые сообщения доставляются заново следующему потребителю; `list_topics()`; `ensure_topics()` идемпотентен; одинаковое поведение с интерфейсом `Broker` (проверка, что `KafkaBroker` и `MemoryBroker` реализуют все методы `Broker`)
- [ ] T007 [P] Тесты формата в `tests/unit/test_stream_messages.py` (contracts/messages.md): `encode_flow` → `decode_flows` на `synthetic_flows` даёт кадр, **равный** исходному по значениям и типам всех колонок схемы кроме группы `label` (train = serve), включая `null` и float64 без потери точности; метка идёт только в `true_label`/`label`, не в признаки; `end` кодируется/читается; причины отказа: `bad_json`, `missing_field` (удалено одно поле схемы), `schema_major` (`2.0.0`), `bad_type` (строка в числовом поле), `source_mismatch` (заголовок ≠ тело) — каждая с текстом по-русски; лишнее поле в `fields` игнорируется; минорная версия `1.1.0` принимается
- [ ] T008 [P] Тесты миграции 3 → 4 в `tests/unit/test_store_migration_v4.py`: снимок схемы 3 `tests/fixtures/soc_schema_v3.sql` (T010) с прогоном, алертами, решением, аудитом → после `init_db` `user_version == 4`; у `runs` `mode='batch'`, `status='completed'`; у инцидентов `last_alert_start_ms = MAX(first_seen_ms)` своих алертов, `alerts_after_decision = 0`, `merged_into IS NULL`; у алертов `late = 0`; новые таблицы `stream_offsets`, `stream_seen`, `stream_lease`, `stream_stats`, `stream_divergences` есть; аудит — те же строки с теми же `entry_id`, CHECK принимает `incident_updated`, `incident_merged`, `action_reproposed`, `session_status_changed`, триггеры запрета UPDATE/DELETE работают; цепочка 0 → 2 → 3 → 4 со снимка 002; версия 5 → `SchemaTooNew`; сбой посреди шага → база целиком в схеме 3; обновить ожидания версии в `tests/unit/test_store_migration.py`, `tests/unit/test_store_migration_v3.py`, `tests/unit/test_cli_serve.py` на `store.SCHEMA_VERSION` (версия схемы меняется по спеке)

### Реализация фундамента

- [ ] T009 [P] `StreamConfig` и `load_stream_config`/`parse_stream_config` в `src/mlsiem/stream/config.py` по образцу `DetectConfig` (проверки T005, ошибки через `ConfigError` из `mlsiem.data.config`, `raw` для журнала)
- [ ] T010 [P] Снимок DDL схемы 3 в `tests/fixtures/soc_schema_v3.sql` — копия текущего `DDL` из `src/mlsiem/soc/store.py` с `PRAGMA user_version = 3` и шапкой «копия DDL на коммите <HEAD>, нужна тестам миграции 3 → 4» (сделать ДО правки store.py в T013)
- [ ] T011 Интерфейс и реализации брокера в `src/mlsiem/stream/broker.py` (R4): абстрактный `Broker` (`produce(topic, key, value, headers)`, `flush(timeout) → неотправленных`, `subscribe(topics)`, `poll_batch(max_messages, timeout_ms) → list[Message]`, `seek`, `commit(offsets)`, `committed`, `end_offsets(topic)`, `list_topics()`, `ensure_topics(specs)`, `close()`), датакласс `Message(topic, partition, offset, key, value: bytes, headers: dict[str, str], timestamp_ms)`; `MemoryBroker` по тестам T006; `KafkaBroker` на `confluent_kafka.Producer` (`enable.idempotence=true`, `acks=all`, `linger.ms=5`) и `Consumer` (`enable.auto.commit=false`, `auto.offset.reset=earliest`, `group.id` из конфига), `AdminClient` для топиков (`retention.ms` из `retention_hours`); ошибки подключения → `BrokerUnavailable` с текстом «брокер <адрес> недоступен за N с — машина выключена? Start-VM <vm_name>»
- [ ] T012 Формат сообщений в `src/mlsiem/stream/messages.py` (R5, contracts/messages.md): `FEATURE_FIELDS` = `SCHEMA.columns` без группы `label` (из схемы, не руками); `encode_flow(row, source_id, seq, sent_at_ms, label=None) → (key, value, headers)` на `orjson`; `encode_end`; `decode_flows(messages) → (pl.DataFrame по SCHEMA.dtypes с колонками meta: source_id, seq, sent_at_ms, label; list[Rejected], list[EndMark])` — пачкой, без построчного polars; `Rejected(reason_code, text, message)`; `check_schema_major(version, model_schema)`
- [ ] T013 Схема 4 в `src/mlsiem/soc/store.py` (data-model «Миграция 3 → 4»): `SCHEMA_VERSION = 4`; новые колонки в `DDL`; `AUDIT_EVENTS` + `incident_updated`, `incident_merged`, `action_reproposed`, `session_status_changed`; `MIGRATION_V4` — `ADD COLUMN`, заполнение `last_alert_start_ms`, новые таблицы, пересоздание `audit_log` с сохранением `entry_id` (как `MIGRATION_V2`), индексы `ux_runs_source` (частичный уникальный по `source_id`), `ix_incidents_after_decision`; `migrate()` доводит 0→2→3→4 по шагам; `write_run` пишет `mode='batch'`, `status='completed'`, `last_alert_start_ms` инцидентов; `_run_row`/`list_runs` отдают новые поля
- [ ] T014 Общие функции SOC для обоих режимов: в `src/mlsiem/soc/incidents.py` вынести `incident_fields(alerts_of_incident, severity_base, bump_at) → dict` (first/last_seen, last_alert_start_ms, n_alerts, max/mean_score, targets по `victim_ip`, severity и пояснение) и использовать её в `group_alerts` (пакетный результат не меняется — тесты 002–004 зелёные); в `src/mlsiem/soc/run.py` вынести `alert_rows(alerts) → list[dict]` (колонки для `store.write_run`) — чтобы потребитель писал алерты теми же полями

**Checkpoint**: `uv run pytest` зелёный (002–004 + фундамент), база 004 мигрирует на схему 4 без
потерь, сообщения кодируются и читаются без потери точности.

---

## Phase 3: User Story 1 — Брокер на стенде поднимается по инструкции (Priority: P1) 🎯 MVP

**Goal**: воспроизводимые скрипты Hyper-V + seed-ISO автоустановки Ubuntu с Kafka + команда проверки.

**Independent Test**: `00-check.ps1 -WhatIf` показывает план; seed-ISO собирается и содержит
корректные `user-data`/`meta-data`; `mlsiem stand check` против `MemoryBroker`/недоступного
адреса даёт понятный результат за ≤ `connect_timeout_s`. На машине владельца (T026) — брокер
доступен, топики созданы, брокера нет в `mlsiem-lab`.

### Тесты для User Story 1

- [ ] T015 [P] [US1] Тесты seed-ISO в `tests/unit/test_stand_seed.py`: `build_seed_iso(cfg, pubkey, out)` создаёт ISO с меткой тома `CIDATA` и файлами `user-data`, `meta-data`; `user-data` — валидный YAML с `autoinstall.version: 1`, статическим адресом `broker_ip/prefix` на адаптере служебной сети, пользователем и SSH-ключом из аргумента, пакетами `openjdk-21-jre-headless`, `ufw`, командами установки Kafka с проверкой SHA-512, юнитом `kafka.service`, `KAFKA_HEAP_OPTS` из `kafka_heap_mb`, правилами ufw (9092 только из `mgmt`-сети, 22 только с `host_ip`), созданием топиков из конфига с `retention.ms`; в `server.properties` — `process.roles=broker,controller`, `listeners=PLAINTEXT://<broker_ip>:9092,CONTROLLER://127.0.0.1:9093`, `auto.create.topics.enable=false`; нет ключа → понятная ошибка с командой `ssh-keygen -t ed25519`; повтор — байт в байт тот же ISO (детерминизм)
- [ ] T016 [P] [US1] Тесты проверки в `tests/unit/test_stand_check.py`: `check_broker(cfg, broker_factory)` с `MemoryBroker` — «доступен», топики и их `retention` перечислены, отсутствующий топик → проблема с подсказкой; недоступный брокер → проблема «машина выключена? Start-VM <vm_name>» за ≤ `connect_timeout_s`; `check_isolation(adapters)` — у ВМ адаптер в `lab_switch` → проблема «брокер виден из сети стенда»; разбор вывода `Get-VMNetworkAdapter` (JSON через `ConvertTo-Json`) из фикстуры
- [ ] T017 [P] [US1] Тест скриптов в `tests/unit/test_stand_scripts.py`: каждый `stand/hyperv/*.ps1` (кроме `00-check.ps1`) объявляет `[CmdletBinding(SupportsShouldProcess)]`, вызывает `$PSCmdlet.ShouldProcess` перед каждым `New-VMSwitch`/`New-VM`/`New-NetIPAddress`/`Remove-VM`/`Set-VMNetworkAdapter`/`Invoke-WebRequest`; содержит проверку существования перед созданием (идемпотентность — `Get-VMSwitch`/`Get-VM` … `-ErrorAction SilentlyContinue`); не содержит жёстко заданных адресов/имён — берёт их из `configs/stream.yaml` через `stand/hyperv/Read-StreamConfig.ps1`; синтаксис проверяется `powershell -NoProfile -Command "[scriptblock]::Create((Get-Content …))"` (тест пропускается, если PowerShell недоступен)

### Реализация User Story 1

- [ ] T018 [P] [US1] Шаблоны брокерной машины в `stand/broker/`: `user-data.yaml.j2` (autoinstall: локаль ru_RU/en_US, часовой пояс UTC, пользователь `mlsiem`, SSH-ключ, netplan со статическим адресом служебной сети и DHCP на установочном адаптере, пакеты, `late-commands` установки Kafka), `server.properties.j2`, `kafka.service`, `install-kafka.sh.j2` (скачивание архива Kafka с downloads.apache.org, проверка SHA-512, пользователь `kafka`, `kafka-storage.sh format` с фиксированным cluster id из конфига, systemd, ufw, создание топиков), `meta-data.j2`; версия и SHA-512 Kafka — ключи `stand.kafka_version`/`stand.kafka_sha512` в `configs/stream.yaml` (добавить с комментарием, как обновлять)
- [ ] T019 [US1] `build_seed_iso` и команда `mlsiem stand seed-iso` в `src/mlsiem/stand/seed.py` и `src/mlsiem/cli.py` (R3): Jinja2-рендер шаблонов параметрами `StreamConfig`, ISO через `pycdlib` (Joliet + Rock Ridge, метка `CIDATA`), детерминированные даты файлов; ключ из `~/.ssh/id_ed25519.pub` (опция `--pubkey`); вывод — путь и размер; ничего кроме файла не меняет
- [ ] T020 [P] [US1] `stand/hyperv/Read-StreamConfig.ps1` — чтение `configs/stream.yaml` раздела `stand` (через `uv run python -c` → JSON, чтобы не тянуть YAML-модуль в PowerShell)
- [ ] T021 [P] [US1] `stand/hyperv/00-check.ps1` — только проверки и план (FR-002): права администратора, Hyper-V включён (`Get-WindowsOptionalFeature`), свободная RAM ≥ `memory_mb` + 4 ГБ, свободный диск ≥ `disk_gb`, наличие коммутаторов и ВМ, наличие ISO (путь параметром), печать списка действий следующих скриптов с ресурсами; код 0/1
- [ ] T022 [US1] `stand/hyperv/10-network.ps1` — `mlsiem-mgmt` (Internal) + `New-NetIPAddress host_ip/prefix` на `vEthernet (mlsiem-mgmt)`, `mlsiem-lab` (Private); идемпотентно, с `ShouldProcess`, комментарии «почему Private» (FR-003a)
- [ ] T023 [US1] `stand/hyperv/20-vm-broker.ps1 -Iso <путь> -Seed <путь> [-Download]` — ВМ Gen2 (`memory_mb` статически, `cpus`, VHDX `disk_gb` динамический в `var\stand\`), Secure Boot с шаблоном `MicrosoftUEFICertificateAuthority`, адаптеры: `mgmt` и `Default Switch` (установочный), два DVD (ISO и seed), порядок загрузки с DVD; `-Download` — скачать ISO Ubuntu 24.04 live-server с releases.ubuntu.com и сверить SHA-256 из `SHA256SUMS` — только после `ShouldProcess`; идемпотентно; в конце печатает «откройте консоль ВМ и ответьте yes на Continue with autoinstall?»
- [ ] T024 [US1] `stand/hyperv/30-post-install.ps1` (отключить адаптер `Default Switch`, извлечь DVD, загрузка с диска, дождаться порта 9092, `uv run mlsiem stand check`) и `90-remove.ps1` (удалить ВМ, VHDX, коммутаторы — каждое с `ShouldProcess`)
- [ ] T025 [US1] `check_broker`/`check_isolation` и команда `mlsiem stand check` в `src/mlsiem/stand/check.py` и `src/mlsiem/cli.py` (contracts/cli.md): адрес хоста на vEthernet (`Get-NetIPAddress` через PowerShell только чтение), брокер (версия через `AdminClient.describe_cluster`/список топиков), топики и `retention.ms`, адаптеры ВМ (`Get-VMNetworkAdapter -VMName … | ConvertTo-Json`); код 0/1 с перечнем проблем и подсказками; всё за ≤ `connect_timeout_s` на шаг
- [ ] T026 [US1] Подъём брокера на машине владельца по quickstart §2 — **только после явного разрешения владельца в чате** на каждый меняющий шаг (скачивание ISO ~3 ГБ, коммутаторы, ВМ 2 ГБ/20 ГБ); зафиксировать время (SC-001), вывод `stand check`, повторный запуск скриптов без изменений, поведение при `Stop-VM`

**Checkpoint**: брокер на машине владельца доступен с хоста, топики созданы, из сети стенда не
виден; инструкция воспроизводима.

---

## Phase 4: User Story 2 — Проигрывание данных в брокер (Priority: P2)

**Goal**: `mlsiem stream replay` для разбиения 001 и PCAP с темпом ×N/max, `end`, resume.

**Independent Test**: на `MemoryBroker` проигрывание test синтетики → сообщений = потоков части,
порядок по времени начала, `seq` без пропусков, в конце `end`; темп ×N выдерживается по
подменённым часам.

### Тесты для User Story 2

- [ ] T027 [P] [US2] Тесты проигрывателя в `tests/unit/test_stream_replay.py` (на `MemoryBroker`, подменённые часы `clock`/`sleep`): часть `unsw_time/test` синтетики → число `flow` = потоков части, порядок по `(bidirectional_first_seen_ms, flow_uid)`, `seq` 0…n−1, один `end` с `n_sent`/`last_seq`; ключ = `source_id`; `--speed 60` — суммарный «сон» = (последнее − первое время трафика)/60 ± 1%, без снов < 1 мс; `max` — без снов; метка в поле `label`; `--limit`; несовместимая версия схемы в метаданных parquet → отказ до первой отправки; `BrokerUnavailable` посреди → исключение с «отправлено N из M»; `resume(source_id)` продолжает с `seq` после последнего доставленного (по сообщениям в топике)
- [ ] T028 [P] [US2] Тест PCAP-проигрывателя в `tests/integration/test_stream_replay_pcap.py`: `tests/fixtures/synthetic.pcap` → потоки тем же экстрактором 001 (`extract_flows`), в сообщениях все поля схемы; сравнение с `soc run --pcap` той же фикстуры по `flow_uid` и признакам
- [ ] T029 [P] [US2] Тест CLI в `tests/integration/test_stream_replay_cli.py`: `mlsiem stream replay --split unsw_time --part test --speed max` с подменой фабрики брокера на `MemoryBroker` (через `mlsiem.stream.broker.make_broker` monkeypatch) → код 0, stdout: `source_id`, отправлено, скорость; недоступный брокер → код 1 с подсказкой

### Реализация User Story 2

- [ ] T030 [US2] Проигрыватель в `src/mlsiem/stream/replay.py` (R6): `iter_split_flows(split, part, data_dir, limit)` (все колонки схемы + `label`, сортировка по времени начала, чтение пачками по 50 тыс., проверка версии схемы по метаданным parquet), `iter_pcap_flows(pcap, workdir)`; `replay(flows_iter, broker, cfg, *, source_id, speed, clock, sleep, on_progress)` — темп с компенсацией отставания, `flush` в конце, `end`, сводка; `resume(source_id)` — поиск последнего доставленного `seq` источника в топике
- [ ] T031 [US2] Фабрика `make_broker(cfg, role)` в `src/mlsiem/stream/broker.py` и CLI `stream replay` в `src/mlsiem/cli.py` (contracts/cli.md): опции `--split/--part/--pcap/--limit/--speed/--resume/--data-dir`, прогресс в stderr раз в секунду, итог в stdout, коды возврата; `source_id` = `replay:<вход>:<UTC YYYYMMDDTHHMMSS>`

**Checkpoint**: проигрыватель шлёт в брокер (заглушку в тестах, настоящий на стенде) правильный
поток сообщений.

---

## Phase 5: User Story 3 — Онлайн-цепочка (Priority: P3)

**Goal**: `mlsiem stream consume` — пачки → вердикты → алерты → инкрементальная группировка со
слиянием → плейбуки → одна транзакция SQLite → подтверждение; консоль видит без перезапуска.

**Independent Test**: на `MemoryBroker` проиграть test синтетики, `consume --once` → сеанс
`completed`; `stream compare` с пакетным `soc run` того же входа → «эквивалентно».

### Тесты для User Story 3

- [ ] T032 [P] [US3] Property-тест группировки в `tests/unit/test_stream_incremental.py` (R8): на алертах из `alerts_from_verdicts` синтетики (и на случайных сгенерированных ключах/временах, сид) — инкрементальная группировка пачками размеров {1, 7, 100, всё} в порядке по времени **и** в перемешанном порядке с опозданием ≤ `allowed_lateness_ms` даёт те же группы, что `group_alerts` (сравнение по (ключ, first_seen, last_seen, n_alerts, severity, targets)); граница «ровно W» — тот же инцидент; окно считается по `last_alert_start_ms`, а не `last_seen_ms` (тест с длинным потоком); опоздавший алерт между двумя инцидентами → слияние позднего в ранний, у поглощённого `merged_into`; если у позднего решение (статус ≠ `new` или действие ≠ `proposed`) — слияния нет, запись в `stream_divergences` `merge_blocked_by_decision`; алерт раньше максимума больше чем на `allowed_lateness_ms` → `late = 1`
- [ ] T033 [P] [US3] Тесты дописывания в `tests/unit/test_store_stream.py`: `store.append_batch(conn, session, alerts, incident_changes, actions, offsets, seen, stats)` — одна транзакция (сбой в середине → ничего не записано, включая позиции); повтор той же пачки → алерты не дублируются (`INSERT OR IGNORE`), счётчики не растут; дописывание в инцидент со статусом `closed` или решённым действием: статус/резолюция/действие не меняются, `alerts_after_decision += n`, `first_after_decision_ms` — минимум, аудит `incident_updated` с `after_decision: true`; рост серьёзности → `incident_history` (поле `severity`, аналитик `system`) и аудит; пересчёт плейбука при `proposed` → действие обновлено, `version + 1`, аудит `action_reproposed`; одновременное решение аналитика (другое соединение меняет `version`) → потребитель перечитывает и повторяет, решение аналитика сохранено
- [ ] T034 [P] [US3] Интеграционный тест в `tests/integration/test_stream_chain.py` на `MemoryBroker`: проиграть test синтетики (`speed=max`), `consume(once=True, model_dir=tiny_ensemble)` → сеанс `completed` (получен `end`), `mode='stream'`, `source_id`; вердикты в `var/runs/<run>/verdicts/part-*.parquet`; `compare` с пакетным `run_chain` того же входа и модели → `equivalent: true` (вердикты, инциденты, действия); то же с `tiny_detector`; сообщения двух источников вперемешку → два сеанса, без смешения; модель проверяется до первого poll (битый эксперт → отказ, топик не тронут, позиции не сдвинуты)
- [ ] T035 [P] [US3] Тест консоли и API в `tests/ui/test_stream_ui.py` и `tests/api/test_api_stream.py` (contracts/api-ui-additions.md): `GET /runs` — `mode`, `status`, `source_id`, `last_activity_at`; инцидент — `merged_into`, `alerts_after_decision`, `first_after_decision_ms`; `GET /incidents?after_decision=only`; карточка — пометка «новые алерты после решения: N, первый — … UTC», у поглощённого — «объединён с <ссылка>»; поглощённые скрыты в списке по умолчанию, фильтр «показать объединённые»; хронология — `incident_updated`/`incident_merged`/`action_reproposed` по-русски; детали алерта сеанса читают вероятности из каталога `verdicts/`; ключи ответов 002–004 не изменились; нет inline-скриптов/стилей

### Реализация User Story 3

- [ ] T036 [US3] Инкрементальная группировка в `src/mlsiem/stream/incremental.py` (R8, data-model «Инцидент»): `plan_batch(conn, session, alerts, cfg) → IncidentChanges` — чтение инцидентов ключей пачки из БД, правило окна `first_seen − W ≤ t ≤ last_alert_start + W`, новые инциденты (`incident_id` как в 002 от сеанса, ключа и времени первого алерта), дописывание, слияние/блокировка слияния, флаг `late`; поля инцидента — через `incident_fields` (T014); решение «принято» = статус ≠ `new` или действие ≠ `proposed`
- [ ] T037 [US3] Запись пачки в `src/mlsiem/soc/store.py`: `create_session`, `append_batch` (T033), `set_session_status` (аудит `session_status_changed`), `session_by_source`, `load_offsets`, фильтры `after_decision` и `show_merged` в `_incident_filters` (по умолчанию `merged_into IS NULL` только для прогонов `mode='stream'` — пакетные не затронуты), поля в `list_incidents`/`get_incident`
- [ ] T038 [US3] Потребитель в `src/mlsiem/stream/consumer.py` (R7): `consume(cfg_stream, cfg_soc, *, broker, model_dir, once=False, stop_event)` — загрузка модели и `check_model_classes` до poll; позиции из `stream_offsets` → `seek`; цикл: `poll_batch` → `decode_flows` → отвергнутые в топик `rejected` → по источникам сеанс (создать `running` с `model_version`, `summary.model`; сменившаяся версия модели → сеанс `stopped` с причиной, сообщения источника не обрабатываются) → отсев `stream_seen` → `compute_verdicts` (+ `true_label` из `label`) → вердикты пачки в `verdicts/part-<n>.parquet` → `alerts_from_verdicts` → `plan_batch` → `propose_action` → `append_batch` → после COMMIT `broker.commit`; `end` → проверить, что все `seq ≤ last_seq` обработаны → `completed`; `once` — выйти, когда poll пуст; Ctrl+C — доделать пачку, статус `stopped`
- [ ] T039 [US3] CLI `stream consume` в `src/mlsiem/cli.py` (опции `--model/--detector/--once`, строка показателей раз в 10 с в stderr, сводка по сеансам при выходе) и прогон пакетного режима с `mode='batch'` в `src/mlsiem/soc/run.py`
- [ ] T040 [US3] API в `src/mlsiem/soc/api.py`: поля `Run` (`mode`, `status`, `source_id`, `last_activity_at`) и инцидента (`merged_into`, `alerts_after_decision`, `first_after_decision_ms`), параметры `after_decision=only`, `show_merged`; всё с значениями по умолчанию для пакетных прогонов
- [ ] T041 [US3] Консоль: `src/mlsiem/ui/labels.py` (статусы сеанса «идёт/остановлен/завершён», «поток», события хронологии), `src/mlsiem/ui/views.py` (пометки инцидента, фильтры, `alert_probs` читает `verdicts.parquet` **или** `verdicts/*.parquet` через `pl.scan_parquet` по glob с отбором `flow_uid`), шаблоны `fragments/_incident_table.html`, `incident.html`, `fragments/_timeline.html`, `incidents.html` (фильтры), выбор прогона в шапке с значком «поток» и статусом; стили в `static/console.css`

**Checkpoint**: онлайн-цепочка на заглушке даёт тот же результат, что пакетная; консоль
показывает сеансы и растущие инциденты.

---

## Phase 6: User Story 4 — Перезапуск без потерь и без дублей (Priority: P4)

**Goal**: гарантии at-least-once + идемпотентность, аренда единственного потребителя, отвергнутые.

**Independent Test**: на `MemoryBroker` три «сбоя» потребителя в разных точках (до записи, между
записью и подтверждением, после) → итог = непрерывная обработка, 0 потерь, 0 дублей.

### Тесты для User Story 4

- [ ] T042 [P] [US4] Тесты надёжности в `tests/integration/test_stream_reliability.py` (`MemoryBroker`, точки сбоя через подмену): сбой до COMMIT SQLite, между COMMIT и `broker.commit`, после — по разу каждого за одно проигрывание; итоговые алерты/инциденты/действия = непрерывная обработка (сравнение как в `compare`), `stream_seen` без дублей; повторная отправка части сообщений (дубли производителя) → число алертов не меняется; хранилище заблокировано (`BEGIN EXCLUSIVE` из другого соединения дольше тайм-аута) → потребитель не подтверждает, сообщает ошибку, после разблокировки продолжает без потерь
- [ ] T043 [P] [US4] Тесты аренды и отвергнутых в `tests/unit/test_stream_lease.py`: второй потребитель при живой аренде → отказ с «уже работает <хост:PID> с <время>»; аренда истекла (подмена часов > `lease_ttl_s`) → второй забирает, первый при продлении обнаруживает потерю и останавливается без записи; битые сообщения (все 5 кодов причин) → в `mlsiem.flows.rejected` с причиной и исходным телом (≤ 64 КБ), потребитель продолжает, счётчик `rejected` в показателях

### Реализация User Story 4

- [ ] T044 [US4] Аренда в `src/mlsiem/stream/consumer.py` + `src/mlsiem/soc/store.py` (`acquire_lease`, `renew_lease`, `release_lease` — атомарно через `BEGIN IMMEDIATE`), продление каждые `lease_ttl_s/6` в том же цикле; потеря аренды → остановка до следующей записи
- [ ] T045 [US4] Порядок «запись → подтверждение» и восстановление в `src/mlsiem/stream/consumer.py`: позиции только из `stream_offsets` при старте; ошибка SQLite → без `broker.commit`, повтор с экспоненциальной паузой до `consumer.db_retry_s` (новый ключ конфига), затем остановка с понятным сообщением; отвергнутые — `produce` в `rejected` и `flush` до записи пачки; отметка статусов `stopped` при выходе и по истёкшей аренде

**Checkpoint**: потребителя можно убивать в любой момент — результат тот же.

---

## Phase 7: User Story 5 — Наблюдаемость потока (Priority: P5)

**Goal**: показатели в `stream status`, `GET /stream/status` и блок «Поток» на панели.

**Independent Test**: во время обработки на заглушке `stream status` показывает скорость,
отставание, p50/p95 задержки, отвергнутые, опоздавшие; остановленный потребитель — «не работает»
и растущее отставание.

### Тесты для User Story 5

- [ ] T046 [P] [US5] Тесты показателей в `tests/unit/test_stream_stats.py`: `StatsWindow` — p50/p95 задержек по окну 60 с (подменённые часы), скорость, отставание = `end_offsets − позиция` и `now − sent_at` последнего; запись в `stream_stats` не чаще `stats_interval_s`; хранение ≤ 24 ч (старые удаляются — таблица не аудит); `status_report(conn, broker)` — по сеансам и живость аренды/брокера
- [ ] T047 [P] [US5] Тесты CLI/API/консоли показателей в `tests/integration/test_stream_status.py`: `mlsiem stream status` (код 0, строки по сеансам, «потребитель не работает» без аренды, «брокер недоступен» с подсказкой); `GET /api/v1/stream/status` по контракту; панель прогона `mode='stream'` — блок «Поток» с показателями и опросом `hx-trigger="every Ns"`, для пакетного — блока нет

### Реализация User Story 5

- [ ] T048 [US5] Показатели в `src/mlsiem/stream/stats.py` (R11) и их запись из потребителя (`received_at` алертов, `stream_stats`); `status_report`
- [ ] T049 [US5] `mlsiem stream status` и `mlsiem stream close --session` в `src/mlsiem/cli.py` (contracts/cli.md; `close` — `completed` + аудит `session_status_changed`); `GET /stream/status` в `src/mlsiem/soc/api.py` (брокер проверяется с тайм-аутом 2 с и кешем 10 с, чтобы API не зависал)
- [ ] T050 [US5] Блок «Поток» на панели: `src/mlsiem/ui/views.py` (`stream_panel(conn, run_id)`), фрагмент `src/mlsiem/ui/templates/fragments/_stream_panel.html`, маршрут опроса в `src/mlsiem/ui/routes.py`, стили

**Checkpoint**: видно, как живёт поток, и доказуемы цели производительности.

---

## Phase 8: Сравнение с пакетным режимом (FR-021, SC-004) — сквозное

- [ ] T051 [P] Тесты сравнения в `tests/unit/test_stream_compare.py`: одинаковые прогоны → `equivalent: true`; подменённый вердикт одного потока → расхождение `other` с `flow_uid`; инцидент с другой границей → расхождение; записи `stream_divergences` (`merge_blocked_by_decision`, `late_beyond_allowed`) попадают в расхождения с этими причинами и не делают результат неэквивалентным; разные версии модели → ошибка
- [ ] T052 `compare(conn, cfg, session, batch) → report` и `render_compare` в `src/mlsiem/stream/compare.py` (R12, data-model «Отчёт сравнения»); вердикты сеанса — объединение `verdicts/part-*.parquet` с отсевом дублей по `flow_uid`; CLI `mlsiem stream compare` в `src/mlsiem/cli.py` (отчёт `.md`/`.json` атомарно, коды по контракту)

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: настоящий брокер, производительность, приёмка по quickstart, журнал

- [ ] T053 [P] Тесты на настоящем брокере в `tests/integration/test_stream_stand.py` (`@pytest.mark.stand`, пропуск если `stand check` не проходит): `KafkaBroker` — produce/poll/commit/seek/end_offsets, идемпотентный продюсер, `ensure_topics` идемпотентен; короткое проигрывание синтетики → `consume --once` → эквивалентно пакетному
- [ ] T054 [P] Медленный тест в `tests/integration/test_stream_real.py` (`@pytest.mark.slow` + `stand`): test `unsw_time` `--speed max` → обработка ≤ 10 мин, отставание к концу ≤ 30 с (SC-002), `compare` эквивалентно (SC-004)
- [ ] T055 Приёмка quickstart §3–§7 на стенде — после T026: реальное время ×60 (задержка p95 ≤ 5 с, инцидент в консоли ≤ 15 с — SC-003), `--speed max` + `compare` (SC-002, SC-004), три прерывания потребителя (SC-005), битое сообщение (SC-006), решение аналитика во время потока (FR-017), память хоста (SC-007); проверка консоли в браузере через превью `soc-console` со скриншотом; копия `var\soc.db` → `var\soc.db.bak-004` перед первым запуском
- [ ] T056 [P] `uv run ruff check .`, `uv run ruff format --check .`, `uv run pytest`, `uv run pytest -m slow`, `uv run pytest -m stand` (если стенд поднят) — всё чисто и зелёно
- [ ] T057 [P] README: раздел «Потоковая обработка (фича 005)» — стенд, команды `stand`/`stream`, где что лежит; `stand/hyperv/README.md` — пошаговая инструкция с ресурсами и подтверждениями
- [ ] T058 Запись в `docs/JOURNAL.md` (quickstart §8): время подъёма стенда, скорость, задержки, сравнение, перезапуски, находки и отклонения от плана

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: без зависимостей.
- **Foundational (Phase 2)**: после Setup; блокирует все истории. T010 до T013 (снимок схемы 3
  до правки store); T009 → T011 (фабрика берёт конфиг); T012 независим; T014 после T013.
- **US1 (Phase 3)**: после фундамента; T018 → T019; T020 → T021–T024; T025 после T011;
  **T026 — только после явного разрешения владельца**, ей не блокируются другие истории
  (они тестируются на заглушке).
- **US2 (Phase 4)**: после фундамента (T011, T012).
- **US3 (Phase 5)**: после фундамента; интеграционный тест T034 использует проигрыватель US2
  (T030) — делать после US2. T036 → T037 → T038 → T039; T040, T041 после T037.
- **US4 (Phase 6)**: после US3 (T038).
- **US5 (Phase 7)**: после US3 (T038); T050 после T041.
- **Phase 8**: после US3; T034 опирается на T052 — сделать T051/T052 вместе с US3 или сразу после.
- **Polish (Phase 9)**: T053–T055 требуют поднятого стенда (T026); остальное — после всех историй.

### User Story Dependencies

- **US1 (P1)**: только фундамент. Код и тесты — на заглушке; подъём на машине — по разрешению.
- **US2 (P2)**: фундамент.
- **US3 (P3)**: фундамент + US2 для сквозного теста.
- **US4 (P4)**: US3.
- **US5 (P5)**: US3.

### Within Each User Story

- Тесты первыми, падают до реализации.
- Чистые функции (формат, группировка, показатели) → хранилище → потребитель/CLI → API/консоль.

### Parallel Opportunities

- Setup: T002, T003, T004.
- Фундамент: тесты T005–T008 параллельно; T009, T010, T012 параллельно.
- US1: T015–T017 параллельно; T018, T020, T021 параллельно.
- US2: T027–T029 параллельно.
- US3: T032–T035 параллельно.
- US4: T042, T043. US5: T046, T047. Polish: T053, T054, T056, T057.

---

## Parallel Example: User Story 3

```bash
Task: "T032 Property-тест группировки в tests/unit/test_stream_incremental.py"
Task: "T033 Тесты дописывания в tests/unit/test_store_stream.py"
Task: "T035 Тесты консоли и API в tests/ui/test_stream_ui.py и tests/api/test_api_stream.py"
# затем: T036 → T037 → T038 → T039, параллельно T040/T041 после T037
```

---

## Implementation Strategy

### MVP First

1. Setup → фундамент (формат сообщений, заглушка брокера, схема 4).
2. US1 — скрипты и seed-ISO, затем (с разрешения) подъём брокера на машине владельца.
3. **STOP and VALIDATE**: `stand check` зелёный.

### Incremental Delivery

1. US1 → брокер на стенде.
2. US2 → данные идут в брокер.
3. US3 → онлайн-цепочка и эквивалентность (главная ценность фичи).
4. US4 → надёжность.
5. US5 → наблюдаемость.
6. Polish → приёмка на настоящем брокере, журнал.

Если подъём стенда задерживается (нет разрешения, проблемы Hyper-V), US2–US5 полностью делаются
и проверяются на `MemoryBroker`; на стенде остаётся только приёмка T053–T055.

---

## Notes

- [P] — разные файлы и нет зависимостей от незавершённых задач.
- Скачивание ISO Ubuntu (~3 ГБ), создание коммутаторов и ВМ — только с разрешения владельца.
- База мигрирует на схему 4 при первом `soc serve`/`soc run`/`stream consume` — перед этим копия.
- После каждой истории — предложить владельцу название коммита; коммитит он сам.
