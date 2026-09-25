# Data Model: потоковая обработка через Kafka (фича 005)

Сущности спеки ([spec.md](spec.md), Key Entities) в виде сообщений, таблиц и правил. Решения —
в [research.md](research.md) (R1–R15). Всё, что не упомянуто, — как в 002–004.

## Сообщения Kafka (R5)

### Топики

| Топик | Партиции | Ключ | Содержимое |
|---|---|---|---|
| `mlsiem.flows` | 1 (конфиг) | `source_id` | сообщения `flow` и `end` |
| `mlsiem.flows.rejected` | 1 | `source_id` или `—` | отвергнутые сообщения + причина |

Срок хранения — `retention_hours` конфига (по умолчанию 168). `auto.create.topics.enable=false`.

### Заголовки (у всех сообщений)

| Заголовок | Значения |
|---|---|
| `mlsiem-kind` | `flow` \| `end` |
| `mlsiem-schema` | версия схемы признаков 001, например `1.0.0` |
| `mlsiem-source` | `source_id` |

### Тело `flow` (JSON)

| Поле | Тип | Правило |
|---|---|---|
| `flow_uid` | str | идентификатор потока 001; уникален в источнике |
| `source_id` | str | `replay:<вход>:<YYYYMMDDTHHMMSS>` или `sensor:<имя>` (006) |
| `seq` | int | номер сообщения в источнике, с 0, без пропусков |
| `sent_at_ms` | int | часы производителя при отправке (для задержки) |
| `schema_version` | str | = заголовку `mlsiem-schema` |
| `fields` | obj | все колонки `SCHEMA.columns`, кроме группы `label`, имя → значение (`null` допустим) |
| `label` | str \| отсутствует | только размеченный вход; в модель не подаётся (FR-007) |

Проверки потребителя (иначе → `rejected` с `reason`): JSON разбирается; обязательные поля есть;
мажорная версия схемы = мажорной версии модели; каждое поле `fields` приводится к типу схемы;
`source_id` в теле = заголовку.

### Тело `end` (JSON)

| Поле | Тип | Правило |
|---|---|---|
| `source_id` | str | источник |
| `n_sent` | int | сколько `flow` отправлено |
| `last_seq` | int | `seq` последнего `flow` (`n_sent − 1`) |
| `sent_at_ms` | int | время отправки |

### Отвергнутое сообщение

`{"reason": "<код>: <текст по-русски>", "topic", "partition", "offset", "headers", "value": "<исходное тело строкой, ≤ 64 КБ>", "rejected_at"}`. Коды: `bad_json`, `missing_field`,
`schema_major`, `bad_type`, `source_mismatch`.

## Сеанс — строка `runs` (R10, clarify Q4)

Прогон с `mode = stream`. Поля 002–004 плюс:

| Поле | Тип | Правило |
|---|---|---|
| `mode` | `batch` \| `stream` | пакетные прогоны — `batch` |
| `status` | `running` \| `stopped` \| `completed` | у пакетных — `completed` |
| `source_id` | str | ключ связи сеанса с источником; уникален среди сеансов |
| `last_activity_at` | ISO | время последней записанной пачки |
| `model_version` | str | версия модели, с которой сеанс начат |

`run_id` сеанса — `stream-<хеш12 от source_id>`. `detector_version` = `model_version`.
`finished_at` у сеанса = `last_activity_at` (обновляется), `n_flows/n_alerts/n_incidents` —
текущие счётчики. `summary` — как у 004 (`model`, `experts`, `experts_meta`, …) плюс
`stream: {n_rejected, n_late, n_merged, n_after_decision, end_received}`.

Переходы статуса:

```text
(первое сообщение источника) → running
running → stopped      потребитель остановлен (Ctrl+C, сбой — при следующем старте/статусе по истёкшей аренде)
stopped → running      потребитель снова обрабатывает сообщения источника
running → completed    получен end и обработаны все seq ≤ last_seq
running|stopped → completed   команда `stream close --session` (для сенсора без конца)
```

Модель сеанса неизменна: если при перезапуске загружена модель другой версии, сообщения этого
источника не обрабатываются (сеанс остаётся `stopped`, причина в статусе) — владелец либо
возвращает модель, либо закрывает сеанс (`stream close`) и начинает новый источник.

## Алерт (новые поля)

| Поле | Правило |
|---|---|
| `late` | 1 — время начала потока раньше максимума, виденного в сеансе, больше чем на `allowed_lateness_ms` |
| `received_at` | ISO: когда потребитель записал алерт (задержка = `received_at − sent_at_ms`) |

Уникальность `(run_id, flow_uid)` — как в 002; повтор вставки игнорируется (FR-015).

## Инцидент (новые поля и правила, R8, R9)

| Поле | Правило |
|---|---|
| `last_alert_start_ms` | максимум времени начала потоков алертов; правая граница окна присоединения |
| `merged_into` | id инцидента, поглотившего этот (null — не поглощён) |
| `alerts_after_decision` | сколько алертов дописано после решения/закрытия |
| `first_after_decision_ms` | время трафика первого такого алерта |

Правило присоединения алерта `t` (время начала) к инциденту ключа `(attacker_ip, класс)`:
`first_seen_ms − W ≤ t ≤ last_alert_start_ms + W`, W = `grouping.window_ms`. Если подходят два
инцидента — слияние позднего в ранний, кроме случая, когда у позднего уже есть решение
(статус ≠ `new` или действие ≠ `proposed`): тогда алерт идёт в ранний, а пара — в
`stream_divergences`.

«Решение принято» (для FR-017) — статус инцидента ≠ `new` **или** действие ≠ `proposed`.
Поглощённый инцидент: алертов 0, `merged_into` задан, действие `proposed` удаляется из
предложений (строка действия получает `state = rejected`, `decided_by = system`, комментарий
«инцидент объединён с …») — аудит сохраняет историю.

## Служебные таблицы потока

| Таблица | Поля | Назначение |
|---|---|---|
| `stream_offsets` | `topic`, `partition`, `next_offset`, `updated_at`; PK (`topic`, `partition`) | позиция, записанная в той же транзакции, что результат (R7) |
| `stream_seen` | `run_id`, `flow_uid`, `seq`; PK (`run_id`, `flow_uid`) | обработанные потоки сеанса (дубли отсекаются) |
| `stream_lease` | `name` PK, `holder` (хост:PID), `renewed_at` | единственный потребитель (FR-019) |
| `stream_stats` | `at`, `run_id`, `processed`, `lag_messages`, `lag_seconds`, `latency_p50_ms`, `latency_p95_ms`, `rejected`, `late`, `rate_per_s` | показатели (R11); хранится последние 24 ч |
| `stream_divergences` | `run_id`, `kind`, `incident_id`, `other_incident_id`, `flow_uid`, `at`, `details` | известные причины расхождения с пакетным режимом |

## Аудит — новые события (R10)

| Событие | Когда | details |
|---|---|---|
| `incident_updated` | пачка дописала алерты | `added`, `n_alerts`, `severity_old/new`, `after_decision` |
| `incident_merged` | слияние | `into`, `moved_alerts` |
| `action_reproposed` | плейбук пересчитал предложение | `old`/`new` (тип, объект, правило) |
| `session_status_changed` | смена статуса сеанса | `old`, `new`, `reason` |

Все — от `system`. Появление инцидента — как в 002: `action_proposed`; `run_loaded` для сеанса
пишется один раз при создании.

## Миграция 3 → 4 (одна транзакция)

```text
ALTER TABLE runs ADD COLUMN mode TEXT NOT NULL DEFAULT 'batch'
ALTER TABLE runs ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'
ALTER TABLE runs ADD COLUMN source_id TEXT
ALTER TABLE runs ADD COLUMN last_activity_at TEXT
ALTER TABLE runs ADD COLUMN model_version TEXT
ALTER TABLE incidents ADD COLUMN merged_into TEXT
ALTER TABLE incidents ADD COLUMN alerts_after_decision INTEGER NOT NULL DEFAULT 0
ALTER TABLE incidents ADD COLUMN first_after_decision_ms INTEGER
ALTER TABLE incidents ADD COLUMN last_alert_start_ms INTEGER
UPDATE incidents SET last_alert_start_ms = (SELECT MAX(first_seen_ms) FROM alerts a WHERE a.incident_id = incidents.incident_id)
ALTER TABLE alerts ADD COLUMN late INTEGER NOT NULL DEFAULT 0
ALTER TABLE alerts ADD COLUMN received_at TEXT
CREATE TABLE stream_offsets / stream_seen / stream_lease / stream_stats / stream_divergences
пересоздание audit_log с новым CHECK (entry_id сохраняются), триггеры и индекс заново
CREATE UNIQUE INDEX ux_runs_source ON runs(source_id) WHERE source_id IS NOT NULL
CREATE INDEX ix_incidents_after_decision ON incidents(run_id, alerts_after_decision)
PRAGMA user_version = 4
```

`SchemaTooNew` для версии > 4. Пакетный `write_run` пишет `mode = batch`, `status = completed`.

## Отчёт сравнения — `reports/stream_compare_<session>.{md,json}` (R12)

| Раздел | Содержимое |
|---|---|
| `session`, `batch` | сравниваемые прогоны, модели (обязаны совпадать по версии) |
| `verdicts` | потоков у обоих, совпало, расхождения (до 20 примеров) |
| `incidents` | инцидентов у обоих, совпало по (ключ, first/last_seen, n_alerts, severity, targets) |
| `actions` | совпало по (тип, объект, правило) |
| `divergences` | расхождения с причиной: `merge_blocked_by_decision` \| `late_beyond_allowed` \| `other` |
| `equivalent` | true, если расхождений `other` нет |

## Конфигурация — `configs/stream.yaml` (новый)

```yaml
broker:
  bootstrap: 10.77.0.10:9092
  connect_timeout_s: 10
topics:
  flows: mlsiem.flows
  rejected: mlsiem.flows.rejected
  partitions: 1
  retention_hours: 168
consumer:
  group: mlsiem-chain
  batch_max_messages: 2000
  batch_max_wait_ms: 500
  allowed_lateness_ms: 120000
  lease_ttl_s: 30
  stats_interval_s: 1
replay:
  default_speed: 60        # «реальное время × 60»; max — без пауз
stand:
  vm_name: mlsiem-broker
  mgmt_switch: mlsiem-mgmt
  lab_switch: mlsiem-lab
  host_ip: 10.77.0.1
  broker_ip: 10.77.0.10
  prefix: 24
  memory_mb: 2048
  cpus: 2
  disk_gb: 20
  kafka_heap_mb: 512
```
