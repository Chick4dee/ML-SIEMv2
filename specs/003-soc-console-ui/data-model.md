# Data Model: SOC-консоль аналитика (003)

Базовые сущности — из [data-model 002](../002-detection-incident-chain/data-model.md) (Run,
Alert, Incident, Action, AuditEntry). Здесь описаны только изменения и новые сущности консоли.
Время трафика — миллисекунды epoch UTC; время решений — ISO-8601 UTC.

## Изменения хранилища 002 (`var/soc.db`)

Версия схемы хранится в `PRAGMA user_version`. База фичи 002 имеет версию 0; фича 003 вводит
версию 2 (1 зарезервирована как «схема 002», чтобы явно отличать её от пустого файла).

### Incident — новое поле

| Поле | Тип | Описание |
|---|---|---|
| `assignee` | TEXT NULL | имя ответственного аналитика; NULL — не назначен |

- Меняется только через `store.assign(...)`: оптимистичная блокировка по `version` (как статус),
  `version + 1`, запись в `incident_history` (`field = 'assignee'`, `old`, `new`, `comment`)
  и в аудит (`incident_assigned`) — одной транзакцией.
- Назначение допустимо в любом статусе, включая `closed` (не меняет статус и резолюцию).
- Значение: обрезанная строка 1–64 символа без управляющих символов; пустое значение = снять
  назначение (NULL). Повторное назначение того же имени — `bad_request` «уже назначен».

### AuditEntry — новое событие и новые поля `details`

| Изменение | Описание |
|---|---|
| событие `incident_assigned` | `details`: `{"old": ..., "new": ..., "comment": ...}` |
| `details.assignee` | у `incident_status_changed`, `action_executed`, `action_rejected`: ответственный на момент решения (или null) |
| `details.by_non_assignee` | `true`, если ответственный задан и не совпадает с автором решения; иначе `false` |

Оба поля вычисляются в `store` внутри транзакции решения (research R6), независимо от того,
пришло решение из консоли или из API.

### Run — `summary` дополняется

| Ключ `summary` | Описание |
|---|---|
| `threshold` | порог детектора, с которым сделан прогон |
| `classes` | классы детектора в порядке столбцов `p_<класс>` в `verdicts.parquet` |

Старые прогоны без этих ключей обрабатываются по research R10.

### Миграция 0 → 2 (одна транзакция, идемпотентно в `init_db`)

1. `ALTER TABLE incidents ADD COLUMN assignee TEXT`.
2. `ALTER TABLE audit_log RENAME TO audit_log_v1`; создать `audit_log` с расширенным
   `CHECK (event IN …)`; `INSERT INTO audit_log SELECT * FROM audit_log_v1` (с `entry_id`);
   `DROP TABLE audit_log_v1`; создать заново триггеры запрета UPDATE/DELETE и индекс.
3. `CREATE INDEX ix_alerts_run_time ON alerts(run_id, first_seen_ms)`,
   `CREATE INDEX ix_incidents_assignee ON incidents(assignee)`.
4. `PRAGMA user_version = 2`.

База новее, чем знает код (`user_version > 2`) — отказ с понятным сообщением.

## Конфигурация (`configs/soc.yaml`) — новые разделы

```yaml
networks:                     # именованные сети для меток источника (FR-018)
  - {name: "жертвы UNSW-NB15", role: victims,    cidrs: [149.171.126.0/24]}
  - {name: "фон UNSW-NB15",    role: background, cidrs: [59.166.0.0/24]}
ui:
  refresh_seconds: 10         # интервал автообновления (FR-023), 3…300
  page_size: 50               # строк в списке инцидентов и журнале
  recent_alerts: 20           # последних алертов на панели
  alerts_page_size: 50        # алертов на страницу в карточке
```

- `role` ∈ `victims | background | infrastructure | other`; метку источника дают только
  `victims` и `background` (остальные роли — для подписи адресов в карточке).
- CIDR проверяются при загрузке конфига (`ipaddress.ip_network(strict=False)`); ошибка —
  `ConfigError` с указанием сети.

## Сущности консоли (не хранятся в БД)

### Analyst (аналитик в браузере)

| Поле | Источник | Правила |
|---|---|---|
| `name` | cookie `mlsiem_analyst` (URL-кодирование) | 1–64 символа после обрезки, без управляющих; нет cookie → операции, меняющие состояние, отклоняются с просьбой представиться |

### CsrfContext

| Поле | Источник | Правила |
|---|---|---|
| `session` | cookie `mlsiem_csrf`, 32 случайных байта (base64url) | ставится при первом заходе, `SameSite=Strict`, `Path=/` |
| `token` | `<ts>.<HMAC-SHA256(secret, session + ts)>` | действителен 12 ч; `secret` — случайный на процесс |

Проверки — research R7. Нарушение → 403 + запись в лог `mlsiem.ui.security`, база не меняется.

### SourceFlag (метка подозрительного источника)

| Поле | Описание |
|---|---|
| `kind` | `network` \| `target_elsewhere` |
| `network_name`, `role` | для `network`: название и роль сети (`victims`/`background`) |
| `related_incidents` | для `target_elsewhere`: `incident_id` инцидентов прогона, где адрес — цель |
| `explanation` | готовый русский текст: «источник входит в сеть „жертвы UNSW-NB15“ (149.171.126.0/24)» / «адрес — цель в 3 других инцидентах» |

Вычисляется функцией `soc.flags.source_flags(incidents_of_run, networks)` →
`{incident_id: [SourceFlag, ...]}`. Инцидент «подозрительный», если список непуст. На
серьёзность, статус, резолюцию и действие не влияет (FR-020).

### IncidentListView (вид списка = адрес страницы)

| Параметр | Значения | По умолчанию |
|---|---|---|
| `run` | `run_id` | последний прогон (`started_at` ↓) |
| `status` | `new,in_progress,closed` (несколько) | все |
| `severity` | `low,medium,high,critical` (несколько) | все |
| `attack_class` | класс атаки | все |
| `src` | IP-адрес или CIDR | — |
| `assignee` | имя или `__none__` | все |
| `action_state` | `proposed,executed,rejected` | все |
| `flagged` | `only` \| `hide` \| пусто | пусто (показывать все) |
| `sort` | `severity`, `first_seen`, `last_seen`, `n_alerts` | `severity` |
| `dir` | `asc` \| `desc` | `desc` |
| `page` | ≥ 1 | 1 |

Вторичный порядок при `sort=severity` — `first_seen_ms` ↓, затем `incident_id` (стабильность).
Некорректное значение параметра игнорируется, над таблицей — предупреждение «фильтр X не
применён: …» (edge case спеки); остальные параметры применяются.

### DashboardSummary (панель прогона)

| Поле | Как считается |
|---|---|
| `by_status`, `by_severity`, `by_class` | `GROUP BY` по инцидентам прогона |
| `actions_pending` | действия прогона в состоянии `proposed` |
| `unassigned` | инциденты прогона с `assignee IS NULL` и статусом не `closed` |
| `flagged` | инциденты с непустыми метками (SourceFlag) |
| `run` | сводка прогона: потоки, алерты, инциденты, детектор, время, предупреждения |
| `recent_alerts` | `ui.recent_alerts` последних алертов прогона по `first_seen_ms` ↓ |

Каждому счётчику соответствует `IncidentListView`, дающий ровно это число строк (FR-022,
SC-004): например, `unassigned` → `assignee=__none__&status=new,in_progress`,
`actions_pending` → `action_state=proposed`.

### TimelineEvent (хронология карточки)

| Поле | Описание |
|---|---|
| `at` | время события (UTC) |
| `clock` | `traffic` (время трафика из датасета) \| `decision` (время работы системы/аналитика) |
| `kind` | `first_alert`, `last_alert`, `incident_created`, `action_proposed`, `incident_assigned`, `incident_status_changed`, `action_executed`, `action_rejected` |
| `actor` | аналитик или `system`; для событий трафика — нет |
| `text` | русская строка события; для решений не ответственным — пометка «не ответственный» |

Источники: `alerts` (первый/последний), `incidents.created_at`, `audit_log` по `incident_id`.
Сортировка по `at`, при равенстве — по порядку источника.

### AlertHistogram

| Поле | Описание |
|---|---|
| `start_ms`, `end_ms` | интервал инцидента |
| `bin_ms` | ширина корзины: `max(1000, ceil((end − start) / 40))` |
| `counts[]` | число алертов в каждой корзине (до 40) |

## Переходы (без изменений правил 002)

Статусы: `new → in_progress → closed`, `new → closed`; из `closed` — никуда. Действия:
`proposed → executed | rejected`. Консоль показывает только кнопки допустимых переходов;
окончательная проверка — в `store`.
