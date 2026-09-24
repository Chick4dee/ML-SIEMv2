---

description: "Задачи фичи 003 — SOC-консоль аналитика (серверный рендеринг + htmx)"
---

# Tasks: SOC-консоль аналитика

**Input**: Design documents from `specs/003-soc-console-ui/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/ui.md,
contracts/api-v1-additions.md, quickstart.md

**Tests**: включены. Конституция (принцип VI), research R14 и SC-005/SC-007/SC-009 требуют
автоматических тестов на каждую страницу, форму, ошибку, миграцию и защиту: модульные — на
`store`/`flags`/`views`/`security`, UI — через `TestClient` + BeautifulSoup на временной БД
с прогоном на синтетике (фикстуры 002 `synthetic_split`, `tiny_detector`), медленные
(`-m slow`) — на реальном прогоне 002 из `var/soc.db`. Тесты пишутся до или вместе с кодом и
должны падать до реализации.

**Organization**: задачи сгруппированы по пользовательским историям спеки (US1…US5), чтобы
каждую можно было реализовать и проверить отдельно.

**Общие правила для всех задач**:
- Комментарии, надписи интерфейса, сообщения об ошибках — на русском, подробно и живым языком
  (где логика неочевидна — «почему», а не пересказ кода). Идентификаторы — английские.
- Консоль НЕ дублирует правила 002: переходы статусов, решения по действиям, версии, аудит —
  только через функции `src/mlsiem/soc/store.py` (FR-003). В `ui/` нет SQL.
- Зависимость строго `ui → soc`; `store.py` и `api.py` не импортируют ничего из `ui` (кроме
  подключения роутера в `api.create_app`).
- Все данные в шаблонах выводятся с автоэкранированием Jinja2; `|safe` и `Markup` — только для
  разметки, собранной сервером из констант (SVG гистограммы), никогда для данных (FR-029).
- Никаких inline-скриптов и `on*=`-атрибутов (CSP `default-src 'self'`); никаких внешних
  адресов (CDN, шрифты) в страницах (FR-030).
- Каждая страница работает без JS: у форм есть `method`/`action`, у ссылок — `href`; `hx-*`
  только дополняют их (FR-032).
- Интервалы, размеры страниц, сети — только из `configs/soc.yaml` (раздел `ui`, `networks`),
  не в коде.
- Время показывается в UTC с подписью «UTC»; время трафика и время решений подписаны явно.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: можно делать параллельно (разные файлы, нет зависимостей от незавершённых задач)
- **[Story]**: к какой истории относится задача (US1…US5)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: зависимости, вендоринг htmx, конфиг, скелет пакета

- [X] T001 Добавить в `pyproject.toml` зависимость `python-multipart` (разбор HTML-форм в FastAPI, research R15) и в extra `dev` — `beautifulsoup4`; включить `src/mlsiem/ui/templates/**` и `src/mlsiem/ui/static/**` в пакет (hatch по умолчанию берёт всё из `src/mlsiem`, проверить сборкой `uv build` или импортом из установленного пакета); затем `uv sync --extra dev` для обновления `uv.lock`
- [X] T002 [P] Создать скелет по plan.md: `src/mlsiem/ui/__init__.py`, каталоги `src/mlsiem/ui/templates/fragments/`, `src/mlsiem/ui/static/vendor/`, `tests/ui/__init__.py`
- [X] T003 [P] Вендоринг htmx (research R3): **спросить у владельца разрешение на скачивание** (файл, источник, размер), затем скачать `htmx.min.js` последней стабильной версии 2.x с `https://cdn.jsdelivr.net/npm/htmx.org@<версия>/dist/htmx.min.js` в `src/mlsiem/ui/static/vendor/htmx.min.js`, положить текст лицензии 0BSD в `src/mlsiem/ui/static/vendor/LICENSE-htmx.txt`, записать версию, адрес источника и SHA-256 в `src/mlsiem/ui/static/vendor/README.md`
- [X] T004 [P] Дополнить `configs/soc.yaml` разделами из data-model: `networks` — `{name: "жертвы UNSW-NB15", role: victims, cidrs: [149.171.126.0/24]}` и `{name: "фон UNSW-NB15", role: background, cidrs: [59.166.0.0/24]}`; `ui: {refresh_seconds: 10, page_size: 50, recent_alerts: 20, alerts_page_size: 50}`; с комментариями, что значит каждый ключ и что метки источников — только подсказка (FR-020)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: конфиг сетей и UI, миграция базы на схему 2, порог в прогоне, безопасность
(имя аналитика, CSRF, заголовки), подписи, каркас роутера и базового шаблона — то, на что
опираются все истории.

**⚠️ CRITICAL**: работа над историями начинается только после этой фазы

### Тесты фундамента

- [X] T005 [P] Модульные тесты конфига в `tests/unit/test_soc_config.py` (дополнить): `networks` и `ui` читаются; неверный CIDR → `ConfigError` с названием сети; `role` вне `victims|background|infrastructure|other` → ошибка; `refresh_seconds` вне 3…300 → ошибка; нет раздела `ui`/`networks` → значения по умолчанию из data-model (обратная совместимость с конфигом 002)
- [X] T006 [P] Модульные тесты миграции в `tests/unit/test_store_migration.py`: база в состоянии схемы 002 (создать DDL 002 из фикстуры-копии, `user_version = 0`) с прогоном, решениями и ≥ 5 записями аудита → `init_db` → `user_version == 2`, у `incidents` есть `assignee` (NULL у старых строк), все записи аудита на месте с теми же `entry_id`, `at`, `details`; событие `incident_assigned` принимается CHECK-ом; `UPDATE`/`DELETE` в `audit_log` по-прежнему падают ошибкой триггера; индексы `ix_alerts_run_time` и `ix_incidents_assignee` существуют; повторный `init_db` ничего не меняет; миграция на пустом файле даёт сразу схему 2; `user_version = 3` → понятная ошибка «база новее, чем знает код»; сбой посреди миграции (подменить шаг исключением) → откат, база осталась в схеме 002 целиком
- [X] T007 [P] Модульные тесты безопасности в `tests/unit/test_ui_security.py`: имя аналитика из cookie (URL-кодирование, кириллица `Влад` туда-обратно); имя «1–64 символа после обрезки, без управляющих символов» — пустое, 65 символов, `\n`/`\x00` → отказ; токен CSRF: выпущенный для cookie-сессии проходит, для другой сессии — нет, с подделанной подписью — нет, старше 12 ч — «устарел», выпущенный другим `secret` (перезапуск) — «устарел»; проверка источника: `Sec-Fetch-Site: same-origin` → да, `cross-site`/`same-site` → нет; `Origin: http://127.0.0.1:<port>` и `http://localhost:<port>` → да, `http://evil.example` → нет; нет обоих заголовков → решает токен
- [X] T008 [P] Модульные тесты подписей в `tests/unit/test_ui_labels.py`: у каждого значения `store.INCIDENT_STATUSES`, `store.RESOLUTIONS`, `store.ACTION_STATES`, `store.AUDIT_EVENTS` (включая `incident_assigned`), `config.SEVERITY_LEVELS`, `config.ACTION_TYPES` и ролей сетей есть русская подпись; фильтр `utc_ms(1424242234000)` → `2015-02-18 06:50:34 UTC`; `utc_iso` форматирует ISO-время решений в том же виде
- [X] T009 Фикстуры UI в `tests/ui/conftest.py`: `soc_cfg` и `run` по образцу `tests/api/conftest.py` (временная БД, прогон `run_chain` на `synthetic_split` + `tiny_detector`); `ui_client` — `TestClient(create_app(...))` с `base_url="http://127.0.0.1:8000"`; помощники `csrf(client)` (получить токен со страницы или из cookie), `login(client, name)` (выставить `mlsiem_analyst` через `POST /analyst`), `post_form(client, url, data, htmx=True)` (подставляет токен, `Origin`, `Sec-Fetch-Site: same-origin`, `HX-Request`), `soup(response)` (BeautifulSoup); фабрика `add_incidents(db, specs)` — вставка инцидентов/алертов/действий прямо в SQLite для краевых случаев (тысячи алертов, длинные цели, спецсимволы в имени/комментарии)

### Реализация фундамента

- [X] T010 [P] Расширить `src/mlsiem/soc/config.py`: dataclass `NetworkConfig(name, role, cidrs: tuple[ipaddress.IPv4Network | IPv6Network, ...])`, `UiConfig(refresh_seconds=10, page_size=50, recent_alerts=20, alerts_page_size=50)`, поля `SocConfig.networks` и `SocConfig.ui`; разбор с проверками из T005 (`ip_network(strict=False)`, роль из `NETWORK_ROLES = ("victims", "background", "infrastructure", "other")`, `refresh_seconds` 3…300); разделы необязательны — значения по умолчанию из data-model
- [X] T011 Миграция хранилища в `src/mlsiem/soc/store.py` (research R5, data-model «Миграция 0 → 2»): константа `SCHEMA_VERSION = 2`; `AUDIT_EVENTS` + `incident_assigned`; DDL новой базы сразу со столбцом `incidents.assignee TEXT` и расширенным CHECK; функция `migrate(conn)` одной транзакцией: `ALTER TABLE incidents ADD COLUMN assignee TEXT` → `ALTER TABLE audit_log RENAME TO audit_log_v1` → создать `audit_log` с новым CHECK → `INSERT INTO audit_log SELECT * FROM audit_log_v1` → `DROP TABLE audit_log_v1` → триггеры запрета UPDATE/DELETE и индекс `ix_audit_incident` заново → `CREATE INDEX ix_alerts_run_time ON alerts(run_id, first_seen_ms)`, `CREATE INDEX ix_incidents_assignee ON incidents(assignee)` → `PRAGMA user_version = 2`; `init_db` определяет пустой файл / схему 002 (`user_version` 0 или 1 при существующих таблицах) / схему 2 / «новее» (`BadRequest`-подобная ошибка `SchemaTooNew` с русским текстом) и возвращает признак «мигрировано»; комментарий, почему `DROP TABLE` не запускает триггеры удаления и почему аудит переносится с `entry_id` (зависит от T006)
- [X] T012 [P] Записывать порог и классы детектора в сводку прогона в `src/mlsiem/soc/run.py`: `summary.threshold` и `summary.classes` (порядок столбцов `p_<класс>` в `verdicts.parquet`); дополнить `tests/integration/test_soc_run_split.py` проверкой этих ключей
- [X] T013 [P] Реализовать `src/mlsiem/ui/security.py` (research R4, R7): `read_analyst(request) -> str | None` и `analyst_cookie(name) -> str` (URL-кодирование, `SameSite=Strict`, `Path=/`, срок 1 год) с проверкой «1–64 символа после обрезки, без управляющих символов»; `CsrfGuard(secret=secrets.token_bytes(32), max_age=12*3600)` с методами `ensure_session(request, response)` (cookie `mlsiem_csrf`, 32 случайных байта base64url), `issue(session) -> "<ts>.<hmac>"`, `verify(session, token) -> ok | stale | invalid`, `origin_ok(request, allowed_origins) -> bool | None`; FastAPI-зависимость `require_csrf` для всех POST консоли: отказ → `403` + фрагмент `fragments/_error.html` («запрос отклонён: он пришёл не со страницы консоли» / «страница устарела — обновите её»), `logging.getLogger("mlsiem.ui.security").warning(...)` с методом, путём, `Origin`, `Sec-Fetch-Site`; middleware заголовков `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin` для всех ответов вне `/api/v1` (зависит от T007)
- [X] T014 [P] Реализовать `src/mlsiem/ui/labels.py` (research R13): словари подписей для статусов, резолюций, серьёзности, типов и состояний действий, событий аудита, ролей сетей; функции-фильтры Jinja `label(value, kind)`, `utc_ms(ms)`, `utc_iso(iso)`, `short_list(items, n=3)` («a, b, c и ещё 5»); функция `register(env)` (зависит от T008)
- [X] T015 Каркас консоли в `src/mlsiem/ui/routes.py` и `src/mlsiem/ui/templates/base.html`: `APIRouter`, `Jinja2Templates` с автоэкранированием и фильтрами из `labels.register`, помощник `render(request, page, fragment, ctx)` — полная страница без `HX-Request` (или при `HX-Boosted`), только фрагмент с `HX-Request`; `base.html` — шапка (название, имя аналитика со ссылкой «сменить» на `/analyst?next=…` или «представиться», выбор прогона — GET-форма `run`), место для баннеров (`#banners`), `<body hx-headers='{"X-CSRF-Token": "..."}'>`, подключение `/static/console.css`, `/static/console.js`, `/static/vendor/htmx.min.js`; страница `404` «не найдено» со ссылкой на список; состояние «пустая база» с командой `uv run mlsiem soc run --split unsw_time --part test`; подключить роутер, `StaticFiles` (`/static`) и middleware из T013 в `create_app` в `src/mlsiem/soc/api.py`, не меняя маршрутов `/api/v1` (зависит от T011, T013, T014)
- [X] T016 [P] Базовые стили и скрипт: `src/mlsiem/ui/static/console.css` (CSS-переменные, светлая/тёмная тема через `prefers-color-scheme`, таблицы, бейджи серьёзности/статуса/меток, формы, баннеры, полоса «данные устарели», длинные значения сокращаются с `<details>`, ширина от 360 px без горизонтальной прокрутки страницы) и `src/mlsiem/ui/static/console.js` — пока только подключение обработчиков по `data-*`-атрибутам (без inline-скриптов); наполняется в US2 и US4
- [X] T017 Обновить `soc serve` в `src/mlsiem/cli.py`: после `init_db` печатать «схема базы обновлена до версии 2» при миграции, адреса консоли `http://127.0.0.1:<port>/` и API `http://127.0.0.1:<port>/api/v1`; ошибка «база новее» → код `1` и сообщение на русском (зависит от T011, T015)

**Checkpoint**: `uv run pytest` — тесты T005–T008 зелёные, все тесты 002 зелёные (API не
сломан миграцией); `uv run mlsiem soc serve` открывает `/` с шапкой и пустым состоянием или
заглушкой панели

---

## Phase 3: User Story 1 — Список инцидентов и карточка (Priority: P1) 🎯 MVP

**Goal**: аналитик открывает консоль, фильтрует и сортирует список инцидентов прогона и
открывает карточку: сводка, объяснение серьёзности, действие с правилом, алерты постранично
с вероятностями по классам, гистограмма, хронология, история, аудит.

**Independent Test**: на временной БД с прогоном на синтетике открыть `/incidents`, применить
каждый фильтр и сортировку (полная страница и фрагмент `HX-Request`), открыть карточку и
сверить её содержимое с `store.get_incident` / `store.list_alerts` / аудитом.

### Тесты для User Story 1

- [X] T018 [P] [US1] Модульные тесты фильтров хранилища в `tests/unit/test_store_filters.py`: `src_ip` — точный адрес и CIDR (`10.0.0.0/24`), IPv6; неверный адрес → `BadRequest`; `assignee` — имя и `__none__`; `action_state` (несколько); `incident_ids`/`exclude_ids`; сортировки `severity|first_seen|last_seen|n_alerts` × `asc|desc` со стабильным вторичным ключом `incident_id`; значение `sort` вне белого списка → `BadRequest`; без новых параметров порядок и результат — как в 002 (регрессия); `total` совпадает с числом строк без `limit`
- [X] T019 [P] [US1] Модульные тесты сборки видов в `tests/unit/test_ui_views.py`: разбор `IncidentListView` из параметров адреса (все параметры data-model; по умолчанию `sort=severity`, `dir=desc`, прогон — последний); некорректные значения (`severity=ultra`, `src=999.1.1.1`, `page=-2`, `sort=drop`) игнорируются и дают предупреждения «фильтр X не применён: …», остальные применяются; обратное построение адреса из вида (ссылка = тот же вид); гистограмма — `bin_ms = max(1000, ceil((end − start) / 40))`, до 40 корзин, сумма = `n_alerts`, инцидент с одним алертом — одна корзина; хронология — первый/последний алерт с `clock=traffic`, `incident_created` и записи аудита с `clock=decision`, порядок по времени, решения не ответственным помечены
- [X] T020 [P] [US1] UI-тесты списка в `tests/ui/test_incidents_list.py`: `/incidents` без параметров — последний прогон, порядок «серьёзность ↓, время начала ↓», колонки из FR-004 (серьёзность, статус, резолюция, класс, источник, цели сокращённо, число алертов, время начала и последнего алерта, ответственный, состояние действия); каждый фильтр и их сочетание дают те же `incident_id`, что `store.list_incidents`; число найденных показано; с `HX-Request` возвращается только фрагмент таблицы (нет `<html>`), без него — полная страница; у фильтров есть GET-форма с кнопкой «показать» и `hx-get` + `hx-push-url`; пагинация — ссылки с `href`; пустой результат — сообщение и ссылка «сбросить фильтры»; некорректный параметр — предупреждение над таблицей; выбор другого прогона (`run=`) меняет список; пустая база — объяснение с командой
- [X] T021 [P] [US1] UI-тесты карточки в `tests/ui/test_incident_card.py`: `/incidents/{id}` содержит ключ группировки, цели, интервал, число алертов, серьёзность и `severity_reason`, статус, резолюцию, ответственного, действие с `rule_id`/`rule_text`/состоянием, историю, записи аудита инцидента; фрагмент алертов постранично (`alerts_page_size`) с контекстом потока; инцидент с 5000 алертов (фабрика `add_incidents`) — первая страница карточки содержит ровно `alerts_page_size` алертов и гистограмму; фрагмент вероятностей `/fragments/alerts/{run_id}/{flow_uid}/probs` — вероятности по всем классам из `verdicts.parquet` и порог из `summary.threshold`; прогон без `threshold` — порог из `model_card.json` при совпадении `detector_version`, иначе «порог неизвестен»; нет файла вердиктов — «вероятности недоступны» и код 200; SVG гистограммы без `<script>`; хронология в порядке времени с подписями «время трафика»/«время решения»; неизвестный инцидент — 404-страница со ссылкой на список

### Реализация User Story 1

- [X] T022 [US1] Расширить `store.list_incidents` в `src/mlsiem/soc/store.py` (research R9): фильтры `src_ip` (точный адрес или CIDR — отбор источников прогона через `ipaddress`, затем `IN (...)`), `assignee` (имя / `__none__` → `IS NULL`), `action_state`, `incident_ids`, `exclude_ids`; параметр `sort` из белого списка `SORTS = {"severity": SEVERITY_RANK_SQL, "first_seen": "i.first_seen_ms", "last_seen": "i.last_seen_ms", "n_alerts": "i.n_alerts"}` и `direction`; при `sort=None` — порядок 002 без изменений; в строках списка поле `assignee` (зависит от T018)
- [X] T023 [US1] Добавить в `src/mlsiem/soc/store.py` чтение для карточки: `alert_histogram(conn, incident_id, bins=40) -> dict` (SQL-группировка по корзинам, research R11), `incident_audit(conn, incident_id) -> list[dict]` (обёртка над `list_audit` без лимита по порядку записи), `get_run(conn, run_id) -> dict` (`NotFound`), `latest_run_id(conn) -> str | None`
- [X] T024 [US1] Реализовать `src/mlsiem/ui/views.py` (часть US1): `IncidentListView` (dataclass + `parse(query_params, runs) -> (view, warnings)` + `to_query()`), `list_page(conn, cfg, view)`, `incident_card(conn, cfg, incident_id)` (карточка + гистограмма + хронология `TimelineEvent` из data-model), `alert_probs(cfg, run, flow_uid, detector_dir)` — чтение одной строки `verdicts.parquet` через `pl.scan_parquet(...).filter(pl.col("flow_uid") == uid)`, порог по правилам research R10 (зависит от T019, T022, T023)
- [X] T025 [P] [US1] Шаблоны списка: `src/mlsiem/ui/templates/incidents.html` (форма фильтров GET с кнопкой «показать» + `hx-get="/incidents" hx-target="#incident-table" hx-push-url="true" hx-trigger="change, submit"`, кнопка «сбросить фильтры», предупреждения о непринятых фильтрах) и `src/mlsiem/ui/templates/fragments/_incident_table.html` (колонки FR-004, заголовки-ссылки сортировки с `href` и `hx-get`, бейджи, строка → ссылка на карточку, счётчик найденных, пагинация ссылками)
- [X] T026 [P] [US1] Шаблоны карточки: `src/mlsiem/ui/templates/incident.html` (сводка, объяснение серьёзности, действие с правилом и состоянием, история, аудит инцидента) и фрагменты `fragments/_alerts.html` (таблица алертов, каждый алерт — `<details>` с `hx-get` вероятностей по `toggle`, без JS — ссылка на фрагмент), `fragments/_probs.html` (классы по убыванию вероятности, порог, пометка превышения), `fragments/_histogram.html` (inline-SVG: столбики, подписи начала/конца в UTC, `<title>` с числом алертов на столбике), `fragments/_timeline.html` (лента `TimelineEvent`)
- [X] T027 [US1] Маршруты US1 в `src/mlsiem/ui/routes.py`: `GET /incidents`, `GET /incidents/{incident_id}`, `GET /fragments/incidents/{incident_id}/alerts`, `GET /fragments/alerts/{run_id}/{flow_uid}/probs`, `GET /fragments/incidents/{incident_id}/timeline`; `NotFound` → 404-страница; пустая база → пустое состояние; временная заглушка `GET /` → редирект на `/incidents` до US4 (зависит от T024, T025, T026)

**Checkpoint**: `uv run pytest tests/unit/test_store_filters.py tests/unit/test_ui_views.py tests/ui/test_incidents_list.py tests/ui/test_incident_card.py` зелёные; в браузере список фильтруется без перезагрузки, карточка открывается

---

## Phase 4: User Story 2 — Решения аналитика из консоли (Priority: P2)

**Goal**: аналитик представляется, берёт инцидент себе или назначает другого, меняет статус,
подтверждает (после явного вопроса) или отклоняет (с комментарием) действие, видит симуляцию;
конфликты, недопустимые переходы и решения не ответственным обрабатываются понятно; чужие
сайты ничего изменить не могут.

**Independent Test**: на заранее созданном инциденте пройти из консоли (`TestClient`)
назначение → в работу → подтверждение → закрытие, на другом — отклонение; проверить историю
и аудит (`by_non_assignee`), все ошибки и отказ межсайтовых запросов без изменений в базе.

### Тесты для User Story 2

- [X] T028 [P] [US2] Модульные тесты назначения в `tests/unit/test_store_assign.py`: `assign` ставит и снимает ответственного (пусто → NULL), `version + 1`, запись в `incident_history` (`field='assignee'`) и аудит `incident_assigned` с `old`/`new`/`comment` — одной транзакцией; устаревшая версия → `Conflict`; имя вне «1–64 символа, без управляющих символов» → `BadRequest`; повторное назначение того же имени → `BadRequest` «уже назначен»; назначение закрытого инцидента разрешено и не меняет статус/резолюцию; без аналитика → `BadRequest`; `change_status`, `confirm_action`, `reject_action` пишут в `details` аудита `assignee` и `by_non_assignee` (true, только если ответственный задан и не равен автору)
- [X] T029 [P] [US2] UI-тесты решений в `tests/ui/test_decisions.py`: `POST /analyst` ставит cookie и редиректит на `next` (только относительный путь — внешний `next` игнорируется); «взять себе» (`take=1`) и назначение другого имени, снятие; `in_progress` → `closed` с резолюцией и комментарием; закрытие без резолюции → 400 и сообщение, комментарий сохранён в форме; у закрытого инцидента нет формы смены статуса, но есть форма назначения; подтверждение без `ack_action` → фрагмент-вопрос с типом действия и объектом, база не изменилась; с `ack_action=1` → действие `executed`, блок симуляции и фраза «реальных изменений в сети и на хостах не было»; отклонение без комментария → 400; после решения кнопок по действию нет; повторное решение → 409 `invalid_transition` с русским текстом; устаревшая `expected_version` → 409, фрагмент с актуальным состоянием и кнопкой «повторить на новой версии», введённый комментарий сохранён; нет cookie имени → 401 и ссылка «представиться», база не изменилась; ответственный `alice`, решает `bob` без `ack_not_assignee` → фрагмент «Ответственный — alice. Всё равно продолжить?», база не изменилась; с флагом → применено, в аудите `by_non_assignee: true`; с `HX-Request` ответ — фрагменты и заголовок `HX-Trigger: incident-changed`, без него — `303` на карточку
- [X] T030 [P] [US2] UI-тесты защиты в `tests/ui/test_csrf.py` (SC-009): для каждого POST консоли (`/analyst`, `/incidents/{id}/assign`, `/incidents/{id}/status`, `/actions/{id}/confirm`, `/actions/{id}/reject`): `Origin: http://evil.example` → 403; `Sec-Fetch-Site: cross-site` → 403; без токена → 403; с токеном другой сессии → 403; с просроченным токеном (подменить время) → 403 и текст «страница устарела — обновите её»; во всех случаях содержимое `incidents`, `actions`, `incident_history`, `audit_log` не изменилось, а в логе `mlsiem.ui.security` есть предупреждение (`caplog`); корректный запрос с тем же набором полей проходит; у страниц консоли есть заголовки CSP, `X-Frame-Options: DENY`, `Referrer-Policy`
- [X] T031 [P] [US2] API-тесты дополнений в `tests/api/test_api_assign.py`: `POST /api/v1/incidents/{id}/assign` (назначить, снять, конфликт, неверное имя, без `X-Analyst` → 400); `GET /api/v1/incidents` с `src_ip`, `assignee`, `action_state`, `sort`, `dir`; неверный `src_ip` → 400 `bad_request`; поле `assignee` в списке и карточке; `event=incident_assigned` в `/audit`; `OPTIONS` на изменяющие адреса API с `Origin: http://evil.example` и `Access-Control-Request-Headers: X-Analyst` → нет `Access-Control-Allow-Origin` (research R7); все тесты `tests/api/` фичи 002 проходят без изменений

### Реализация User Story 2

- [X] T032 [US2] Реализовать в `src/mlsiem/soc/store.py` функцию `assign(conn, incident_id, analyst, assignee, expected_version, comment=None)` по data-model (проверки из T028, транзакция, история, аудит `incident_assigned`) и добавить `assignee`/`by_non_assignee` в `details` аудита в `change_status` и `_decide` — значение `assignee` читается внутри той же транзакции, что и решение (research R6) (зависит от T028)
- [X] T033 [US2] Дополнить `src/mlsiem/soc/api.py` по `contracts/api-v1-additions.md`: модель `AssignChange(assignee: str | None, comment: str | None, expected_version: int >= 1)`, `POST /incidents/{incident_id}/assign`, параметры `src_ip`, `assignee`, `action_state`, `sort`, `dir` в `GET /incidents` (порядок по умолчанию прежний), поле `assignee` в `IncidentItem`; CORS-middleware не добавлять (зависит от T022, T032)
- [X] T034 [P] [US2] Страница имени аналитика: маршруты `GET /analyst` и `POST /analyst` в `src/mlsiem/ui/routes.py`, шаблон `src/mlsiem/ui/templates/analyst.html` (поле имени с `maxlength=64`, `required`, скрытый `next`; `next` принимается только как относительный путь внутри консоли); ошибка имени — сообщение под полем (зависит от T013)
- [X] T035 [P] [US2] Фрагменты решений в `src/mlsiem/ui/templates/fragments/`: `_assign_form.html` (кнопка «взять себе», поле имени, «снять», комментарий), `_status_form.html` (только допустимые переходы из `store.TRANSITIONS`, `resolution` обязателен при «закрыт» — `required` на радиокнопках, комментарий), `_action_panel.html` (действие, правило, состояние; кнопки «подтвердить»/«отклонить» только при `proposed`; блок симуляции при `executed` с фразой «Реальных изменений в сети и на хостах не было»), `_confirm_question.html` (вопрос с типом действия и объектом + та же форма с `ack_action=1`; с JS — внутри `<dialog>`), `_not_assignee_question.html` («Ответственный — X. Всё равно продолжить?» + форма с `ack_not_assignee=1`), `_error.html` (сообщение `store` рядом с формой, для `conflict` — актуальное состояние и «повторить на новой версии»); все формы — `method="post"` с `action`, скрытыми `csrf_token` и `expected_version`, плюс `hx-post`/`hx-target`/`hx-swap`; введённые значения возвращаются в форму при ошибке
- [X] T036 [US2] POST-маршруты в `src/mlsiem/ui/routes.py` по `contracts/ui.md`: `/incidents/{id}/assign`, `/incidents/{id}/status`, `/actions/{action_id}/confirm`, `/actions/{action_id}/reject` — зависимость `require_csrf`; нет имени → 401 + фрагмент «представьтесь»; логика `ack_action` и `ack_not_assignee` (ответственный читается свежим из `store.get_incident`, а не из формы); вызов функций `store`; `StoreError` → статус по `api.STATUS_BY_CODE` и `_error.html` с сохранёнными полями; успех — фрагменты карточки + `HX-Trigger: incident-changed` при `HX-Request`, иначе `303` на карточку; карточка из US1 подключает формы и перерисовывает хронологию/историю по событию `incident-changed` (зависит от T032, T034, T035)
- [X] T037 [US2] Дополнить `src/mlsiem/ui/static/console.js`: открытие `<dialog>` для фрагментов-вопросов (подтверждение действия, не ответственный) по событию `htmx:afterSwap`; подстановка `X-CSRF-Token` из `data-csrf` на `<body>` (дублирует `hx-headers` для старых браузеров); без inline-скриптов (зависит от T035, T036)

**Checkpoint**: тесты T028–T031 зелёные, тесты 002 зелёные; в браузере весь путь US2
(quickstart §3–4) проходит

---

## Phase 5: User Story 3 — Подсказки о подозрительных источниках (Priority: P3)

**Goal**: инциденты с источниками из сетей жертв/фона или с источником, который сам цель
в других инцидентах прогона, помечены в списке и карточке, с объяснением и фильтром; метка
ничего не меняет в инциденте.

**Independent Test**: на синтетике с заданными сетями проверить метки и объяснения, фильтры
`flagged=only|hide`; на реальном прогоне 002 (slow) — ровно 14 из 66 инцидентов с метками сетей.

### Тесты для User Story 3

- [X] T038 [P] [US3] Модульные тесты меток в `tests/unit/test_soc_flags.py`: источник в сети `victims` → метка `network` с названием и CIDR в объяснении; `background` → тоже; `infrastructure`/`other` → нет метки; адрес в двух сетях → две метки; источник встречается в `targets` другого инцидента прогона → `target_elsewhere` со списком `incident_id` (не более 10 в объяснении + «ещё N»), свой собственный инцидент не считается; инциденты другого прогона не учитываются; IPv6; пустой список сетей → только `target_elsewhere`; функция чистая — вход не меняется, серьёзность/статус/действие не трогаются (FR-020)
- [X] T039 [P] [US3] UI- и API-тесты меток в `tests/ui/test_flags_ui.py`: бейджи меток в строках списка и в карточке с текстом объяснения и ссылками на связанные инциденты; `/incidents?flagged=only` и `flagged=hide` дают дополняющие друг друга множества, в сумме — все инциденты прогона; `GET /api/v1/incidents?flagged=only` и поле `flags` в списке и карточке API; у помеченного инцидента обычные формы решений (закрытие как «ложное срабатывание» работает по одному)
- [X] T040 [P] [US3] Медленный тест на реальном прогоне в `tests/ui/test_flags_real.py` (`@pytest.mark.slow`, пропуск если нет `var/soc.db` с прогоном 002): в прогоне с 66 инцидентами метки сетей стоят ровно у 14 инцидентов с источниками `149.171.126.0/24` и `59.166.0.0/24`; ни одного инцидента с источником вне этих сетей и не встречающимся среди целей не помечено (SC-003); число меток `target_elsewhere` записывается в вывод теста для журнала

### Реализация User Story 3

- [X] T041 [US3] Реализовать `src/mlsiem/soc/flags.py` (research R8, data-model SourceFlag): dataclass `SourceFlag(kind, network_name, role, related_incidents, explanation)`, чистая функция `source_flags(incidents, networks) -> dict[str, list[SourceFlag]]`; функция `run_flags(conn, run_id, networks)` — читает `incident_id`, `src_ip`, `targets` прогона и кэширует результат в памяти по `(run_id, max(updated_at), count, networks)` (зависит от T038)
- [X] T042 [US3] Подключить метки: `flagged=only|hide` в `IncidentListView` и `list_page` в `src/mlsiem/ui/views.py` (через `incident_ids`/`exclude_ids` из T022), метки в строках списка и в карточке; в `src/mlsiem/soc/api.py` — параметр `flagged` и поле `flags: list[SourceFlag]` в `IncidentItem`/`IncidentCard` по `contracts/api-v1-additions.md` (зависит от T041)
- [X] T043 [US3] Шаблоны меток: переключатель «все / только подозрительные / скрыть подозрительные» в форме фильтров `src/mlsiem/ui/templates/incidents.html`, бейджи в `fragments/_incident_table.html`, блок «Почему помечен» с объяснением и ссылками в `incident.html`; текст «метка — подсказка, серьёзность и действие не изменены» (зависит от T042)

**Checkpoint**: тесты T038–T039 зелёные; `uv run pytest -m slow -k flags_real` на реальном прогоне — 14 из 66

---

## Phase 6: User Story 4 — Обзорная панель и живое обновление (Priority: P4)

**Goal**: стартовая страница со сводкой прогона и кликабельными счётчиками, лента последних
алертов; панель, список и баннер нового прогона обновляются сами, не ломая ввод; при
недоступности сервиса видно, что данные могли устареть.

**Independent Test**: счётчики панели совпадают с API, клик по счётчику даёт список ровно из
этого числа инцидентов; опрашиваемые фрагменты отвечают `204` без изменений и новым
содержимым после изменения; новый прогон даёт баннер, но не меняет выбранный прогон.

### Тесты для User Story 4

- [X] T044 [P] [US4] Модульные тесты сводки в `tests/unit/test_store_dashboard.py`: `dashboard_summary(conn, run_id)` — `by_status`, `by_severity`, `by_class`, `actions_pending`, `unassigned` («`assignee IS NULL` и статус не `closed`»), совпадают с ручным подсчётом по `list_incidents`; `recent_alerts(conn, run_id, n)` — `n` алертов по `first_seen_ms` ↓ со ссылкой на `incident_id`; прогон без инцидентов — нули; `list_state(conn, run_id)` для ETag меняется после любого решения и не меняется без них
- [X] T045 [P] [US4] UI-тесты панели в `tests/ui/test_dashboard.py`: `/` показывает счётчики по статусу, серьёзности, классу, «ждут решения», «без ответственного», «подозрительный источник» и сводку прогона; для **каждого** счётчика переход по его ссылке даёт на `/incidents` ровно это число найденных (SC-004); лента последних алертов (`ui.recent_alerts` строк) со ссылками на инциденты; пустая база — объяснение с командой; прогон без инцидентов — нули и сообщение
- [X] T046 [P] [US4] UI-тесты обновления в `tests/ui/test_refresh.py`: опрашиваемые контейнеры (таблица списка, счётчики, лента алертов, баннер, штамп карточки) имеют `hx-trigger="every {refresh_seconds}s"` из конфига, а формы решений в эти контейнеры не входят (FR-024); фрагмент таблицы с `If-None-Match` текущего ETag → `204`, после смены статуса инцидента → `200` с новым ETag; `/fragments/runs-banner?run=<старый>` после второго `run_chain` → баннер «появился новый прогон … — переключиться» со ссылкой, при текущем последнем — пусто; `/fragments/incidents/{id}/stamp?v=&av=` при совпадении версий — пусто, после изменения инцидента или действия — полоса «инцидент изменён — обновить»; на `/` без параметра `run` после нового прогона выбранный прогон в опрашиваемых фрагментах остаётся прежним (он зашит в `hx-get`)

### Реализация User Story 4

- [X] T047 [US4] Добавить в `src/mlsiem/soc/store.py`: `dashboard_summary(conn, run_id)`, `recent_alerts(conn, run_id, n)` (индекс `ix_alerts_run_time`), `list_state(conn, run_id) -> str` (хеш от `count(*)`, `max(updated_at)`, `max(actions.version)` прогона и `max(entry_id)` аудита — основа ETag), `incident_versions(conn, incident_id) -> (version, action_version)` (зависит от T044)
- [X] T048 [US4] Панель в `src/mlsiem/ui/views.py`: `dashboard(conn, cfg, run_id)` — сводка + `flagged` из `run_flags` + для каждого счётчика готовый `IncidentListView` (например, `unassigned` → `assignee=__none__&status=new,in_progress`, `actions_pending` → `action_state=proposed`, `flagged` → `flagged=only`); ETag фрагмента списка = хеш `(list_state, view.to_query())` (зависит от T041, T047)
- [X] T049 [P] [US4] Шаблоны панели: `src/mlsiem/ui/templates/dashboard.html`, `fragments/_dashboard_counters.html` (счётчики-ссылки с `href`), `fragments/_recent_alerts.html`, `fragments/_runs_banner.html` (кнопка «переключиться» = ссылка с `run=`), `fragments/_stamp.html` (полоса «инцидент изменён другим аналитиком — обновить»); опрос `hx-get` + `hx-trigger="every {{ refresh }}s"` + `hx-swap="outerHTML"` только на этих контейнерах и на таблице списка
- [X] T050 [US4] Маршруты US4 в `src/mlsiem/ui/routes.py`: `GET /` (панель, вместо временного редиректа из T027), `GET /fragments/dashboard`, `GET /fragments/recent-alerts`, `GET /fragments/runs-banner`, `GET /fragments/incidents/{id}/stamp`; ETag/`If-None-Match` → `204` для фрагмента таблицы `/incidents` и счётчиков; подключить баннер в `base.html` и штамп в `incident.html` (зависит от T048, T049)
- [X] T051 [US4] Дополнить `src/mlsiem/ui/static/console.js` и `console.css`: полоса «данные могут быть устаревшими» по `htmx:sendError`/`htmx:responseError` (кроме 4xx от форм), снятие по первому успешному `htmx:afterRequest`; `204` не меняет DOM (штатно для htmx 2 — проверить и отметить в комментарии); открытые `<details>` и прокрутка сохраняются при обмене таблицы (`hx-preserve` или `id`-стабильные элементы) (зависит от T050)

**Checkpoint**: тесты T044–T046 зелёные; в браузере quickstart §6 — баннер нового прогона
≤ 15 с, полоса «данные устарели» при остановленном сервере

---

## Phase 7: User Story 5 — Журнал аудита (Priority: P5)

**Goal**: отдельная страница аудит-журнала с фильтрами, новые сверху, события и детали на
русском, переход к инциденту, без возможности изменить или удалить запись.

**Independent Test**: после нескольких решений открыть `/audit`, отфильтровать по аналитику,
событию и инциденту и сверить с `GET /api/v1/audit`.

### Тесты для User Story 5

- [X] T052 [P] [US5] UI-тесты журнала в `tests/ui/test_audit_page.py`: `/audit` — записи новые сверху, у каждой время UTC, автор, событие по-русски, инцидент (ссылка), действие, детали по-русски (изменения статуса «новый → в работе», назначения, симуляция, пометка «не ответственный»); фильтры `actor`, `event` (включая `incident_assigned`), `incident`, `run` — результат совпадает с `store.list_audit`; неизвестное событие — предупреждение, фильтр не применён; пагинация ссылками; на странице нет форм и кнопок изменения/удаления; `POST`/`DELETE` на `/audit` → 405

### Реализация User Story 5

- [X] T053 [US5] Добавить в `store.list_audit` в `src/mlsiem/soc/store.py` параметр `newest_first: bool = False` (API 002 сохраняет прежний порядок) и фильтр `run_id` (уже есть — проверить) (зависит от T052)
- [X] T054 [US5] Страница журнала: маршрут `GET /audit` в `src/mlsiem/ui/routes.py`, разбор параметров во `src/mlsiem/ui/views.py` (`AuditView` с предупреждениями, как у списка), шаблоны `src/mlsiem/ui/templates/audit.html` и `fragments/_audit_table.html` (фильтры GET-формой + `hx-get`/`hx-push-url`, детали по типу события через подписи `labels`) (зависит от T053)

**Checkpoint**: тест T052 зелёный; в браузере quickstart §7 проходит

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: сквозные проверки безопасности и работы без JS, производительность, сквозной
тест, документация, журнал

- [X] T055 [P] Сквозные проверки страниц в `tests/ui/test_pages_safety.py`: для всех страниц (`/`, `/incidents`, карточка, `/audit`, `/analyst`) — нет `<script>` без `src` и атрибутов `on*`; все `<script src>`/`<link href>` — только `/static/...`; у каждой формы есть `method` и `action`, у каждой ссылки пагинации/сортировки/счётчика — `href` (FR-032); имя аналитика `<script>alert(1)</script>` и такой же комментарий выводятся экранированными в шапке, истории, хронологии и журнале (SC-007, FR-029); длинные цели (200 адресов) сокращены; SHA-256 `static/vendor/htmx.min.js` совпадает с `static/vendor/README.md` (research R3)
- [X] T056 [P] Медленный тест скорости в `tests/ui/test_ui_perf.py` (`@pytest.mark.slow`, копия `var/soc.db` во временный каталог): панель, `/incidents` с каждым фильтром и их сочетанием, карточка самого большого инцидента, фрагмент алертов и вероятностей — каждый ответ < 1 с (SC-001); времена печатаются для журнала
- [X] T057 Сквозной интеграционный тест `tests/integration/test_console_chain.py`: `synthetic_split` → `tiny_detector` → `run_chain` → консоль через `TestClient`: панель → счётчик → список → карточка → «взять себе» → «в работу» → подтверждение действия с вопросом → закрытие → журнал показывает все решения с автором; второй `run_chain` → баннер нового прогона; всё без обращения к `/api/v1`
- [X] T058 [P] Обновить `README.md`: раздел фичи 003 — запуск `uv run mlsiem soc serve`, адреса консоли и API, как представиться, что значат метки подозрительных источников, где настроить сети и интервал обновления (`configs/soc.yaml`), что консоль работает только локально и без интернета
- [X] T059 [P] Прогнать `uv run ruff check src tests` и `uv run ruff format --check src tests`, исправить замечания
- [X] T060 Пройти `quickstart.md` целиком на реальной базе 002 во встроенном браузере (разделы 1–9, включая два окна, остановку сервера, отключённый JS и `curl` с чужим `Origin`); зафиксировать время ответов, число помеченных инцидентов, найденные проблемы интерфейса
- [X] T061 Записать итоги фичи 003 в `docs/JOURNAL.md`: что сделано, решения (htmx вендоринг, миграция схемы 2, CSRF, метки), цифры (время ответов, 14/66 меток, число `target_elsewhere`), проверка SC-001…SC-009, что отложено (исправление группировки по направлению — задача детекции, массовые операции, Playwright-тесты)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: без зависимостей; T003 ждёт разрешения владельца на скачивание
- **Foundational (Phase 2)**: после Setup — блокирует все истории
- **US1 (Phase 3)**: после Foundational
- **US2 (Phase 4)**: после Foundational; формы встраиваются в карточку US1 (T036 зависит от T026/T027), модульные тесты и `store.assign` (T028, T032) можно делать параллельно с US1
- **US3 (Phase 5)**: после US1 (фильтры `incident_ids`/`exclude_ids` из T022, шаблоны списка и карточки); `flags.py` и его тест (T038, T041) — параллельно с US1/US2
- **US4 (Phase 6)**: после US1 (список, ETag таблицы) и US3 (счётчик «подозрительный источник» — `run_flags`); сводка `store` (T044, T047) — параллельно
- **US5 (Phase 7)**: после Foundational; от US2 зависят только проверки событий решений в T052
- **Polish (Phase 8)**: после всех историй

### User Story Dependencies

```text
Setup → Foundational → US1 → US2
                        ├──→ US3 → US4
                        └──────────→ US5 (нужен только фундамент)
```

Независимость историй — в проверке: каждая проверяется своими тестами на временной БД
с прогоном на синтетике. Консоль без US2 — рабочий просмотрщик; без US3/US4/US5 — рабочая
консоль решений.

### Within Each User Story

- Тесты пишутся первыми и падают до реализации
- `store` → `views` → шаблоны → маршруты → `console.js`
- Медленные тесты и ручная проверка в браузере — в конце истории

### Parallel Opportunities

- Setup: T002–T004 параллельно
- Foundational: тесты T005–T008 параллельно; T010, T012, T013, T014, T016 параллельно
- US1: тесты T018–T021 параллельно; шаблоны T025 и T026 параллельно
- US2: тесты T028–T031 параллельно; T034 и T035 параллельно
- US3: тесты T038–T040 параллельно; T038 + T041 можно вести параллельно с US1/US2
- US4: тесты T044–T046 параллельно
- US5: T052 параллельно с US4
- Polish: T055, T056, T058, T059 параллельно

---

## Parallel Example: User Story 1

```bash
# Тесты US1 одновременно:
Task: "Модульные тесты фильтров в tests/unit/test_store_filters.py"
Task: "Модульные тесты видов в tests/unit/test_ui_views.py"
Task: "UI-тесты списка в tests/ui/test_incidents_list.py"
Task: "UI-тесты карточки в tests/ui/test_incident_card.py"

# Шаблоны US1 одновременно:
Task: "Шаблоны списка incidents.html и _incident_table.html"
Task: "Шаблоны карточки incident.html, _alerts, _probs, _histogram, _timeline"
```

## Parallel Example: User Story 2

```bash
Task: "Модульные тесты назначения в tests/unit/test_store_assign.py"
Task: "UI-тесты решений в tests/ui/test_decisions.py"
Task: "UI-тесты защиты в tests/ui/test_csrf.py"
Task: "API-тесты дополнений в tests/api/test_api_assign.py"

Task: "Страница имени аналитика analyst.html"
Task: "Фрагменты решений _assign_form, _status_form, _action_panel, вопросы, _error"
```

---

## Implementation Strategy

### MVP First (User Story 1)

1. Phase 1 Setup → Phase 2 Foundational (миграция базы, безопасность, каркас)
2. Phase 3 US1: список с фильтрами и карточка в браузере
3. **STOP and VALIDATE**: `uv run pytest`; `uv run mlsiem soc serve` → список реального прогона
   фильтруется без перезагрузки, карточка открывается, тесты 002 зелёные

Просмотрщик уже заменяет чтение JSON; «консоль SOC» в полном смысле — US1 + US2.

### Incremental Delivery

1. Setup + Foundational → консоль открывается, база мигрирована
2. US1 → просмотр инцидентов (MVP)
3. US2 → решения аналитика из браузера (консоль SOC)
4. US3 → находка 002 видна и разбирается за минуты
5. US4 → панель и живое обновление (демо)
6. US5 → журнал аудита
7. Polish → безопасность, скорость, сквозной тест, quickstart, журнал

---

## Notes

- [P] — разные файлы, нет зависимостей от незавершённых задач
- `src/mlsiem/soc/store.py`, `src/mlsiem/soc/api.py`, `src/mlsiem/ui/routes.py`,
  `src/mlsiem/ui/views.py` и `console.js` правятся в нескольких историях — задачи над ними
  не параллелятся между собой
- Скачивание htmx (T003) — только после явного разрешения владельца
- Коммитит владелец; после каждой логической группы задач — готовое название коммита
- На каждой контрольной точке история проверяется отдельно
