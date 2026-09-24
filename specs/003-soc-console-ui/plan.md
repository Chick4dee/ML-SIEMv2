# Implementation Plan: SOC-консоль аналитика

**Branch**: `003-soc-console-ui` | **Date**: 2026-09-24 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/003-soc-console-ui/spec.md`

## Summary

Веб-консоль аналитика поверх цепочки 002. Новый подпакет `src/mlsiem/ui` — FastAPI-роутер
с шаблонами Jinja2 и htmx 2.x (вендоринг файла, без сборки и CDN), подключённый в то же
приложение, что API 002: `mlsiem soc serve` поднимает на `127.0.0.1:8000` и консоль (`/`),
и API (`/api/v1`). Консоль вызывает `soc.store` напрямую, поэтому все правила 002 (переходы,
оптимистичная блокировка, аудит) действуют без дублирования. Хранилище получает поле
`assignee`, событие аудита `incident_assigned` и отметку `by_non_assignee` в решениях —
через миграцию схемы SQLite на версию 2 с сохранением аудита. Новый модуль `soc/flags.py`
помечает инциденты с источниками из сетей жертв/фона и источники, которые сами бывают целью.
Защита от CSRF — проверка `Origin`/`Sec-Fetch-Site` плюс подписанный токен формы. Панель,
список и баннер нового прогона обновляются опросом htmx раз в 10 с, не трогая формы.
Подробности — [research.md](research.md).

## Technical Context

**Language/Version**: Python 3.11 (как в 001–002)

**Primary Dependencies**: из 002 — FastAPI 0.141, Starlette 1.7, uvicorn, Jinja2 3.1, polars;
новые — `python-multipart` (формы), htmx 2.x как вендоринг-файл (0BSD); dev — `beautifulsoup4`

**Storage**: SQLite `var/soc.db` из 002 + миграция схемы 0 → 2 (`PRAGMA user_version`);
вероятности алертов читаются из `var/runs/<run_id>/verdicts.parquet`

**Testing**: pytest; `TestClient` + BeautifulSoup для страниц и фрагментов; маркер `slow`
для реального прогона 002; ручные сценарии в браузере — quickstart

**Target Platform**: Windows 11, локальная машина; браузер — актуальный Chromium/Firefox;
сервер слушает только `127.0.0.1`

**Project Type**: Python-пакет с CLI и локальным веб-сервисом (HTML-консоль + JSON API)

**Performance Goals**: панель, список с любыми фильтрами и карточка самого большого
инцидента (~8 тыс. алертов в прогоне, 66 инцидентов) < 1 с (SC-001); изменения видны
на открытых страницах ≤ 15 с (SC-006)

**Constraints**: без интернета во время работы (SC-008), без сборки фронтенда, без
inline-скриптов (CSP `default-src 'self'`); основные страницы читаются без JS (FR-032);
никаких реальных сетевых действий (принцип V)

**Scale/Scope**: 1–3 аналитика (окна одного браузера); десятки–сотни инцидентов и до
десятков тысяч алертов на прогон; 5 страниц, ~10 фрагментов, 5 форм

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Принцип | Как выполняется | Статус |
|---|---|---|
| I. Вертикальные срезы | Консоль подключается к работающей цепочке 002 и показывает её целиком: от прогона до решения аналитика в браузере; запуск той же командой `mlsiem soc serve`; логирование безопасности — внутри фичи | ✅ |
| II. Train = serve | Детекция не меняется; вероятности в карточке — те же, что записал прогон (`verdicts.parquet`), порог — детектора прогона | ✅ |
| III. Честная оценка | Новых моделей и метрик нет; метки подозрительных источников не выдаются за детекцию и не меняют серьёзность (FR-020); находка 002 остаётся открытой задачей детекции | ✅ (н/п) |
| IV. Решения через эксперимент | Архитектура детекции не затрагивается | ✅ (н/п) |
| V. Безопасный SOAR | Решения только через `store` 002 (подтверждение обязательно, только симуляция, аудит на вставку); дополнительный вопрос перед подтверждением; `by_non_assignee` в аудите; миграция сохраняет все записи аудита и триггеры запрета изменений; CSRF-защита не даёт чужой странице подтвердить действие | ✅ |
| VI. Воспроизводимость и понятный код | Версия htmx зафиксирована хешем с тестом; версия схемы БД; тесты на каждую страницу, форму, ошибку и миграцию; русские комментарии; запись в журнал | ✅ |
| VII. Прозрачное авторство | Коммитит владелец; новые файлы — код, шаблоны, статика; `var/` вне git | ✅ |
| Ограничения среды | CPU, без Docker/WSL2; сервер и браузер на одной машине | ✅ |
| Язык | Интерфейс, сообщения, комментарии — на русском; идентификаторы — английские | ✅ |

Нарушений нет.

**Повторная проверка после фазы 1**: контракт UI требует `expected_version`, CSRF-токен и имя
аналитика для каждого POST, а ошибки берёт из `store` (V); data-model фиксирует миграцию
аудита с сохранением `entry_id` и пересозданием триггеров (V, VI); API меняется только
добавлениями — клиенты 002 и их тесты не ломаются (I). Статус — ✅.

## Project Structure

### Documentation (this feature)

```text
specs/003-soc-console-ui/
├── plan.md                      # этот файл
├── research.md                  # решения фазы 0 (R1–R15)
├── data-model.md                # изменения хранилища, сущности консоли
├── quickstart.md                # сценарии проверки
├── contracts/
│   ├── ui.md                    # страницы, фрагменты, формы консоли
│   └── api-v1-additions.md      # добавления в API 002
├── checklists/
│   └── requirements.md
└── tasks.md                     # создаётся /speckit-tasks
```

### Source Code (repository root)

```text
configs/
└── soc.yaml                     # + networks (сети жертв/фона), ui (интервал, размеры страниц)
src/mlsiem/
├── cli.py                       # soc serve: печатает адрес консоли, миграция при старте
├── soc/
│   ├── config.py                # + NetworkConfig, UiConfig, проверка CIDR
│   ├── store.py                 # + user_version и миграция 0→2, assignee, assign(),
│   │                            #   by_non_assignee, фильтры/сортировки, сводка панели,
│   │                            #   последние алерты, гистограмма
│   ├── flags.py                 # НОВЫЙ: метки подозрительных источников (чистые функции)
│   ├── run.py                   # + threshold и classes в summary прогона
│   └── api.py                   # + параметры списка, assignee/flags в ответах,
│                                #   POST /incidents/{id}/assign, подключение ui-роутера
└── ui/                          # НОВЫЙ подпакет консоли
    ├── __init__.py
    ├── routes.py                # страницы и фрагменты (GET), формы (POST)
    ├── views.py                 # сборка данных для шаблонов: вид списка, карточка,
    │                            #   хронология, панель; разбор параметров адреса
    ├── security.py              # имя аналитика (cookie), CSRF: Origin/Sec-Fetch-Site + токен,
    │                            #   заголовки безопасности
    ├── labels.py                # русские подписи значений, фильтры Jinja (label, utc_ms, …)
    ├── templates/
    │   ├── base.html            # шапка (имя, прогон), баннеры, подключение статики
    │   ├── dashboard.html  incidents.html  incident.html  audit.html  analyst.html
    │   └── fragments/           # _incident_table, _dashboard_counters, _recent_alerts,
    │                            #   _runs_banner, _stamp, _alerts, _probs, _timeline,
    │                            #   _histogram (SVG), _status_form, _assign_form,
    │                            #   _action_panel, _confirm_question, _error
    └── static/
        ├── console.css
        ├── console.js           # полоса «данные устарели», CSRF-заголовок, диалоги
        └── vendor/
            ├── htmx.min.js
            ├── LICENSE-htmx.txt
            └── README.md        # версия и SHA-256
tests/
├── unit/                        # test_soc_flags, test_store_migration, test_store_assign,
│                                #   test_store_filters, test_ui_security, test_ui_labels,
│                                #   test_ui_views (вид списка, хронология, гистограмма)
├── ui/                          # НОВЫЙ: TestClient + BeautifulSoup — страницы, фрагменты,
│                                #   формы, ошибки, CSRF, экранирование, без JS, perf (slow)
└── api/                         # + новые параметры, assign, flags, отсутствие CORS
```

**Structure Decision**: консоль — отдельный подпакет `ui` рядом с `soc`, зависимость строго
в одну сторону `ui → soc` (store, flags, config). Ни `store`, ни `api` не знают про HTML;
`api.create_app` только подключает роутер консоли. Метки источников — в `soc/flags.py`,
а не в `ui`, потому что они нужны и API (поле `flags`). Будущие фичи (стенд, живой захват)
добавят прогоны в тот же `store`, и консоль покажет их без изменений.

## Complexity Tracking

Нарушений конституции нет.
