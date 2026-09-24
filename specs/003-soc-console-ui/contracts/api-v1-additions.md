# Контракт: дополнения API аналитика v1

Базовый контракт — [api.md фичи 002](../../002-detection-incident-chain/contracts/api.md).
Все изменения **только добавляют** параметры, поля и методы: клиенты 002 работают без
изменений, порядок по умолчанию в `GET /incidents` прежний.

## `GET /incidents` — новые параметры

| Параметр | Значения | Описание |
|---|---|---|
| `src_ip` | IP-адрес или CIDR | источник совпадает или входит в сеть; неверный формат → `400 bad_request` |
| `assignee` | имя или `__none__` | ответственный / без ответственного |
| `action_state` | `proposed,executed,rejected` (через запятую) | состояние действия |
| `flagged` | `only` \| `hide` | только / без инцидентов с метками подозрительного источника |
| `sort` | `severity`, `first_seen`, `last_seen`, `n_alerts` | ключ сортировки; без параметра — порядок 002 |
| `dir` | `asc` \| `desc` | по умолчанию `desc` для `severity`, `asc` для остальных |

Новые поля элемента списка и карточки:

```json
{
  "assignee": "vlad",
  "flags": [
    {"kind": "network", "network_name": "жертвы UNSW-NB15", "role": "victims",
     "related_incidents": [], "explanation": "источник входит в сеть «жертвы UNSW-NB15» (149.171.126.0/24)"}
  ]
}
```

## `POST /incidents/{incident_id}/assign` — новый метод

Заголовок `X-Analyst` обязателен (как у всех изменяющих запросов).

```json
{"assignee": "alice | null", "comment": "необязательно", "expected_version": 3}
```

`null` или пустая строка — снять назначение. Ответ `200` — обновлённая карточка. Ошибки:
`not_found`, `conflict` (устаревшая версия), `bad_request` (имя длиннее 64 символов, управляющие
символы, «уже назначен»).

## `GET /audit` — новые значения

- `event` принимает `incident_assigned`.
- В `details` решений (`incident_status_changed`, `action_executed`, `action_rejected`) — поля
  `assignee` и `by_non_assignee` (data-model).

## `GET /runs` — новые ключи `summary`

`threshold`, `classes` — для прогонов, сделанных после 003.

## CORS

Как и в 002, CORS-заголовки не выдаются; изменяющие запросы с `X-Analyst` с чужого сайта
браузер не отправит (preflight не проходит). Это закреплено тестом (research R7).
