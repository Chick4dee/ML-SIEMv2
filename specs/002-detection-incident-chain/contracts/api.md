# Контракт: API аналитика (v1)

Базовый адрес: `http://127.0.0.1:8000/api/v1`. Формат — JSON, UTF-8. Интерфейс доступен
только локально; аутентификации нет. Изменяющие запросы (`POST`) требуют заголовок
`X-Analyst: <имя>` (непустой), иначе `400 bad_request`.

## Ошибки

```json
{"error": "not_found | invalid_transition | conflict | bad_request", "message": "по-русски"}
```

| Код HTTP | `error` | Когда |
|---|---|---|
| 400 / 422 | `bad_request` | нет `X-Analyst`, неверные параметры, `closed` без резолюции |
| 404 | `not_found` | нет прогона/инцидента/действия |
| 409 | `invalid_transition` | недопустимый переход статуса или повторное решение по действию |
| 409 | `conflict` | `expected_version` не совпал с текущей версией (изменено кем-то ещё) |

## Инциденты

### `GET /incidents`

Параметры: `status`, `severity` (можно несколько через запятую), `attack_class`, `run_id`,
`from_ms`, `to_ms` (пересечение с интервалом инцидента), `limit` (по умолчанию 50, максимум 500),
`offset`. Порядок: серьёзность по убыванию, затем `first_seen_ms` по возрастанию, затем `incident_id`.

```json
{
  "total": 137,
  "items": [
    {
      "incident_id": "inc-3f9a1c0b2e7d", "run_id": "20260924T101500-a1b2c3",
      "src_ip": "175.45.176.1", "attack_class": "exploits", "targets": ["149.171.126.18"],
      "first_seen_ms": 1424242234000, "last_seen_ms": 1424243100000,
      "n_alerts": 312, "severity": "critical", "status": "new", "resolution": null,
      "action": {"action_type": "isolate_host", "target": "149.171.126.18", "state": "proposed"},
      "version": 1
    }
  ]
}
```

### `GET /incidents/{incident_id}`

Карточка: все поля списка + `severity_reason`, `max_score`, `mean_score`, полное действие
(`action_id`, `rule_id`, `rule_text`, `state`, `decided_by`, `decided_at`, `comment`,
`simulation`, `version`) и `history[]` (`at`, `analyst`, `field`, `old`, `new`, `comment`).

### `GET /incidents/{incident_id}/alerts?limit=&offset=`

`{"total": N, "items": [alert...]}`; поля алерта — как в data-model (Alert), порядок по
`first_seen_ms`, затем `flow_uid`.

### `POST /incidents/{incident_id}/status`

```json
{"status": "in_progress | closed", "resolution": "confirmed | false_positive | null",
 "comment": "необязательно", "expected_version": 1}
```

Ответ `200` — обновлённая карточка. Ошибки: `invalid_transition`, `conflict`, `bad_request`.

## Действия

### `POST /actions/{action_id}/confirm`

```json
{"comment": "необязательно", "expected_version": 1}
```

Переводит `proposed → executed`, записывает симуляцию и аудит атомарно. Ответ — действие
с заполненным `simulation`. Никаких реальных сетевых операций.

### `POST /actions/{action_id}/reject`

```json
{"comment": "обязательно", "expected_version": 1}
```

`proposed → rejected`. Пустой комментарий — `bad_request`.

## Аудит-журнал

### `GET /audit?incident_id=&actor=&event=&limit=&offset=`

`{"total": N, "items": [{"entry_id", "at", "actor", "event", "run_id", "incident_id", "action_id", "details"}]}`,
порядок по `entry_id`. Изменить или удалить записи через API нельзя (методов нет).

## Прогоны

### `GET /runs`

Список прогонов со сводкой (data-model, Run), новые сверху.

## Служебное

### `GET /health`

`{"status": "ok", "detector_version": "...", "db": "var/soc.db"}`.
