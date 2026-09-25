# Контракт: добавления в API и консоль (фича 005)

Только добавления (SC-008): пути, параметры и поля 002–004 не меняются. Для пакетных прогонов
новые поля имеют значения по умолчанию (`mode = batch`, `status = completed`, счётчики 0, `null`).

## API `/api/v1`

### Прогон — `GET /runs`

Новые поля элемента: `mode` (`batch` | `stream`), `status` (`running` | `stopped` | `completed`),
`source_id` (str | null), `last_activity_at` (str | null).

### Инцидент — `GET /incidents`, `GET /incidents/{id}`

Новые поля: `merged_into` (str | null), `alerts_after_decision` (int), `first_after_decision_ms`
(int | null). Новый параметр списка `after_decision=only` — только инциденты с новыми алертами
после решения.

### `GET /stream/status` (новый, только чтение)

```json
{
  "broker": {"reachable": true, "checked_at": "…"},
  "consumer": {"alive": true, "holder": "HOST:1234", "renewed_at": "…"},
  "sessions": [
    {"run_id": "stream-3f2a…", "status": "running", "source_id": "replay:…",
     "processed": 120000, "lag_messages": 35, "lag_seconds": 0.8,
     "latency_p50_ms": 180, "latency_p95_ms": 900, "rejected": 0, "late": 0,
     "rate_per_s": 2400, "last_activity_at": "…"}
  ]
}
```

Изменяющих методов для потока нет: закрытие сеанса — только CLI.

## Консоль

| Место | Что добавляется |
|---|---|
| Выбор прогона в шапке | у сеансов значок «поток» и статус («идёт», «остановлен», «завершён») |
| Панель | блок «Поток» для сеанса: статус, потоков/с, отставание, задержка p50/p95, отвергнутые, опоздавшие, последняя активность; опрос 10 с |
| Список инцидентов | фильтр «новые алерты после решения»; значок у таких инцидентов; поглощённые скрыты по умолчанию, фильтр «показать объединённые» |
| Карточка | пометка «новые алерты после решения: N, первый — <время UTC>»; у поглощённого — «объединён с <ссылка>»; в хронологии — события `incident_updated`, `incident_merged`, `action_reproposed` по-русски |
| Детали алерта | вероятности читаются и из каталога вердиктов сеанса (`verdicts/part-*.parquet`) |

Подписи — по-русски, без inline-скриптов и стилей, CSRF и CSP как в 003.
