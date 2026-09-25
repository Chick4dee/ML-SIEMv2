# Контракт: добавления в API `/api/v1` (фича 004)

Только добавления (FR-018): существующие пути, параметры, поля и коды ошибок 002/003 не
меняются. Клиенты 002/003 новые поля игнорируют. Для прогонов до 004 новые поля — `null`.

## Алерт — `GET /incidents/{id}/alerts`

Новые поля каждого элемента `items[]`:

| Поле | Тип | Смысл |
|---|---|---|
| `attacker_ip` | str \| null | атакующая сторона (research R8); у старых прогонов = `src_ip` |
| `victim_ip` | str \| null | вторая сторона; у старых = `dst_ip` |
| `reversed` | bool | поток признан ответным; `src_*`/`dst_*` — как в потоке |
| `experts` | object \| null | `{имя: {score, threshold, fired}}`; `null` — прогон до ансамбля |
| `fired_experts` | list[str] \| null | сработавшие эксперты; `[]` — алерт поднят только мета-слоем |
| `explanation` | str \| null | объяснение итогового вердикта по-русски |

## Карточка инцидента — `GET /incidents/{id}`

Новое поле:

```json
"experts_summary": {
  "available": true,
  "by_expert": {"classifier": 120, "anomaly": 7},
  "combinations": [
    {"experts": ["classifier"], "n_alerts": 113},
    {"experts": ["anomaly", "classifier"], "n_alerts": 7},
    {"experts": [], "n_alerts": 0}
  ],
  "note": "алерт, поднятый несколькими экспертами, учитывается у каждого в by_expert"
}
```

Для прогона до ансамбля: `{"available": false, "note": "прогон сделан до появления ансамбля
(один детектор <версия>)"}`.

## Прогоны — `GET /runs`

Новое поле элемента: `model` — `{kind: "detector"|"ensemble", version, selected, experts:
{имя: версия}}`. Для старых прогонов: `{kind: "detector", version: <detector_version>,
selected: null, experts: null}`.

## Фильтр класса — `GET /incidents?attack_class=`

Принимает `anomaly` наравне с классами атак (список допустимых — ключи `severity.base`
конфига). Сортировки и остальные фильтры — без изменений.

## Ошибки

Новых кодов нет. Прогон с повреждённым/отсутствующим `verdicts.parquet` не ломает ответы:
блоки экспертов берутся из SQLite (`experts`, `fired_experts`), а не из parquet.
