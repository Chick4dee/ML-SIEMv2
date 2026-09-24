# Quickstart: проверка фичи 002

Сценарии, которые доказывают, что цепочка работает от начала до конца. Команды —
по [contracts/cli.md](contracts/cli.md), API — по [contracts/api.md](contracts/api.md),
форматы — по [data-model.md](data-model.md).

## Предусловия

- Готовы результаты фичи 001: `uv run dvc status` — «up to date», есть `data/flows/unsw`,
  `data/splits/unsw_time.*`, `data/splits/unsw_cross_day.*`.
- `uv sync --extra dev`.

## 1. Быстрые тесты (без датасетов)

```
uv run pytest
```

Ожидается: всё зелёное, включая интеграционный тест «синтетика → обучение → прогон → API».

## 2. Эксперимент и детектор (US1, SC-001, SC-002)

```
uv run mlsiem detect train
```

Ожидается: таблица кандидатов `logreg` и `lgbm` с macro PR-AUC на val и test; победитель выбран
по val; macro PR-AUC победителя на test выше `prior`; строка переноса на `unsw_cross_day`;
файлы `models/detector/*` и `reports/detector_experiment.md`; runs в MLflow (`uv run mlflow ui`).
Повторный запуск — те же метрики и тот же `detector_version`.

## 3. Прогон test через цепочку (US2, US3, SC-003, SC-004)

```
uv run mlsiem soc run --split unsw_time --part test
```

Ожидается: за ≤ 15 минут — `run_id`, около 282 тыс. потоков, алерты, инциденты по серьёзности
(инцидентов минимум в 10 раз меньше, чем алертов), действия по типам, доля верных алертов.
Повторный прогон на том же входе — те же инциденты, серьёзности и предложения (новый `run_id`).

## 4. API и решения аналитика (US3, US4, SC-005, SC-006)

```
uv run mlsiem soc serve
```

В другом терминале (или через `http://127.0.0.1:8000/docs`):

- `GET /api/v1/incidents?severity=critical,high` — список отвечает быстрее 1 секунды;
- открыть инцидент, `POST /actions/{id}/confirm` с `X-Analyst: vlad` — в ответе `simulation`,
  в `GET /api/v1/audit` — записи о предложении и подтверждении;
- тот же запрос без `X-Analyst` — `400`; повторное подтверждение — `409 invalid_transition`;
  запрос с устаревшим `expected_version` — `409 conflict`;
- `POST /incidents/{id}/status` `in_progress`, затем `closed` с `false_positive` — история видна
  в карточке.

## 5. Новый PCAP (US5, SC-007)

```
uv run mlsiem soc run --pcap "A:/datasets/CTU-13/CTU-13-Dataset/7/<файл>.pcap"
uv run pytest -m slow -k soc_pcap
```

Ожидается: прогон с источником `pcap:…`; признаки совпадают с `mlsiem data extract` для того же
файла; если атак не найдено — «инцидентов нет» в сводке, а не ошибка. (Детектор обучен на
UNSW-NB15, поэтому на ботнет-трафике CTU-13 его вердикты не показатель качества — сценарий
проверяет путь данных, а не точность.)

## 6. Журнал

Итоги (метрики кандидатов, победитель, перенос на другой день, число алертов/инцидентов,
время прогона) — в `docs/JOURNAL.md`.
