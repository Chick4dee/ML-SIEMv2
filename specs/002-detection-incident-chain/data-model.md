# Data Model: Сквозная цепочка «детекция → инцидент → реагирование → API» (002)

Входные данные — сущности фичи 001 (Flow, SplitManifest, FeatureSchema); здесь описано только
новое. Времена — миллисекунды epoch UTC (как в потоках 001) либо ISO-8601 UTC для отметок
действий аналитика.

## Detector (артефакт детектора)

Каталог `models/detector/` (выход стадии DVC `train_detector`).

| Файл / поле | Описание |
|---|---|
| `model.joblib` | конвейер «предобработка → модель» победившего кандидата |
| `model_card.json` → `detector_version` | `YYYYMMDD-<хеш8>`; хеш — от конфига эксперимента и `input_hashes` |
| `candidate` | `logreg` \| `lgbm` |
| `classes` | упорядоченный список классов модели (`benign` + классы атак) |
| `threshold` | порог скора атаки `1 − P(benign)`, выбран на val |
| `features` | список 58 полей группы `feature` в порядке подачи |
| `schema_version` | версия схемы признаков 001, на которой обучен детектор |
| `data` | `split_hash` и `input_hashes` разбиения `unsw_time`, хеш `unsw_cross_day` |
| `metrics` | macro и по классам PR-AUC на val/test; precision/recall/F1 при пороге; test `unsw_cross_day` |
| `seed`, `libraries`, `git_commit`, `mlflow_run_id` | воспроизводимость |

**Правила**: загрузчик отказывает, если мажорная версия `schema_version` входного parquet
(`mlsiem.schema_version`) отличается от `model_card.schema_version`, или если во входе нет
какого-то из `features`.

## Experiment (эксперимент)

`models/detector/experiment.json` + `reports/detector_experiment.md` + runs в MLflow.

| Поле | Описание |
|---|---|
| `candidates[]` | для каждого: имя, параметры, macro PR-AUC и PR-AUC по классам на val и test, порог, время обучения |
| `prior_baseline` | macro PR-AUC «угадывания по доле классов» на val и test |
| `selection_rule` | текст правила (R4) и `winner` |
| `classes_without_examples` | по частям: классы, для которых PR-AUC не считается |
| `seed`, `config`, `data` | как в `model_card` |

## Run (прогон)

Таблица `runs` + каталог `var/runs/<run_id>/`.

| Поле | Тип | Описание |
|---|---|---|
| `run_id` | str | `YYYYMMDDTHHMMSS-<хеш6 входа>` |
| `source` | str | `split:unsw_time/test` или `pcap:<имя файла>` |
| `input_hash` | str | хеш содержимого входной таблицы потоков |
| `detector_version` | str | версия артефакта |
| `limit` | int \| null | ограничение числа потоков |
| `started_at`, `finished_at` | ISO | |
| `n_flows`, `n_alerts`, `n_incidents` | int | сводка |
| `summary` | JSON | инциденты по серьёзности, действия по типам, для разметки — сколько алертов верных |
| `warnings` | JSON | предупреждения экстрактора (обрезанный PCAP и т. п.) |

Файл `var/runs/<run_id>/verdicts.parquet`: `flow_uid`, `predicted_class`, `attack_score`,
`is_alert`, вероятности по классам; для проигрывания разбиения — ещё `true_label`
(только для сводки, в детектор не подаётся).

## Alert (алерт)

Таблица `alerts`; один алерт = один поток выше порога.

| Поле | Описание |
|---|---|
| `alert_id` | `<run_id>/<flow_uid>` |
| `run_id`, `incident_id` | принадлежность (ровно один инцидент) |
| `flow_uid`, `capture_id` | ссылка на поток 001 |
| `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol` | контекст (группа `identity` 001) |
| `first_seen_ms`, `last_seen_ms` | время потока (группа `time` 001) |
| `predicted_class`, `attack_score` | вердикт детектора |

## Incident (инцидент)

Таблица `incidents` (+ `incident_history`).

| Поле | Описание |
|---|---|
| `incident_id` | `inc-<хеш12 от run_id, src_ip, класса, first_seen первого алерта>` |
| `run_id` | прогон |
| `src_ip`, `attack_class` | ключ группировки |
| `targets` | уникальные `dst_ip` алертов (JSON, отсортирован) |
| `first_seen_ms`, `last_seen_ms` | интервал алертов |
| `n_alerts`, `max_score`, `mean_score` | сводка алертов |
| `severity` | `low` \| `medium` \| `high` \| `critical` |
| `severity_reason` | «базовый уровень класса X = …; +1 за N ≥ 100 алертов» |
| `status` | `new` \| `in_progress` \| `closed` |
| `resolution` | null \| `confirmed` \| `false_positive` (обязательна при `closed`) |
| `version` | int, растёт при каждом изменении (оптимистичная блокировка) |
| `created_at`, `updated_at` | ISO |

**Группировка**: алерты с одинаковыми `(src_ip, attack_class)` в порядке `first_seen_ms`, затем
`flow_uid`; разрыв > `window_ms` (900 000) открывает новый инцидент.

**Серьёзность**: `base[attack_class]` из конфига; `+1` уровень при `n_alerts ≥ bump_at` (100);
не выше `critical`.

**Переходы статуса**:

```
new ──► in_progress ──► closed(resolution)
 └──────────────────────► closed(resolution)
```

Допустимы `new → in_progress`, `new → closed`, `in_progress → closed`. Из `closed` переходов нет
(повторное открытие — вне объёма). `closed` без `resolution` — ошибка `bad_request`.

**История** (`incident_history`): `incident_id`, `at`, `analyst`, `field`, `old`, `new`, `comment`.

## Action (действие плейбука)

Таблица `actions`; ровно одно действие на инцидент.

| Поле | Описание |
|---|---|
| `action_id` | `act-<incident_id>` |
| `incident_id` | |
| `action_type` | `block_source_ip` \| `isolate_host` \| `observe` \| `manual_review` |
| `target` | IP-адрес объекта действия или null (`observe`, `manual_review`) |
| `rule_id`, `rule_text` | сработавшее правило плейбука |
| `state` | `proposed` \| `executed` \| `rejected` |
| `decided_by`, `decided_at`, `comment` | решение аналитика |
| `simulation` | JSON: что было бы сделано (тип, объект, описание); заполняется при `executed` |
| `version` | оптимистичная блокировка |

**Переходы**: `proposed → executed` (подтверждение = симулированное выполнение, атомарно),
`proposed → rejected`. Из `executed` и `rejected` переходов нет. `observe` и `manual_review`
тоже подтверждаются — симуляция тогда фиксирует «наблюдение продолжено» / «передано на ручной
разбор».

## AuditEntry (запись аудит-журнала)

Таблица `audit_log` — только вставка (триггеры запрещают UPDATE/DELETE).

| Поле | Описание |
|---|---|
| `entry_id` | автоинкремент |
| `at` | ISO |
| `actor` | имя аналитика или `system` (предложения плейбуков, создание инцидентов) |
| `event` | `action_proposed` \| `action_executed` \| `action_rejected` \| `incident_status_changed` \| `run_loaded` |
| `run_id`, `incident_id`, `action_id` | ссылки (могут быть null) |
| `details` | JSON: правило, объект, старое/новое значение, комментарий |

## Конфигурация

- `configs/detect.yaml` — кандидаты и их параметры, правило выбора (`min_gain` 0.01), сид,
  разбиения (`unsw_time`, `unsw_cross_day`), путь к артефакту.
- `configs/soc.yaml` — `window_ms`, `severity.base` (класс → уровень), `severity.bump_at`,
  `protected_ips` (список), `playbook.rules` (упорядоченный список правил R11), путь к БД,
  адрес и порт API.
