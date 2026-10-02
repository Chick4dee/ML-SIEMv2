# Data Model: Лабораторный стенд и живой сенсор (006)

Опирается на data-model 005 (сообщения Kafka, сеансы `runs`, `stream_stats`, миграции). Здесь —
только новое и изменённое. Ссылки на 005: [../005-kafka-streaming-chain/data-model.md](../005-kafka-streaming-chain/data-model.md).

## Машины стенда (конфиг, не БД)

Описываются в `configs/stream.yaml`, раздел `lab`. В хранилище не живут.

| Поле | Пример | Смысл |
|---|---|---|
| `lab_subnet` | `10.88.0.0/24` | подсеть сети стенда `mlsiem-lab` |
| `victim.ip` / `victim.vm` | `10.88.0.20` / `mlsiem-victim` | адрес и имя ВМ жертвы |
| `victim.services` | `[web, ssh, ftp, dns]` | службы жертвы (R4) |
| `attacker.ip` / `attacker.vm` | `10.88.0.30` / `mlsiem-attacker` | адрес и имя ВМ атакующего |
| `attacker.mgmt` | `powershell-direct` | канал управления (R6), `com` — fallback |
| `sensor.placement` | `broker` / `vm` | сенсор на брокерной ВМ (R7) или отдельной (R7a) |
| `sensor.iface` | `eth1` | интерфейс-приёмник зеркала в гостевой ОС |
| `sensor.pcap_limit_gb` | `5` | лимит записи pcap сеанса (R12) |
| `sensor.buffer_flows` | `3000` | размер буфера отправки при отказе брокера (R10) |
| `clock_skew_max_s` | `1` | допустимое расхождение часов (R13) |
| `lab_mac.*` | `00:15:5D:4D:00:20…` | постоянные MAC адаптеров (как 005) |

## Сценарии и фоновая норма (конфиг)

`configs/stream.yaml`, раздел `scenarios` — список записей (R11):

| Поле | Смысл |
|---|---|
| `name` | имя сценария (`port_scan`, `web_fuzz`, `ssh_bruteforce`, `web_dos`, `control_replay`, `background_normal`) |
| `version` | версия сценария (привязка набора) |
| `tool` | инструмент (`nmap`, `ffuf`, `hydra`, `slowhttptest`, `tcpreplay`, `normal`) |
| `args` | шаблон аргументов (цель подставляется из `lab`) |
| `target` | служба жертвы (`web`/`ssh`/`ftp`/`dns`) |
| `expected_class` | класс таксономии UNSW или `out_of_taxonomy`; для нормы `benign` |
| `rate_limit` / `duration_limit_s` | ограничения (Edge «Шторм пакетов») |
| `catch_threshold` | порог поимки для разбора R16 |

Контрольный сценарий (`control_replay`) дополнительно: `pcap` (артефакт стенда), `src_map`/
`dst_map` (подмена адресов на `lab`).

## Запуск сценария — запись журнала (на машине, забирается хостом)

Журнал сценариев — JSONL-файл на атакующей машине, строка на запуск (FR-014):

| Поле | Смысл |
|---|---|
| `run_uid` | идентификатор запуска сценария |
| `name`, `version` | сценарий и версия |
| `attacker_ip`, `targets` | атакующий адрес и цели |
| `expected_class` | ожидаемый класс (или `benign` для нормы) |
| `started_at`, `ended_at` | начало/конец по часам сенсора (UTC) |
| `outcome` | `completed` / `aborted` / `rejected` |
| `reject_reason` | если `rejected` (цель вне стенда, параллельный запуск) |

Журнал — вход для разметки набора (R12). Фоновая норма пишет такие же записи с
`expected_class=benign`.

## Сеанс живого сенсора — строка `runs` (расширение 005)

Источник (`source`/`source_id`) = `sensor:live` (термины 005). Статусы и переходы — как 005
(FR-018): `running` ↔ перезапуск (тот же сеанс), `stopped`/`completed` — явной командой
`stream close --session`. Новое — флаг `lossy` (были потери захвата/буфера) и ссылка на запись
pcap сеанса.

## `stream_stats` — новые показатели сенсора (R17)

К строке показателей 005 добавляются (NULL для источников-проигрывателей):

| Поле | Смысл |
|---|---|
| `packets_per_s` | пакетов в секунду, которые видит сенсор |
| `flows_per_s` | завершённых потоков в секунду |
| `drops` | потерянные пакеты (libpcap/nfstream) за интервал |
| `buffer_fill` | занятость буфера отправки, доля [0,1] |
| `liveness` | метка живости (последний пакет не позже N с назад) |

## Набор стенда — `data/lab/<версия>/` (DVC)

| Артефакт | Смысл |
|---|---|
| `flows.parquet` | потоки стенда, схема признаков 001 + колонка `label` |
| `labels.parquet` / колонка `label` | `benign` / класс сценария / `ambiguous` |
| `manifest.json` | версия набора, ссылки на записи сеансов и журнал, сценарии и версии |
| `report.md` | объём, классы, интервалы, сценарии, доля `ambiguous`, потери сенсора |

Метка `ambiguous` — поток, пересекающий границу окна сценария (FR-020); из метрик исключается,
в отчёте считается. Набор не смешивается с UNSW/CTU-13 и не используется для обучения в 006
(FR-021).

## Отчёт оценки — `reports/lab_eval_<версия>.{md,json}` (R15)

| Поле | Смысл |
|---|---|
| `model`, `model_version` | модель прогона и её версия |
| `dataset_version` | версия набора стенда |
| `threshold` | порог из артефакта (не подбирается на стенде) |
| `pr_auc_macro`, `pr_auc_attack` | PR-AUC по классам набора и «атака/нет» |
| `catch_by_scenario` | доля пойманных потоков по каждому сценарию |
| `fpr_normal`, `false_incidents` | FPR и число ложных инцидентов на норме |
| `unexplained[]` | для слабых сценариев — причина R16 (вне таксономии / вне распределения / потери) |

## Миграция SQLite 5 → 6 (одна транзакция)

```
ALTER TABLE stream_stats ADD COLUMN packets_per_s REAL;
ALTER TABLE stream_stats ADD COLUMN flows_per_s   REAL;
ALTER TABLE stream_stats ADD COLUMN drops         INTEGER;
ALTER TABLE stream_stats ADD COLUMN buffer_fill   REAL;
ALTER TABLE stream_stats ADD COLUMN liveness      INTEGER;
ALTER TABLE runs         ADD COLUMN lossy         INTEGER DEFAULT 0;
-- user_version = 6
```

Источник `sensor:live` новой таблицы не требует. Перед первым запуском с миграцией — копия
рабочей `var/soc.db` (как `bak-005` в 007). Тест миграции — обновить `test_store_migration_*`
на 5 → 6; остальные ожидания не трогать (FR-027, опыт 007).
