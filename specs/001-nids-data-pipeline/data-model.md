# Data Model: Пайплайн данных NIDS (001)

## Capture (захват)

Один входной PCAP.

| Поле | Тип | Описание |
|---|---|---|
| `capture_id` | str | `unsw_22-1-2015_01`, `unsw_17-2-2015_27`, `ctu13_07`, `adhoc_<имя файла>` (без двоеточий — идёт в имя файла на Windows) |
| `source` | enum | `unsw` \| `ctu13` \| `adhoc` |
| `day` | str \| null | день захвата UNSW (`22-1-2015` / `17-2-2015`) |
| `scenario` | int \| null | номер сценария CTU-13 (1–13) |
| `family` | str \| null | семейство ботнета CTU-13 (Neris, Rbot, …) |
| `path` | path | путь к PCAP (из `configs/data.yaml`) |
| `fingerprint` | str | размер + mtime + SHA-256 первых/последних 16 МБ |
| `status` | enum | `pending` → `done` \| `failed` |

**Переходы статуса**: `pending` → `done` (результат записан атомарно);
`pending` → `failed` (ошибка чтения/нехватка ресурсов, причина в манифесте);
`done` → `pending`, если изменился отпечаток входа, версия схемы или версия правил разметки.

**Манифест захвата** (`data/flows/<source>/<capture_id>.json`): `capture_id`, `fingerprint`,
`schema_version`, `labeling_version`, `n_flows`, `n_matched`, `label_counts`,
`content_hash`, `warnings[]`, `started_at`, `finished_at`, `status`, `error`.

## Flow (поток)

Строка таблицы `data/flows/<source>/<capture_id>.parquet`. Поля делятся на группы —
группа входит в схему признаков и определяет, что можно подавать в модель.

| Группа | Поля | Роль |
|---|---|---|
| `key` | `flow_uid`, `capture_id` | идентификация строки |
| `identity` | `src_ip`, `src_mac`, `src_oui`, `src_port`, `dst_ip`, `dst_mac`, `dst_oui`, `dst_port`, `ip_version`, `vlan_id`, `tunnel_id`, `expiration_id` | сопоставление и анализ; **в модель не подаются** |
| `time` | `bidirectional_first_seen_ms`, `bidirectional_last_seen_ms`, `src2dst_first_seen_ms`, `src2dst_last_seen_ms`, `dst2src_first_seen_ms`, `dst2src_last_seen_ms` | разбиение и сопоставление; **в модель не подаются** |
| `feature` | `protocol`; `{bidirectional,src2dst,dst2src}_{duration_ms,packets,bytes}`; `{…}_{min,mean,stddev,max}_ps`; `{…}_{min,mean,stddev,max}_piat_ms`; `{…}_{syn,cwr,ece,urg,ack,psh,rst,fin}_packets` | поведенческие признаки — кандидаты для моделей (58 полей) |
| `dpi` | `application_name`, `application_category_name`, `application_is_guessed`, `application_confidence`, `requested_server_name`, `client_fingerprint`, `server_fingerprint`, `user_agent`, `content_type` | контекст nDPI; по умолчанию не признаки, решение — по итогам аудита |
| `label` | `label_raw`, `label_detail`, `label` | исходная подпись класса, подробное имя атаки (UNSW `Attack Name`), канонический класс |

Отбрасывается: `id` (зависит от внутренней нумерации nfstream, ломает детерминизм).

**Правила валидации**
- `flow_uid` уникален в пределах набора.
- `label` ∈ таксономия (см. ниже); для `adhoc` колонки группы `label` отсутствуют.
- `bidirectional_first_seen_ms` ≤ `bidirectional_last_seen_ms`.
- Для UNSW `label` не бывает `unlabeled`; для CTU-13 `benign` не выставляется по умолчанию.

## FeatureSchema (схема признаков)

Файл `src/mlsiem/data/schema.py` (+ экспорт в `data/flows/schema.json`).

| Поле | Описание |
|---|---|
| `version` | семантическая версия, стартовая `1.0.0` |
| `extractor` | `nfstream==6.6.x` и все настройки NFStreamer (R1) |
| `columns[]` | имя, тип, группа (`key`/`identity`/`time`/`feature`/`dpi`/`label`) |

Версия поднимается при любом изменении списка колонок, типов или настроек экстрактора;
все parquet хранят `schema_version` в метаданных файла и манифесте.

## Taxonomy (таксономия)

| Канонический класс | UNSW-NB15 | CTU-13 |
|---|---|---|
| `benign` | несопоставленные потоки | `normal` |
| `background` | — | `background` |
| `botnet` | — | `botnet` |
| `dos`, `exploits`, `fuzzers`, `generic`, `reconnaissance`, `analysis`, `shellcode`, `worms` | одноимённые категории | — |
| `backdoor` | `backdoor`, `backdoors` | — |
| `unlabeled` | — | поток не сопоставлен с `.binetflow` |

`labeling_version` (стартовая `1.0.0`) поднимается при изменении таблицы или правил
сопоставления (допуск, тай-брейки).

## SplitManifest (разбиение)

Файл `data/splits/<split_name>.json` + таблица `data/splits/<split_name>.parquet`
(`flow_uid`, `part`).

| Поле | Описание |
|---|---|
| `split_name` | `unsw_time` \| `unsw_cross_day` \| `ctu13_scenario` |
| `dataset` | `unsw` \| `ctu13` |
| `parts` | для каждой части: список захватов/сценариев и временные интервалы `[start_ms, end_ms)` |
| `params` | квантили (0.70 / 0.85), зазор (600 000 мс), сид, распределение сценариев |
| `excluded` | сколько потоков исключено зазором (по классам) |
| `input_hashes` | `content_hash` всех входных захватов |
| `hash` | хеш таблицы `flow_uid → part` |

**Инварианты** (проверяются автоматически, SC-006): интервалы частей внутри одного дня
не пересекаются; ни один `flow_uid` не встречается в двух частях; поток, пересекающий зону
зазора, не входит ни в одну часть; для `ctu13_scenario` сценарий целиком в одной части.

## AuditResult (проверка на артефакты)

Файл `data/audit/<split_name>.parquet`, одна строка на поле.

| Поле | Описание |
|---|---|
| `field`, `group` | имя поля и его группа по схеме |
| `variant` | `raw` \| `subnet24` (для IP) |
| `pr_auc_macro` | macro PR-AUC дерева глубины 4 на одном поле (train → val) |
| `baseline` | macro PR-AUC по доле классов |
| `lift` | `pr_auc_macro − baseline` |
| `status` | `dangerous` \| `suspicious` \| `ok` (правила — research R8) |

## DataQualityReport (отчёт)

`reports/data_quality.html` + `reports/data_quality.md`. Разделы: обзор (объёмы, версии,
хеши) → сопоставление по захватам → классы по частям разбиения и отсутствующие классы →
исключённое зазором → аудит артефактов → сверка с v1 → известные ограничения источников.

## V1Comparison (сверка с v1)

Строка на захват: `capture_id`, `n_flows_v1`, `n_flows_v2`, `rel_diff`,
доли классов v1/v2, `explained` (текст объяснения, обязателен при `rel_diff > 0.05`).
Объяснения хранятся в `configs/v1_diff_notes.yaml`, чтобы не терялись между прогонами.
