# Контракт: командная строка `mlsiem data`

Все команды запускаются из корня репозитория в окружении проекта:
`uv run mlsiem data <команда> [опции]`. Коды возврата: `0` — успех, `1` — ошибка входных данных
или конфигурации, `2` — часть захватов завершилась с `failed` (остальные обработаны).
Сообщения — на русском, прогресс в stderr, итоговая сводка в stdout.

## `flows` — PCAP → размеченные потоки

```
mlsiem data flows --dataset {unsw,ctu13} [--capture ID ...] [--full-hash] [--force]
```

- Без `--capture` обрабатывает все захваты датасета; с `--capture` — только указанные
  (`22-1-2015:1`, `7` и т. п.).
- Уже готовые захваты с тем же отпечатком, версией схемы и версией разметки пропускаются
  (`--force` — пересчитать).
- Выход: `data/flows/<dataset>/<capture_id>.parquet` + `.json` (манифест),
  `data/flows/<dataset>/summary.csv`.

## `extract` — неразмеченный PCAP

```
mlsiem data extract PCAP --output PATH
```

- Те же настройки экстрактора и та же схема, что у `flows`; колонок группы `label` нет.
- Выход: parquet с `schema_version` в метаданных.

## `split` — разбиение

```
mlsiem data split --name {unsw_time,unsw_cross_day,ctu13_scenario}
```

- Выход: `data/splits/<name>.json` + `data/splits/<name>.parquet`.
- После построения выполняет проверку инвариантов; нарушение → код `1`, файлы не пишутся.

## `audit` — проверка на артефакты

```
mlsiem data audit --split NAME
```

- Выход: `data/audit/<split>.parquet`; в stdout — поля со статусом `dangerous`/`suspicious`.

## `compare-v1` — сверка с v1

```
mlsiem data compare-v1 [--v1-dir PATH]
```

- По умолчанию читает `v1_processed_dir` из `configs/data.yaml`.
- Выход: `data/compare_v1.csv`; в stdout — захваты с расхождением > 5% без объяснения.

## `report` — отчёт о качестве

```
mlsiem data report [--output reports/]
```

- Собирает всё выше в `reports/data_quality.html` и `reports/data_quality.md`.

## `all` — сквозной прогон

```
mlsiem data all
```

- Эквивалент `dvc repro`: flows (оба датасета) → split (три разбиения) → audit → compare-v1 →
  report. Прерванный прогон при повторном запуске продолжается (FR-011).

# Контракт: выходной parquet потоков

- Колонки и типы — строго по `FeatureSchema` версии, записанной в метаданных файла
  (`mlsiem.schema_version`, `mlsiem.labeling_version`, `mlsiem.capture_id`).
- Строки отсортированы по ключу из research R3; `flow_uid` уникален.
- Потребители (будущие фичи) обязаны проверять `schema_version` и отказываться работать
  с несовместимой мажорной версией.

# Контракт: `configs/data.yaml`

```yaml
datasets:
  unsw:
    root: "A:/datasets/UNSW-NB15/OneDrive_2_12.06.2026"
    gt_csv: "CSV Files/NUSW-NB15_GT.csv"
    pcap_glob: "pcap files/pcaps */*.pcap"
  ctu13:
    root: "A:/datasets/CTU-13/CTU-13-Dataset"
    timezone: "Europe/Prague"
v1_processed_dir: "F:/GitHubRepos/ML-SIEM/data/processed"
split:
  quantiles: [0.70, 0.85]
  gap_ms: 600000
  ctu13_parts: {train: [1, 2, 3, 4, 5, 6, 9, 13], val: [7, 10, 11], test: [8, 12]}
audit:
  sample_per_part: 500000
  tree_depth: 4
  dangerous_lift: 0.10
  suspicious_pr_auc: 0.90
seed: 42
```
