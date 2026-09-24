# Контракт: командная строка `mlsiem detect` и `mlsiem soc`

Запуск из корня репозитория: `uv run mlsiem <группа> <команда> [опции]`. Коды возврата —
как в 001: `0` успех, `1` ошибка входных данных/конфига/ресурсов, `2` прогон выполнен
частично (например, PCAP прочитан до обрыва — предупреждение, но не ошибка: код `0`).
Прогресс — в stderr, итоговая сводка — в stdout, сообщения на русском.

## `detect train` — эксперимент и выбор детектора

```
mlsiem detect train [--config configs/detect.yaml]
```

- Обучает кандидатов на train `unsw_time`, подбирает порог на val, считает метрики на val/test,
  выбирает победителя по правилу (research R4), оценивает его на test `unsw_cross_day`.
- Отказ (код `1`), если разбиения 001 нет или захваты не `done`.
- Выход: `models/detector/model.joblib`, `models/detector/model_card.json`,
  `models/detector/experiment.json`, `reports/detector_experiment.md`; runs в MLflow (`mlruns/`).
- stdout: таблица кандидатов (macro PR-AUC val/test, порог, F1), победитель и причина выбора,
  перенос на `unsw_cross_day`.

## `soc run` — проигрывание данных через цепочку

```
mlsiem soc run --split unsw_time --part test [--limit N]
mlsiem soc run --pcap FILE
```

- Загружает детектор (проверка версии схемы, FR-007), выносит вердикты, создаёт алерты,
  инциденты и предложения плейбуков, записывает прогон в `var/soc.db` одной транзакцией.
- `--limit N` — первые N потоков по времени начала.
- `--pcap` — признаки извлекаются экстрактором 001 (та же схема), затем тот же путь.
- stdout: `run_id`, потоков, алертов, инцидентов по серьёзности, действий по типам; для
  проигрывания размеченных данных — доля верных алертов.

## `soc serve` — API для аналитика

```
mlsiem soc serve [--port 8000]
```

- Поднимает API на `127.0.0.1:<port>` поверх `var/soc.db`. Контракт — [api.md](api.md).

## `soc status` — что лежит в хранилище

```
mlsiem soc status
```

- stdout: список прогонов (`run_id`, источник, время, детектор, число инцидентов по статусам).

# Контракт: конфиги

`configs/detect.yaml`:

```yaml
split: unsw_time
transfer_split: unsw_cross_day
seed: 42
selection:
  metric: macro_pr_auc_val
  min_gain: 0.01          # меньше — выбираем бейзлайн
candidates:
  logreg: {C: 1.0, max_iter: 1000, class_weight: balanced}
  lgbm: {n_estimators: 400, learning_rate: 0.05, num_leaves: 63, class_weight: balanced}
output: models/detector
```

`configs/soc.yaml`:

```yaml
db: var/soc.db
runs_dir: var/runs
api: {host: 127.0.0.1, port: 8000}
grouping: {window_ms: 900000}
severity:
  bump_at: 100
  base:
    reconnaissance: low
    analysis: low
    fuzzers: medium
    generic: medium
    dos: medium
    exploits: high
    shellcode: high
    backdoor: high
    worms: high
protected_ips: []
playbook:
  rules:               # первое подходящее правило срабатывает
    - {id: protected, when: {protected: true}, action: manual_review}
    - {id: intrusion_single_target, when: {class_in: [exploits, shellcode, backdoor, worms], max_targets: 1}, action: isolate_host}
    - {id: intrusion_many_targets, when: {class_in: [exploits, shellcode, backdoor, worms]}, action: block_source_ip}
    - {id: noisy_attack, when: {class_in: [dos, generic, fuzzers]}, action: block_source_ip}
    - {id: recon, when: {class_in: [reconnaissance, analysis], min_severity: medium}, action: block_source_ip}
    - {id: default, when: {}, action: observe}
```
