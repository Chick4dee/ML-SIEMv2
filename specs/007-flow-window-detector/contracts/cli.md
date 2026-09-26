# Контракт CLI: фича 007

Все команды — `uv run mlsiem …`. Сообщения и отчёты на русском. Коды выхода как в 002–005:
`0` — успех (в том числе отрицательный результат эксперимента), `1` — ошибка входа или
конфигурации (понятное сообщение, ничего не записано), `2` — ошибка аргументов.

## `detect windows` — эксперимент (US1)

```
mlsiem detect windows [--config configs/windows.yaml] [--device auto|cuda|cpu]
                      [--skip-nn] [--output models/windows] [--no-mlflow]
```

- Строит окна `unsw_time` (train с аугментацией R9, отложенный хвост, val, test), обучает
  `lgbm` и `gru`, считает текущую модель на окнах, выбирает по R8 (без аудита:
  `audit_verdict = not_run`, `accepted` может быть `true` только после `windows-audit`).
- `--device auto` — видеокарта, если есть PyTorch с CUDA, иначе CPU (в сводке и карточке).
- `--skip-nn` — только бустинг и текущая модель (для машин без PyTorch); шаг 1 выбора
  пропускается с пометкой в отчёте.
- Нет PyTorch и не указан `--skip-nn` → код 1: «установите `uv sync --extra nn` или
  запустите с `--skip-nn`».
- Выход: `models/windows/` (всегда, R11), `models/windows/experiment.json`,
  `reports/windows_experiment.md`, MLflow `windows`.
- stdout — сводка: таблица участников (macro надёжных val, «атака/нет» val, test), решение по
  шагам одной строкой («победитель шага 1: lgbm (+0.004 < 0.01); против текущей модели:
  +0.031 ≥ 0.01 → кандидат принят, ждёт аудита»), время, устройство.

## `detect windows-audit` — проверка на артефакты и перенос (US2)

```
mlsiem detect windows-audit [--model models/windows] [--config configs/windows.yaml]
                            [--device auto|cuda|cpu]
```

- Выполняет R10 для модели из `--model` и для текущей модели на окнах.
- Обновляет `decision` в `window_card.json`: `audit_verdict`, итоговый `accepted`
  (= прошёл шаг 2 выбора **и** аудит `clean`), `reason`. Версия модели не меняется.
- Выход: `reports/windows_audit.md`, метрики в тот же MLflow-запуск победителя.
- Код 1, если `experiment.json` рядом с моделью нет (сначала `detect windows`).

## `detect windows-errors` — разбор ошибок (US4)

```
mlsiem detect windows-errors [--model models/windows] [--part test]
```

- Выход: `reports/windows_errors.md`; итоговые выводы дописываются в журнал вручную.

## `soc run` — дополнение (US3)

```
mlsiem soc run (--split … --part … | --pcap …) [--model …] [--windows auto|off|force]
               [--windows-model models/windows]
```

- `auto` (по умолчанию — из `soc.yaml: windows.mode`): эксперт окон включён, если артефакт
  есть и `accepted: true`; иначе прогон как в 005, в сводке «эксперт окон: не принят / нет».
- `force`: включить и при `accepted: false`, с предупреждением в сводке и в `runs.summary`.
- `off`: как в 005.
- Проверки эксперта окон (версия схемы, классы против таблицы серьёзности, длина окна и режим
  направления против `soc.yaml`) — до любой обработки; при ошибке — код 1, ничего не записано.
- Сводка дополняется строкой: «окон: N, алертов окон: K (эксперт окон lgbm <версия>)».

## `stream consume` — дополнение (US3)

```
mlsiem stream consume … [--windows auto|off|force] [--windows-model models/windows]
```

- То же правило включения; сеанс запоминает режим и версию эксперта окон при создании, при
  перезапуске с другим экспертом — отказ `ModelMismatch` (как для модели 005).
- Строка показателей дополняется: «окна: открыто N, закрыто M, алертов K, опоздавших-вне-окна L».

## `stream close` — дополнение

- Перед завершением сеанса закрывает все открытые окна (вердикты и алерты пишутся), как при
  отметке `end`.

## `stream status` / `stream compare` — дополнения

- `status`: у сеанса с экспертом окон — открытые окна, `n_window_late_dropped`.
- `compare`: раздел «окна» (вердикты окон, алерты окон в подписи инцидентов), причина
  `window_late_dropped` в списке известных.

## Конфиг `configs/windows.yaml` (FR-019)

```yaml
split: unsw_time
transfer_split: unsw_cross_day
seed: 42
window:
  length_ms: 60000
  seq_max: 128
  train_shifts_ms: [0, 15000, 30000, 45000]   # R9, только train
  holdout_share: 0.10                          # хвост train для ранней остановки (R5)
current_model: auto                            # models/ensemble, иначе models/detector
current_aggregate: max                         # R7
selection:
  metric: macro_pr_auc_reliable_val
  min_class_windows: 20
  min_gain: 0.01
audit:
  max_drop: 0.10
  single_feature_share: 0.90
candidates:
  lgbm: {n_estimators: 400, learning_rate: 0.05, num_leaves: 63, class_weight: balanced,
         early_stopping_rounds: 30}
  gru: {proj: 64, hidden: 96, dropout: 0.2, lr: 0.001, weight_decay: 0.0001, batch: 256,
        max_epochs: 40, patience: 5, class_weight_cap: 50, amp: true}
output: models/windows
```

Дополнение `configs/soc.yaml`:

```yaml
windows:
  model: models/windows
  mode: auto        # auto | off (force — только флагом CLI)
```
