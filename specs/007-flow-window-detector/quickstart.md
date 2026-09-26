# Quickstart: проверка фичи 007

Сценарии проверки «от начала до конца». Детали команд — [contracts/cli.md](contracts/cli.md),
поля — [data-model.md](data-model.md).

## 0. Предусловия

- Данные 001 (`data/flows/unsw`, `data/splits/unsw_time*`, `unsw_cross_day*`,
  `data/audit/unsw_time.parquet`) и модели 002/004 (`models/detector`, `models/ensemble`) на
  месте (`dvc pull` при необходимости).
- PyTorch с CUDA для нейросети:
  ```
  uv sync --extra dev --extra nn
  uv run python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_device_name(0))"
  ```
  Ожидается `True NVIDIA GeForce RTX 3060 Ti`. Без видеокарты всё работает на CPU (медленнее),
  без PyTorch — только с `--skip-nn`.
- Рабочая база: перед первым запуском `soc serve`/`soc run` новой версии —
  `copy var\soc.db var\soc.db.bak-005` (миграция схемы 4 → 5, или 3 → 5, если база ещё не
  переведена на 4).

## 1. Быстрые тесты

```
uv run pytest
uv run ruff check .
```

Ожидается: все быстрые тесты 001–007 зелёные; среди новых — одинаковые окна в пакетном и
онлайн-режиме на синтетике, отсутствие запрещённых полей во входах, test не участвует в выборе,
миграция 4 → 5, перезапуск потребителя с открытыми окнами.

## 2. Эксперимент (US1, SC-001–SC-004)

```
uv run mlsiem detect windows
```

Ожидается: сводка с тремя участниками и решением по шагам; `models/windows/window_card.json`
(`decision.audit_verdict = not_run`), `reports/windows_experiment.md`, три запуска в MLflow
`windows`; время ≤ 2 ч (цель SC-001; ожидаемо — минуты). Повтор той же командой: macro
надёжных бустинга совпадает до 0.001, нейросети — в пределах 0.01 (SC-003).

## 3. Аудит и перенос (US2, SC-005)

```
uv run mlsiem detect windows-audit
```

Ожидается: `reports/windows_audit.md` с вердиктом `clean` или `relies_on_artifacts`; в
карточке итоговое `accepted`. Цифры и вывод — в `docs/JOURNAL.md`.

## 4. Разбор ошибок (US4)

```
uv run mlsiem detect windows-errors
```

Ожидается: `reports/windows_errors.md` (матрица ошибок, качество по размеру окна, таблица
«только окна / только потоки / обе / никто»).

## 5. Цепочка с окнами — пакетно (US3)

Если `accepted: true`:

```
uv run mlsiem soc run --split unsw_time --part test
```

Если отрицательный результат — та же проверка интеграции принудительно (в приёмочную базу 005
`var/acceptance/`, рабочая не засоряется):

```
uv run mlsiem soc --config var/acceptance/soc.yaml run --split unsw_time --part test --windows force
```

Ожидается: строка «окон: ≈2 600, алертов окон: K»; в консоли (`uv run mlsiem soc serve`)
инциденты со значком «окна», у алерта окна — интервал, цели, подозрительные потоки, пояснение.

## 6. Цепочка с окнами — онлайн и эквивалентность (US3, SC-006, SC-007)

Брокерная машина 005 запущена (`uv run mlsiem stand check` — всё в порядке).

```
uv run mlsiem stream consume --windows auto          # или force, как в п. 5
uv run mlsiem stream replay --split unsw_time --part test --speed max
uv run mlsiem stream compare --session <id сеанса> --batch <id прогона из п. 5>
```

Ожидается: `compare` — «эквивалентно», включая раздел «окна» (SC-006); вся часть обработана
≤ 10 мин, хвост потребителя после конца проигрывания зафиксирован в журнале (SC-007, запас
по SC-002 005). Прерывание потребителя посреди проигрывания и перезапуск — итог тот же
(открытые окна продолжаются из хранилища).

Реальное время (задержка окна, SC-006): `stream replay --split unsw_time --part test --limit 100000 --speed 60`;
алерт окна появляется не позже чем через 15 с после того, как время трафика ушло на 60 + 120 с
за начало окна.

## 7. Отрицательный результат не меняет цепочку (SC-008)

При `accepted: false` и `--windows auto`: `soc run` даёт те же инциденты, что до 007 (сравнить
с прошлым прогоном того же входа по числу и ключам инцидентов); прежние прогоны открываются в
консоли.
