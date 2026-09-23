# Quickstart: проверка фичи 001

Сценарии, которые доказывают, что фича работает от начала до конца. Команды —
по [contracts/cli.md](contracts/cli.md), форматы — по [data-model.md](data-model.md).

## Предусловия

- Windows 11, Python 3.11, uv, установленный Npcap (режим WinPcap API-compatible).
- Датасеты на месте: `A:\datasets\UNSW-NB15\…`, `A:\datasets\CTU-13\CTU-13-Dataset`.
  **В папках CTU-13 лежат настоящие бинарники ботнетов (`*.exe`) — не открывать и не запускать.**
- Свободно ~15 ГБ на диске для `data/` и кэша DVC.

```
uv sync --extra dev
uv run dvc remote list        # ожидается remote A:\dvc-remote-v2
```

## 1. Быстрые тесты (без датасетов)

```
uv run pytest
```

Ожидается: все тесты зелёные, включая интеграционный на синтетическом PCAP.

## 2. Один сценарий CTU-13 (US1, ~1 минута)

```
uv run mlsiem data flows --dataset ctu13 --capture 7
```

Ожидается: `data/flows/ctu13/ctu13_07.parquet` и манифест; в сводке 51 поток,
доля сопоставления ≈ 0.86 (как в v1), класс `unlabeled` для несопоставленных.

## 3. Воспроизводимость (SC-003)

```
uv run mlsiem data flows --dataset ctu13 --capture 7 --force
```

Ожидается: `content_hash` в манифесте тот же, что после шага 2.

## 4. Возобновление (SC-002)

Запустить `uv run mlsiem data flows --dataset unsw`, прервать `Ctrl+C` после 2–3 захватов,
запустить снова. Ожидается: готовые захваты помечены «пропущен», работа продолжается со
следующего; в `data/flows/unsw/` нет «полуготовых» parquet.

## 5. Train = serve (SC-007)

```
uv run mlsiem data extract "A:/datasets/CTU-13/CTU-13-Dataset/7/<файл>.pcap" --output tmp/adhoc.parquet
uv run pytest -m slow -k train_serve
```

Ожидается: колонки групп `feature`/`identity`/`time`/`dpi` совпадают на 100%
с `ctu13_07.parquet`; колонок `label` нет.

## 6. Полный прогон (SC-001, SC-004–SC-006, SC-008)

```
uv run mlsiem data all
```

Во время прогона следить за памятью в Диспетчере задач: пик < 16 ГБ.
Ожидается:
- 93 захвата со статусом `done`;
- три разбиения, проверка инвариантов пройдена (0 пересечений, 0 дублей);
- `data/compare_v1.csv` — нет расхождений > 5% без объяснения;
- `reports/data_quality.html` открывается двойным кликом, содержит все разделы
  из data-model (DataQualityReport) и список полей `dangerous`/`suspicious`.

## 7. Версионирование

```
uv run dvc status
uv run dvc push
```

Ожидается: `dvc status` — «Data and pipelines are up to date»; данные выгружены
в `A:\dvc-remote-v2`; в `git status` нет parquet-файлов.
