# ML-SIEM v2

SIEM/SOAR с ML-детекцией сетевых атак. Разработка идёт вертикальными срезами по
спецификациям в `specs/`; журнал решений — `docs/JOURNAL.md`.

## Быстрый старт

```
uv sync --extra dev
uv run pytest
uv run mlsiem data flows --dataset ctu13 --capture 7
```

Подробнее о пайплайне данных — `specs/001-nids-data-pipeline/quickstart.md`.

## Детекция, инциденты и API (фича 002)

Сквозная цепочка поверх данных фичи 001: детектор → алерты → инциденты → предложения
плейбуков → API аналитика. Реагирование только симулируется — никаких реальных сетевых действий.

```
uv run mlsiem detect train                              # эксперимент logreg vs lgbm, выбор детектора
uv run dvc repro train_detector                         # то же как стадия DVC
uv run mlsiem soc run --split unsw_time --part test     # прогон test через цепочку (--limit N — первые N потоков)
uv run mlsiem soc run --pcap FILE.pcap                  # новый неразмеченный PCAP тем же путём
uv run mlsiem soc status                                # какие прогоны лежат в хранилище
uv run mlsiem soc serve                                 # API на http://127.0.0.1:8000/api/v1
```

Где что лежит:

- `models/detector/` — артефакт детектора (`model.joblib`, `model_card.json`, `experiment.json`),
  выход DVC; отчёт эксперимента — `reports/detector_experiment.md`;
- `var/soc.db` — SQLite с прогонами, алертами, инцидентами, действиями и аудит-журналом;
  `var/runs/<run_id>/` — вердикты всех потоков прогона (и `flows.parquet` для PCAP).
  `var/` — рабочее состояние аналитика, ни в git, ни в DVC;
- MLflow: метаданные в `mlflow.db`, файлы runs в `mlruns/` (оба вне git).
  Посмотреть: `uv run mlflow ui --backend-store-uri sqlite:///mlflow.db`;
- документация API (Swagger) — `http://127.0.0.1:8000/docs` при запущенном `soc serve`.
  Изменяющие запросы требуют заголовок `X-Analyst: <имя латиницей>`.

Конфиги — `configs/detect.yaml` (кандидаты, правило выбора, сид) и `configs/soc.yaml`
(окно группировки, серьёзность, защищённые адреса, правила плейбуков). Сценарии проверки —
`specs/002-detection-incident-chain/quickstart.md`.
