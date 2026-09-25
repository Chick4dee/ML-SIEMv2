# Контракт: командная строка (фича 004)

Запуск из корня: `uv run mlsiem <группа> <команда> [опции]`. Коды возврата, stderr/stdout и язык
сообщений — как в 002 ([../../002-detection-incident-chain/contracts/cli.md](../../002-detection-incident-chain/contracts/cli.md)).
Команды 002/003 не удаляются и не меняют поведение, кроме явно указанного ниже.

## `detect ensemble` — эксперимент «эксперты + мета-слой» (US1, US2)

```
mlsiem detect ensemble [--config configs/ensemble.yaml] [--reports-dir reports]
```

Порядок работы (test ни на что не влияет):
1. загружает эксперт-классификатор из `classifier` конфига (`models/detector`), проверяет схему;
2. обучает кандидатов детектора аномалий на нормальных потоках train, калибрует перцентиль на
   отложенной норме train, выбирает порог по `anomaly_fpr` на норме val, выбирает кандидата
   по PR-AUC «атака/не атака» на val, проводит аудит артефактов;
3. строит мета-кандидатов, считает OOF-предсказания по блокам val, пороги и метрики;
4. эксперимент «скрытый класс» для каждого класса из `hidden_classes`;
5. выбирает вариант по правилу FR-010 (только val);
6. считает метрики на test у всех вариантов (только отчёт);
7. атомарно пишет `models/experts/anomaly/`, `models/ensemble/`, `reports/ensemble_experiment.md`;
   runs — в MLflow-эксперимент `ensemble`.

- Отказ (код `1`) до обучения: нет разбиения/захватов, нет или битый классификатор, несовместимая
  схема, ошибка конфига (неизвестный кандидат, скрытый класс не из классов классификатора,
  `anomaly_fpr` вне (0, 0.5), `folds` < 2).
- stdout: таблица вариантов (macro PR-AUC val/test, PR-AUC «атака/не атака», порог, F1),
  таблица «скрытый класс» (поимка val/test), выбранный вариант и **какое условие** выполнено
  (`macro_gain` / `unknown_gain` / ни одного → одиночный эксперт), помеченные аудитом признаки.
- Повторный запуск с тем же конфигом, данными и сидом — те же метрики, версии и выбор (SC-003).

## `soc run` — проигрывание через цепочку (изменено)

```
mlsiem soc run --split unsw_time --part test [--limit N] [--model DIR]
mlsiem soc run --pcap FILE [--model DIR]
```

- `--model DIR` — каталог ансамбля (`ensemble_card.json`) или детектора 002 (`model_card.json`).
  По умолчанию `models/ensemble`, если там есть карточка; иначе `models/detector` и строка
  предупреждения «ансамбль не обучен, прогон одиночным детектором».
- `--detector DIR` — синоним `--model` (совместимость с 002/003).
- Все проверки моделей (эксперты на месте, версии совпадают, схема) — до чтения данных (FR-014).
- Направление потоков — по `grouping.direction` из `configs/soc.yaml` (`auto` | `as_is`).
- stdout дополнительно: модель прогона (`ансамбль <версия> (<вариант>)` или `детектор <версия>`),
  алертов по экспертам (классификатор / детектор аномалий / только мета-слой), число ответных
  потоков, инцидентов класса `anomaly`.

## `soc review-sources` — разбор инцидентов с адресов жертв и фона (US4)

```
mlsiem soc review-sources --run RUN_ID [--after RUN_ID] [--reports-dir reports]
```

- Для прогона `--run`: инциденты, у которых источник в сетях с ролью `victims`/`background`
  (`networks` в `configs/soc.yaml`), с причиной по каждому потоку: `response_direction`,
  `detector_error`, `labeled_attack` (правило направления R8 + метки размеченного входа).
- С `--after`: сравнение прогонов — число таких инцидентов до/после и проверка «ни один
  атакующий не потерян» (research R9).
- Отказ (код `1`): прогона нет; у прогона нет `verdicts.parquet` или меток (`true_label`) —
  разбор причин без разметки невозможен, об этом сообщается.
- Выход: `reports/source_review_<run>.md` и `.json`. stdout: сводка «было N → стало M, из-за
  направления K, ошибок детектора L, потеряно атакующих 0».
- Код `0`, даже если атакующие потеряны — это результат разбора, а не сбой команды; строка
  «ПОТЕРЯНЫ АТАКУЮЩИЕ» в stdout и `lost` в json.

## `soc serve`, `soc status`

Без изменений в вызове. `soc serve` при старте мигрирует базу до схемы 3 (как 003 делал 0 → 2),
печатает строку о миграции. `soc status` в колонке модели показывает версию ансамбля или
детектора.

## DVC

```
dvc repro train_ensemble
```

Стадия `train_ensemble`: `cmd: uv run mlsiem detect ensemble`; deps — `data/splits/unsw_time.*`,
`models/detector`, `configs/ensemble.yaml`, `configs/detect.yaml`, `src/mlsiem/detect`; outs —
`models/experts/anomaly`, `models/ensemble`; `reports/ensemble_experiment.md` — `cache: false`.
