# Implementation Plan: Несколько экспертов-детекторов и мета-слой

**Branch**: `004-detection-experts-ensemble` | **Date**: 2026-09-24 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/004-detection-experts-ensemble/spec.md`

## Summary

К классификатору 002 (LightGBM, macro PR-AUC test 0.697) добавляется второй эксперт — детектор
аномалий, обученный только на нормальных потоках train (кандидаты Isolation Forest — бейзлайн —
и автокодировщик на `MLPRegressor`; скор — перцентиль нормы, порог — 0.5% ложных срабатываний
на норме val). Мета-слой объединяет их ответы; кандидаты — два правила без обучения
(`any_fired`, `mean_score`) и стекинг на логистической регрессии. Мета-слой учится на val
с перекрёстной подгонкой по 5 последовательным блокам времени (out-of-fold), test — только
отчёт. Эксперимент «скрытый класс» (`exploits`, `dos`) проверяет пользу для неизвестных атак.
Ансамбль идёт в цепочку, если на val даёт +0.01 macro PR-AUC **или** +0.10 поимки скрытых
классов при падении macro не больше 0.01; иначе остаётся классификатор 002, и это честно
записывается. Цепочка грузит модель через общий интерфейс (детектор или ансамбль), пишет ответы
экспертов и объяснение в алерты, класс `anomaly` всегда получает «ручной разбор». Новое правило
направления по TCP-флагам и портам самого потока определяет атакующую сторону — по ней идёт
группировка. База мигрирует на схему 3 одними добавлениями; консоль показывает вклад экспертов.
Разбор 14 инцидентов с адресов жертв/фона — отдельной командой с отчётом «до/после».
Подробности — [research.md](research.md).

## Technical Context

**Language/Version**: Python 3.11 (как в 001–003)

**Primary Dependencies**: без новых пакетов — scikit-learn (`IsolationForest`, `MLPRegressor`,
`LogisticRegression`), LightGBM (переобучение классификатора без скрытого класса), polars,
numpy, MLflow, FastAPI/Jinja2/htmx из 003

**Storage**: артефакты `models/experts/anomaly/`, `models/ensemble/` (DVC); SQLite `var/soc.db` —
миграция схемы 2 → 3 (только `ADD COLUMN` + заполнение `attacker_ip/victim_ip`);
`var/runs/<run_id>/verdicts.parquet` — с колонками экспертов

**Testing**: pytest; синтетические разбиения и `tiny_detector` из 002 + новые фикстуры
`tiny_anomaly`/`tiny_ensemble`; тесты на отсутствие утечек (эксперт аномалий не видит атак,
мета-слой не видит test и train); миграция 2 → 3 на снимке базы 003; `slow` — реальный
эксперимент и прогон

**Target Platform**: Windows 11, локально, CPU (GPU не нужен); консоль на `127.0.0.1`

**Project Type**: Python-пакет с CLI, ML-экспериментом и локальным веб-сервисом

**Performance Goals**: `detect ensemble` ≤ 30 мин; `soc run` на test `unsw_time` (282 тыс.
потоков) ≤ 15 мин (SC-004, ожидание < 1 мин); консоль — как в 003 (< 1 с)

**Constraints**: 16 ГБ RAM (train признаков ~330 МБ; обучение аномалий на подвыборке 300 тыс.);
test не участвует ни в каком выборе; эксперты — только группа `feature`; правило направления не
знает сетей UNSW-NB15 и меток; API/консоль — только добавления

**Scale/Scope**: 2 эксперта, 3 мета-кандидата, 2 скрытых класса; ~8 тыс. алертов на прогон;
новые модули: `detect/anomaly.py`, `detect/ensemble.py`, `detect/meta.py`, `soc/direction.py`,
`soc/review.py`

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Принцип | Как выполняется | Статус |
|---|---|---|
| I. Вертикальные срезы | Ансамбль доходит до аналитика: `detect ensemble` → `soc run` → API → консоль (блок экспертов, класс `anomaly`, ответные потоки); одна команда на эксперимент, одна на прогон | ✅ |
| II. Train = serve | Эксперты берут только группу `feature` той же схемы 1.x; предобработка (log1p, стандартизация, калибровка перцентиля) — внутри артефактов; ансамбль отказывается работать при разных мажорных версиях схемы или несовпадении версий экспертов; правило направления — по полям самого потока, одинаково на датасете и PCAP | ✅ |
| III. Честная оценка | PR-AUC по классам и macro; эксперт аномалий — только норма train; мета-слой — OOF по блокам времени val; пороги — на val; test — только отчёт; аудит артефактов (однопризнаковый зонд + перестановочная важность); ненадёжные классы (< 50 примеров) помечаются; MLflow с версиями данных, конфигом, сидом | ✅ |
| IV. Решения через эксперимент | Бейзлайны на каждом уровне: Isolation Forest против автокодировщика, правила без обучения против стекинга, одиночный классификатор против ансамбля; правило принятия FR-010 с порогами из конфига; отрицательный результат — в журнал | ✅ |
| V. Безопасный SOAR | Плейбуки детерминированы; класс `anomaly` → всегда `manual_review` (правило в конфиге + страховка в коде); симуляция, подтверждение и аудит 002 не меняются; объект блокировки — атакующая сторона, защищённый список действует как раньше | ✅ |
| VI. Воспроизводимость и понятный код | DVC-стадия `train_ensemble`; версии ансамбля и экспертов — хеш конфига и данных; фиксированные сиды (IsolationForest, MLP, LightGBM deterministic); тесты на каждое правило; русские комментарии; запись в журнал | ✅ |
| VII. Прозрачное авторство | Коммитит владелец; `models/`, `var/`, `mlruns/` вне git (DVC/ignore) | ✅ |
| Ограничения среды | CPU, без Docker/WSL2, без новых тяжёлых зависимостей | ✅ |
| Язык | Отчёты, сообщения, объяснения, комментарии — по-русски | ✅ |

Нарушений нет.

**Повторная проверка после фазы 1**: data-model фиксирует `data_scheme` в карточке ансамбля и
`benign_only` в карточке эксперта (III); миграция 2 → 3 — только добавления, аудит не трогается
(V); контракт API — только новые поля, `null` для старых прогонов (I, SC-005); правило направления
в отдельном модуле без доступа к конфигу сетей, отчёт разбора использует сети только для оценки
(FR-023). Отдельно отмечено: правка синтетической фикстуры (SYN у инициатора) — это правка
данных теста, а не ожиданий; она нужна, потому что фикстура 002 ставила флаги случайно. Статус — ✅.

## Project Structure

### Documentation (this feature)

```text
specs/004-detection-experts-ensemble/
├── plan.md                      # этот файл
├── research.md                  # решения фазы 0 (R1–R15)
├── data-model.md                # артефакты, вердикты, схема БД 3, конфиги
├── quickstart.md                # сценарии проверки
├── contracts/
│   ├── cli.md                   # detect ensemble, soc run --model, soc review-sources
│   ├── api-v1-additions.md      # новые поля API
│   └── ui.md                    # блок экспертов, «ответный поток», класс anomaly
├── checklists/
│   └── requirements.md
└── tasks.md                     # создаётся /speckit-tasks
```

### Source Code (repository root)

```text
configs/
├── ensemble.yaml                # НОВЫЙ: эксперт аномалий, мета-кандидаты, скрытые классы, выбор
└── soc.yaml                     # + severity.base.anomaly, правило unknown_class, grouping.direction
dvc.yaml                         # + стадия train_ensemble
src/mlsiem/
├── cli.py                       # + detect ensemble, soc run --model, soc review-sources
├── detect/
│   ├── anomaly.py               # НОВЫЙ: кандидаты iforest/autoencoder, калибровка перцентиля,
│   │                            #   порог по anomaly_fpr, артефакт эксперта, аудит (R1, R2, R6)
│   ├── meta.py                  # НОВЫЙ: any_fired, mean_score, stack_logreg; OOF по блокам
│   │                            #   времени; класс anomaly; объяснение (R3, R4)
│   ├── ensemble.py              # НОВЫЙ: эксперимент 004 (скрытые классы, правило FR-010,
│   │                            #   отчёт), load_model() — общий интерфейс детектор|ансамбль (R5, R7)
│   ├── config.py                # + EnsembleConfig
│   ├── artifact.py              # без изменения формата; общие версии/проверки схемы
│   └── metrics.py               # + PR-AUC «атака/не атака», поимка класса, доля нормы выше порога
├── soc/
│   ├── direction.py             # НОВЫЙ: attacker_side() по TCP-флагам и портам (R8)
│   ├── review.py                # НОВЫЙ: разбор источников, сравнение до/после (R9)
│   ├── verdicts.py              # вердикты из общего интерфейса модели, колонки экспертов,
│   │                            #   alerts с attacker_ip/victim_ip/reversed/experts/explanation
│   ├── incidents.py             # ключ группировки (attacker_ip, класс), targets = victim_ip
│   ├── playbooks.py             # + страховка anomaly_guard (R12)
│   ├── run.py                   # load_model вместо load_detector, сводка по экспертам
│   ├── store.py                 # схема 3, миграция 2→3, новые поля алертов, experts_summary
│   ├── config.py                # + grouping.direction, проверка уровня для anomaly
│   └── api.py                   # + поля алертов, experts_summary, model у прогонов
└── ui/
    ├── views.py                 # блок экспертов, сводка «кто поднял алерты»
    ├── labels.py                # русские имена экспертов, класс anomaly, «ответный»
    └── templates/fragments/     # _probs (+ эксперты), _alerts (ответный, эксперты),
                                 #   _experts_summary (НОВЫЙ), _dashboard_counters
reports/
├── ensemble_experiment.md       # выход detect ensemble
└── source_review_<run>.md       # выход soc review-sources
tests/
├── fixtures/make_synthetic_flows.py   # SYN у инициатора для TCP (R15)
├── unit/                        # test_detect_anomaly, test_detect_meta (OOF без утечек,
│                                #   блоки времени), test_detect_ensemble_select (правило FR-010),
│                                #   test_soc_direction, test_soc_review, test_store_migration_v3,
│                                #   test_soc_playbooks (+anomaly), test_soc_verdicts (+эксперты)
├── integration/                 # test_ensemble_experiment (синтетика, воспроизводимость),
│                                #   test_chain_ensemble (прогон, отказ при битом эксперте),
│                                #   test_ensemble_real (slow)
├── api/                         # новые поля, старые прогоны → null
└── ui/                          # блок экспертов, старый прогон, класс anomaly
```

**Structure Decision**: всё ML — в `mlsiem.detect`; граница с SOC — одна функция `load_model()`
и объект с интерфейсом «вердикты для кадра потоков», как `load_detector()` в 002. Направление
потока — в `soc/direction.py`: это логика «кто атакует» для группировки, а не часть модели, и она
работает одинаково для детектора и ансамбля. Отчёт разбора — `soc/review.py`, единственное место,
где знание сетей жертв/фона (конфиг 003) встречается рядом с правилом направления, и только для
оценки. Консоль по-прежнему зависит только от `soc`.

## Complexity Tracking

Нарушений конституции нет — таблица не заполняется.
