# Implementation Plan: Сквозная цепочка «детекция → инцидент → реагирование → API»

**Branch**: `002-detection-incident-chain` | **Date**: 2026-09-24 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/002-detection-incident-chain/spec.md`

## Summary

Первый показуемый срез SIEM/SOAR поверх данных фичи 001. Эксперимент сравнивает логистическую
регрессию (бейзлайн) и LightGBM на разбиении `unsw_time` по macro PR-AUC, выбирает победителя
по val, фиксирует всё в MLflow и сохраняет детектор с предобработкой, порогом и версией схемы.
Команда `mlsiem soc run` проигрывает test-часть (или новый PCAP через экстрактор 001) через
детектор: вердикты → алерты → инциденты (ключ «IP-источник + класс», разрыв 15 минут) →
серьёзность → предложения плейбуков; всё пишется в SQLite одной транзакцией. `mlsiem soc serve`
поднимает локальный API (FastAPI) для списка и карточек инцидентов, подтверждения/отклонения
действий (только симуляция) и аудит-журнала. Подробности — [research.md](research.md).

## Technical Context

**Language/Version**: Python 3.11 (как в 001)

**Primary Dependencies**: из 001 — polars, pyarrow, scikit-learn, pyyaml, DVC; новые — LightGBM
(кандидат), MLflow (журнал экспериментов), FastAPI + uvicorn (API), joblib (артефакт);
dev — httpx (для `TestClient`)

**Storage**: SQLite `var/soc.db` (инциденты, алерты, действия, аудит); parquet
`var/runs/<run_id>/verdicts.parquet`; артефакт детектора `models/detector/` под DVC;
MLflow — локально в `mlruns/`

**Testing**: pytest; `TestClient` для API; маркер `slow` для реальных данных

**Target Platform**: Windows 11, локальная машина; API только на `127.0.0.1`

**Project Type**: Python-пакет с CLI (`mlsiem detect …`, `mlsiem soc …`) и локальным HTTP API

**Performance Goals**: прогон полного test `unsw_time` (~282 тыс. потоков) ≤ 15 мин
(оценка — около минуты); список инцидентов с фильтрами < 1 с; эксперимент — стадия DVC,
ориентир ≤ 30 мин

**Constraints**: ≤ 16 ГБ RAM; CPU (GPU не нужен); без Docker/WSL2; никаких реальных сетевых
действий; детерминизм вердиктов, инцидентов и предложений

**Scale/Scope**: train 1.41 млн потоков × 58 признаков; test 282 тыс.; ожидаемо ~10 тыс. алертов
и десятки–сотни инцидентов на прогон; один аналитик

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Принцип | Как выполняется | Статус |
|---|---|---|
| I. Вертикальные срезы | Фича — сквозная цепочка от потоков до API с одной командой прогона; логирование, конфиги и стадия DVC внутри фичи; UI и хранилище «на вырост» не строятся | ✅ |
| II. Train = serve | Вход детектора — поля схемы 001 по `SCHEMA.feature_columns()`; предобработка внутри артефакта; проверка мажорной версии схемы при загрузке (FR-007); новый PCAP идёт через тот же экстрактор 001 | ✅ |
| III. Честная оценка | PR-AUC по классам и macro; порог и выбор победителя только по val; test — итог; перенос на `unsw_cross_day`; только поля `feature` (IP/время/DPI исключены по аудиту 001); runs в MLflow с версией данных, конфигом, сидом | ✅ |
| IV. Решения через эксперимент | Логистическая регрессия — бейзлайн; LightGBM принимается только при приросте ≥ 0.01 macro PR-AUC на val; тривиальная базовая линия `prior`; цифры в журнал | ✅ |
| V. Безопасный SOAR | Плейбуки — упорядоченные правила, первое совпадение (детерминизм); действия только симулируются; выполнение только после подтверждения; аудит-журнал только на вставку; защищённый список адресов | ✅ |
| VI. Воспроизводимость и понятный код | Сиды, детерминированный LightGBM, DVC-стадия `train_detector`, `uv.lock`; тесты на каждый модуль; русские комментарии; журнал | ✅ |
| VII. Прозрачное авторство | Коммитит владелец; `var/`, `mlruns/` — в `.gitignore`; модели — через DVC | ✅ |
| Ограничения среды | CPU, ≤ 16 ГБ; SQLite вместо сервера БД; Docker не нужен | ✅ |

Нарушений нет.

**Повторная проверка после фазы 1**: data-model фиксирует ровно одно действие на инцидент,
переходы только `proposed → executed | rejected` и запрет изменения аудита (V); карточка модели
хранит версию схемы и хеши данных (II, VI); контракт API требует `X-Analyst` для любых изменений
(V). Статус — ✅.

## Project Structure

### Documentation (this feature)

```text
specs/002-detection-incident-chain/
├── plan.md              # этот файл
├── research.md          # решения фазы 0
├── data-model.md        # сущности, переходы, таблицы
├── quickstart.md        # сценарии проверки
├── contracts/
│   ├── cli.md           # команды detect/soc и конфиги
│   └── api.md           # HTTP API аналитика v1
├── checklists/
│   └── requirements.md
└── tasks.md             # создаётся /speckit-tasks
```

### Source Code (repository root)

```text
configs/
├── detect.yaml           # кандидаты, правило выбора, сид
└── soc.yaml              # окно группировки, серьёзность, защищённые адреса, плейбуки, БД, API
src/mlsiem/
├── cli.py                # + группы `detect` и `soc`
├── detect/
│   ├── __init__.py
│   ├── config.py         # чтение configs/detect.yaml
│   ├── dataset.py        # потоки части разбиения → X (поля feature), y; хеши данных
│   ├── candidates.py     # logreg / lgbm / prior как sklearn-конвейеры
│   ├── metrics.py        # PR-AUC по классам и macro, порог по F1 на val
│   ├── experiment.py     # обучение кандидатов, выбор победителя, MLflow, отчёт
│   └── artifact.py       # сохранение/загрузка детектора, проверка версии схемы
└── soc/
    ├── __init__.py
    ├── config.py         # чтение configs/soc.yaml
    ├── verdicts.py       # детектор → вердикты и алерты
    ├── incidents.py      # группировка алертов, серьёзность
    ├── playbooks.py      # правила → предложение действия; симуляция
    ├── store.py          # SQLite: схема, транзакции, оптимистичная блокировка, аудит
    ├── run.py            # прогон: split/pcap → verdicts → incidents → actions → store
    └── api.py            # FastAPI-приложение (контракт api.md)
tests/
├── unit/                 # metrics, candidates, artifact, incidents, severity, playbooks, store
├── api/                  # TestClient: все операции и ошибки контракта
└── integration/          # синтетика → train → run → API; slow: реальные данные, PCAP
models/detector/          # выход DVC (в git только .gitignore/.dvc)
var/                      # SOC-состояние: soc.db, runs/ (вне git и DVC)
```

**Structure Decision**: два новых подпакета рядом с `data` — `detect` (ML: эксперимент и
артефакт) и `soc` (всё после вердикта). Граница — артефакт детектора: `soc` знает только
загрузчик из `detect.artifact` и не зависит от того, какая модель победила. Следующие фичи
добавят других экспертов в `detect`, хранилище и UI — рядом с `soc`.

## Complexity Tracking

Нарушений конституции нет.
