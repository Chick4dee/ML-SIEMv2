# Implementation Plan: Пайплайн данных NIDS

**Branch**: `001-nids-data-pipeline` | **Date**: 2026-09-23 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-nids-data-pipeline/spec.md`

## Summary

Из сырых PCAP UNSW-NB15 (80 файлов) и CTU-13 (13 сценариев) одной командой получить
размеченные таблицы сетевых потоков с версионированной схемой признаков, три разбиения
без утечек (`unsw_time`, `unsw_cross_day`, `ctu13_scenario`), проверку на артефакты
датасета и самостоятельный HTML-отчёт о качестве данных со сверкой с v1.

Подход: единый экстрактор nfstream с фиксированными настройками (тот же код годится для
живого трафика), потоковая запись через временный CSV → parquet, детерминированная
сортировка и хеш содержимого, возобновление по манифестам захватов, конвейер стадий DVC.
Алгоритм разметки берётся из v1 (проверен), код пишется заново с тестами. Подробности —
[research.md](research.md).

## Technical Context

**Language/Version**: Python 3.11

**Primary Dependencies**: nfstream 6.6 (+ Npcap), polars, pyarrow, scikit-learn (аудит),
matplotlib + Jinja2 (отчёт), PyYAML (конфиг), DVC 3.x; dev: pytest, ruff, scapy (фикстуры)

**Storage**: файлы — parquet (потоки, разбиения, аудит), JSON (манифесты), HTML/MD (отчёт);
версионирование — DVC с локальным remote `A:\dvc-remote-v2`

**Testing**: pytest; маркер `slow` для тестов на реальных датасетах

**Target Platform**: Windows 11 (рабочая машина); код без Windows-специфики, кроме
зависимости nfstream от Npcap

**Project Type**: Python-пакет с CLI (`mlsiem data …`)

**Performance Goals**: полный прогон 93 захватов (~100 ГБ) за одну ночь (ориентир ≤ 8 ч);
один сценарий CTU-13 — минуты

**Constraints**: пик памяти < 16 ГБ; результат повторного прогона идентичен по хешу
содержимого; большие файлы не попадают в git; бинарники малвари в папках CTU-13 не трогаем

**Scale/Scope**: ~100 ГБ PCAP, порядка десятков миллионов потоков; 3 разбиения; 1 отчёт

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Принцип | Как выполняется | Статус |
|---|---|---|
| I. Вертикальные срезы | Фича заканчивается запускаемой командой и показуемым отчётом (`mlsiem data all` → `reports/data_quality.html`); логирование прогресса и DVC-конвейер — внутри фичи | ✅ |
| II. Train = serve | Один модуль экстракции и одна версия схемы для `flows` и `extract`; SC-007 проверяет совпадение на 100% | ✅ |
| III. Честная оценка | Разбиения только по времени/сценариям с зазором; автоматические инварианты (SC-006); аудит артефактов по полям; PR-AUC как метрика аудита | ✅ |
| IV. Решения через эксперимент | Модели в 001 нет; аудит использует простое дерево как бейзлайн-инструмент, а не как выбранную модель | ✅ (н/п) |
| V. Безопасный SOAR | В фиче не затрагивается | н/п |
| VI. Воспроизводимость и понятный код | DVC + `uv.lock` + фиксированный сид + хеши содержимого; тесты на каждый модуль; русские комментарии; запись в `docs/JOURNAL.md` | ✅ |
| VII. Прозрачное авторство | Коммитит владелец; `data/`, отчёты с абсолютными путями и локальные настройки — вне git | ✅ |
| Ограничения среды | 16 ГБ RAM — потоковая запись, по одному захвату; GPU не нужен; Docker/WSL2 не нужны | ✅ |

Нарушений нет, Complexity Tracking не заполняется.

**Повторная проверка после фазы 1**: data-model разделяет поля на группы и явно запрещает
подавать `identity`/`time` в модели (II, III); контракт parquet требует проверки
`schema_version` потребителями (II); quickstart содержит проверки SC-002/003/006/007 (III, VI).
Статус — ✅.

## Project Structure

### Documentation (this feature)

```text
specs/001-nids-data-pipeline/
├── plan.md              # этот файл
├── research.md          # решения фазы 0
├── data-model.md        # сущности и форматы
├── quickstart.md        # сценарии проверки
├── contracts/
│   └── cli.md           # команды, выходной parquet, configs/data.yaml
├── checklists/
│   └── requirements.md  # проверка качества спецификации
└── tasks.md             # создаётся /speckit-tasks
```

### Source Code (repository root)

```text
pyproject.toml            # зависимости, entry point `mlsiem`, ruff, pytest
uv.lock
dvc.yaml                  # стадии: flows_unsw, flows_ctu13, split_*, audit_*, compare_v1, report
configs/
├── data.yaml             # пути к датасетам, параметры разбиений и аудита
└── v1_diff_notes.yaml    # объяснения расхождений с v1
src/mlsiem/
├── __init__.py
├── cli.py                # точка входа `mlsiem`, подкоманды `data …`
└── data/
    ├── __init__.py
    ├── config.py         # чтение и проверка configs/data.yaml
    ├── schema.py         # FeatureSchema: колонки, группы, версия, настройки экстрактора
    ├── extract.py        # nfstream → временный CSV → отсортированный parquet
    ├── captures.py       # поиск захватов, отпечатки, манифесты, атомарная запись
    ├── taxonomy.py       # канонические классы и таблицы соответствий
    ├── labeling.py       # сопоставление потоков с разметкой (5-/3-кортеж, интервал, допуск)
    ├── sources/
    │   ├── unsw.py       # чтение GT CSV, правила UNSW (несопоставленное → benign)
    │   └── ctu13.py      # чтение .binetflow, часовой пояс, семейства, unlabeled
    ├── pipeline.py       # прогон датасета с возобновлением, сводка
    ├── split.py          # три разбиения + проверка инвариантов
    ├── audit.py          # проверка на артефакты по полям
    ├── compare_v1.py     # сверка с таблицами v1
    └── report/
        ├── build.py      # сборка HTML/MD
        └── templates/    # Jinja2-шаблоны
tests/
├── fixtures/             # синтетический PCAP (scapy), мини-GT, мини-binetflow
├── unit/                 # schema, taxonomy, labeling, split, audit, captures
└── integration/          # flows на синтетике; slow: CTU-13 №7, train = serve
data/                     # выходы DVC (в git только .gitignore/.dvc-файлы)
reports/                  # data_quality.html / .md (выход DVC)
docs/JOURNAL.md
```

**Structure Decision**: один Python-пакет `mlsiem` с подпакетом `data`; будущие фичи
(детекция, SOAR, API, UI) добавят соседние подпакеты. CLI — единая точка входа `mlsiem`,
чтобы следующие срезы добавляли свои подкоманды, а не отдельные скрипты.

## Complexity Tracking

Нарушений конституции нет.
