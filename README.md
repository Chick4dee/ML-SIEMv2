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
