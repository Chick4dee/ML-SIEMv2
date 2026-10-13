# Quickstart: собрать содержательный набор стенда и получить отчёт

Предполагается поднятый стенд 006 (брокер, жертва, атакующий, сенсор). Все команды на хосте;
любое действие на машинах — по подтверждению.

## 1. Подготовка (один раз)

1. Создать недостающие машины: `stand\hyperv\46-vm-client.ps1`, `stand\hyperv\51-vm-attacker2.ps1`
   (образы из `stand/cloud`, по 512 МБ); добавить алиасы адреса атакующего (скрипт сообщит команды).
2. Проверить стенд и инструменты: `uv run mlsiem stand check` → код 0 (запас памяти ≥ 4 ГБ);
   `uv run mlsiem lab tools check` → код 0 (или перечень недоступного).
3. Остановить потребитель и консоль на время сбора (сенсору и брокеру они не нужны).

## 2. План и сбор

```powershell
uv run mlsiem lab plan --seed 7 --repeats 10 --out var\lab\plan.json
uv run mlsiem lab collect --plan var\lab\plan.json        # подтверждение старта, 10–11 часов
# после прерывания:
uv run mlsiem lab collect --plan var\lab\plan.json --resume
```

## 3. Набор и качество

```powershell
uv run mlsiem lab dataset build --pcap var\lab\session.pcap --journal var\lab\journal.jsonl --plan var\lab\plan.json
uv run mlsiem lab quality --dataset <версия>      # вердикт clean/suspect, перечень причин
```

## 4. Оценка

```powershell
uv run mlsiem lab evaluate --dataset <версия> --model models/ensemble --by tool,source
uv run mlsiem lab shortcuts --dataset <версия> --seeds 0 1 2
uv run mlsiem lab unknown   --dataset <версия> --model models/ensemble
```

Отчёты: `reports/lab_*_<версия>.md`; эксперименты — MLflow `lab`; итог — `docs/JOURNAL.md`.

## 5. Что считать успехом

Набор версии с ≥ 7 классами и ≥ 2 инструментами на класс, `ambiguous` ≤ 5%, вердикт качества
известен (даже `suspect`), отчёты `shortcuts` и `unknown` с интервалами, оговорка FR-023 в отчёте.
`dvc push` набора — только с вашего разрешения.
