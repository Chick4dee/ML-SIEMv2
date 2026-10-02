# Quickstart: Лабораторный стенд и живой сенсор (006)

Проверка фичи от пустого стенда до живого инцидента и отчёта оценки. Подробности команд —
[contracts/cli.md](contracts/cli.md), решения — [research.md](research.md). Живые шаги требуют
Hyper-V, прав администратора и поднятого брокера 005.

## 0. Предусловия

- Брокер 005 поднят (`mlsiem stand check` → `0`), сети `mlsiem-mgmt` и `mlsiem-lab` есть.
- Образ Ubuntu Server 24.04 уже скачан (из 005), повторно не нужен.
- Рабочая `var/soc.db` — сделать копию `bak-005` перед первым запуском с миграцией 5 → 6.
- Быстрые тесты зелёные без ВМ: `uv run pytest -q` (захват и брокер подменены).

## 1. Проверка главного риска (зеркалирование) — до всего остального

```powershell
# макет: два гостя в mlsiem-lab + сенсорный адаптер-приёмник, ICMP между гостями
.\stand\hyperv\60-sensor-adapter.ps1 -WhatIf
```

Ожидаемо: на сенсорном интерфейсе видны кадры ICMP между жертвой и атакующим. Если нет —
переключиться на fallback R7a (отдельная ВМ-сенсор, `-Standalone`).

## 2. Поднять машины стенда (US1)

```powershell
uv run mlsiem stand seed-iso --role victim
uv run mlsiem stand seed-iso --role attacker
.\stand\hyperv\40-vm-victim.ps1   -Iso D:\iso\ubuntu-24.04-live-server-amd64.iso -Seed var\stand\seed-victim.iso
.\stand\hyperv\50-vm-attacker.ps1 -Iso D:\iso\ubuntu-24.04-live-server-amd64.iso -Seed var\stand\seed-attacker.iso
.\stand\hyperv\60-sensor-adapter.ps1
.\stand\hyperv\45-post-install.ps1 -Role victim
.\stand\hyperv\45-post-install.ps1 -Role attacker
uv run mlsiem stand check
```

Ожидаемо (US1, SC-001/SC-002): жертва `10.88.0.20` и атакующий `10.88.0.30` подняты, службы
жертвы отвечают с атакующего, изоляция подтверждена (хост/брокер/служебная/интернет недоступны),
расхождение часов ≤ 1 с. Повторный запуск скриптов — «уже есть».

## 3. Запустить сенсор и потребитель (US2)

```powershell
.\stand\hyperv\70-sensor.ps1 start      # mlsiem stream sensor start на машине, источник sensor:live
uv run mlsiem stream consume            # на хосте, онлайн-цепочка 005
uv run mlsiem stream status             # показатели сенсора: пакеты/с, потоки/с, потери, буфер
```

Ожидаемо (US2): в брокере сообщения источника `sensor:live` с адресами стенда и схемой
признаков 001; `status` показывает показатели сенсора.

После запуска сенсора под нагрузкой фоновой нормы зафиксировать задержку поток→брокер (SC-005,
см. T057a) — она считается сверх idle-таймаута экстрактора (120 с).

## 4. Контрольный сценарий → живой инцидент (US3)

```powershell
uv run mlsiem lab scenario run control_replay
# подождать ≤ 3 мин после конца сценария (idle-таймаут nfstream + цепочка)
```

Ожидаемо (US3, SC-004): в консоли (`soc-console`, порт из launch.json) инцидент с атакующей
стороной `10.88.0.30` и целью `10.88.0.20` не позже 3 мин после конца сценария. Отчёт:

```powershell
uv run mlsiem lab report --run <run_uid>
```

Сценарий, направленный вне `mlsiem-lab`, отклоняется до первого пакета (US3 п. 3). Подтверждение
действия SOAR по инциденту стенда — только симуляция (US3 п. 5, конституция V).

## 5. Фоновая норма и набор (US4)

```powershell
uv run mlsiem lab normal start
# ... дать поработать (цель SC-007: ≥ 1 ч нормы, ≥ 3 запуска каждого сценария) ...
uv run mlsiem lab scenario run port_scan
uv run mlsiem lab scenario run web_fuzz
uv run mlsiem lab scenario run ssh_bruteforce
uv run mlsiem lab scenario run web_dos
uv run mlsiem lab normal stop
.\stand\hyperv\70-sensor.ps1 stop
uv run mlsiem lab dataset build
```

Ожидаемо (US4): набор `data/lab/<версия>/` в схеме 001, метки benign/класс/ambiguous, отчёт с
долей ambiguous (≤ 5% потоков сценариев, SC-007), потери сенсора и ложные алерты/инциденты на
норме.

## 6. Честная оценка модели (US5)

```powershell
uv run mlsiem lab evaluate --dataset <версия> --run <run_id>
```

Ожидаемо (US5, SC-008): отчёт `reports/lab_eval_<версия>.{md,json}` — PR-AUC (macro и
«атака/нет»), поимка по сценариям, FPR на норме, порог тот же, что на валидации 001; для
непойманных сценариев — разбор (вне таксономии / вне распределения / потери). Запись в MLflow
(эксперимент `lab`) и `docs/JOURNAL.md`. Результат записывается, даже если плохой (конституция III).

## 7. Демо одной командой

```powershell
uv run mlsiem lab demo
```

Ожидаемо (US3 п. 6): проверка готовности → `control_replay` → остальные сценарии по порядку →
сводка «сценарий → обнаружен/нет → инцидент».

## 8. Регрессия и уборка

```powershell
uv run pytest -q                                   # 001–007 зелёные (FR-027)
uv run pytest -m "stand or lab" -q                 # живые проверки — только при поднятом стенде
.\stand\hyperv\91-remove-lab.ps1                   # удалить ВМ стенда (брокер и сети 005 остаются)
```
