# Quickstart: проверка фичи 005

Сценарии, доказывающие, что потоковая цепочка работает сквозным путём. Команды — из корня
репозитория. Контракты — [contracts/](contracts/), поля — [data-model.md](data-model.md).

## 0. Предусловия

- Данные 001, модель 004 (`models/ensemble` или `models/detector`), база `var/soc.db` схемы 3.
  Перед первым запуском 005 — копия: `copy var\soc.db var\soc.db.bak-004`.
- Hyper-V включён; PowerShell **от администратора** для скриптов `stand/hyperv/`.
- Образ Ubuntu Server 24.04 LTS (live-server, amd64) скачан с ubuntu.com, SHA-256 сверен
  (`Get-FileHash`). Скрипт может скачать его сам — только после подтверждения.
- SSH-ключ хоста: `ssh-keygen -t ed25519` (если ещё нет).

## 1. Быстрые тесты (без ВМ)

```bash
uv run pytest
```

Все тесты 002–004 и новые тесты 005 на брокере-заглушке зелёные; `uv run ruff check .` чистый.

## 2. Брокерная машина (US1, SC-001)

```powershell
.\stand\hyperv\00-check.ps1                    # план и ресурсы, ничего не меняет
uv run mlsiem stand seed-iso                  # var\stand\seed.iso
.\stand\hyperv\10-network.ps1                  # подтвердить: 2 коммутатора, адрес хоста 10.77.0.1
.\stand\hyperv\20-vm-broker.ps1 -Iso <путь к ubuntu.iso> -Seed var\stand\seed.iso
# в консоли ВМ один раз ответить «yes» на «Continue with autoinstall?»; дождаться перезагрузки
.\stand\hyperv\30-post-install.ps1             # отключить установочную сеть, проверить брокер
uv run mlsiem stand check
```

Ожидание: `stand check` — брокер доступен, версия Kafka 4.x, топики `mlsiem.flows` и
`mlsiem.flows.rejected`, у ВМ нет адаптера в `mlsiem-lab`. Повторный запуск `10-network.ps1` и
`20-vm-broker.ps1` — «уже есть», без изменений. `Stop-VM mlsiem-broker` → `stand check` за ≤ 10 с
пишет «брокер недоступен» с подсказкой.

## 3. Онлайн-цепочка в реальном времени (US2, US3, SC-003)

Терминал 1: `uv run mlsiem soc serve`. Терминал 2: `uv run mlsiem stream consume`.
Терминал 3:

```bash
uv run mlsiem stream replay --split unsw_time --part test --speed 60
```

Ожидание: в консоли появляется сеанс «поток · идёт»; инциденты появляются и растут по ходу
проигрывания; блок «Поток» на панели показывает потоков/с, отставание около нуля, задержку p95
≤ 5 с. После `end` сеанс — «завершён».

## 4. Скорость и эквивалентность (SC-002, SC-004)

```bash
uv run mlsiem stream replay --split unsw_time --part test --speed max
uv run mlsiem soc run --split unsw_time --part test          # пакетный прогон того же входа
uv run mlsiem stream compare --session <run_id сеанса> --batch <run_id пакетного>
```

Ожидание: обработка ≤ 10 мин, отставание к концу проигрывания ≤ 30 с; `compare` — «эквивалентно»
(вердикты, инциденты, действия совпадают).

## 5. Перезапуски и дубли (US4, SC-005, SC-006)

Во время `replay --speed max` трижды прервать `stream consume` (Ctrl+C или закрыть окно) и
запустить снова; затем `stream compare` с пакетным прогоном → «эквивалентно», дублей алертов нет.
Отправить повторно часть сообщений (`replay --resume <source_id>` после ручной отмены) → число
алертов сеанса не меняется. Отправить битое сообщение (тестовая команда из tasks) → оно в
`mlsiem.flows.rejected`, потребитель работает дальше, счётчик «отвергнутых» +1.

## 6. Решения аналитика во время потока (FR-017)

Во время проигрывания ×60 закрыть в консоли растущий инцидент как «подтверждён». Ожидание:
статус и резолюция не меняются, в карточке — «новые алерты после решения: N», фильтр списка их
находит, в аудите — `incident_updated` с `after_decision`.

## 7. Ресурсы (SC-007)

Во время §4: диспетчер задач — ВМ + потребитель + консоль, свободной памяти хоста ≥ 4 ГБ.

## 8. Журнал

Запись в `docs/JOURNAL.md`: время подъёма стенда, скорость и задержки, результат сравнения,
перезапуски, находки.
