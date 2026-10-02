# Брокерная машина стенда: пошаговая инструкция (фича 005)

Здесь — PowerShell-скрипты, которые создают на хосте Windows (Hyper-V) Linux-машину
`mlsiem-broker` с Apache Kafka и сети стенда. Все имена, адреса и ресурсы берутся из
`configs/stream.yaml` (раздел `stand`) через `Read-StreamConfig.ps1` — в скриптах их нет.

Правила, которых держатся все скрипты:

- **ничего не меняется без подтверждения**: у каждого меняющего шага — вопрос
  (`ConfirmImpact = High`); `-WhatIf` показывает план, не меняя ничего;
- **повторный запуск безопасен**: готовое пропускается с пометкой «уже есть»;
- запускать **от администратора** (Hyper-V и сетевые адаптеры иначе не меняются);
- Windows PowerShell 5.1, файлы в UTF-8 с BOM (иначе кириллица в 5.1 ломается).

## Что будет создано и сколько займёт

| Что | Ресурсы |
|---|---|
| коммутатор `mlsiem-mgmt` (Internal) — служебная сеть: хост `10.77.0.1`, брокер `10.77.0.10` | адаптер vEthernet на хосте |
| коммутатор `mlsiem-lab` (Private) — сеть стенда для фичи 006, **брокера в ней нет** | — |
| машина `mlsiem-broker`: Gen 2, Secure Boot (UEFI CA), 2 vCPU | **2 ГБ ОЗУ статически** |
| диск машины `var\stand\mlsiem-broker.vhdx` (динамический) | **до 20 ГБ** |
| образ Ubuntu Server 24.04 live-server (скачивается один раз) | **~3 ГБ** |
| seed-ISO автоустановки `var\stand\seed.iso` | ~100 КБ |

Хосту после этого должно оставаться ≥ 4 ГБ свободной памяти (SC-007) — это проверяет шаг 0.

## Порядок

```powershell
# 0. Проверки и план — ничего не меняет. Код 1 — есть препятствия (перечислены)
.\stand\hyperv\00-check.ps1 -Iso D:\iso\ubuntu-24.04.3-live-server-amd64.iso

# 1. SSH-ключ хоста (если его ещё нет) и seed-ISO автоустановки (только файл)
ssh-keygen -t ed25519
uv run mlsiem stand seed-iso

# 2. Сети: служебная (Internal) с адресом хоста и сеть стенда (Private)
.\stand\hyperv\10-network.ps1 -WhatIf     # посмотреть план
.\stand\hyperv\10-network.ps1             # выполнить (спросит подтверждение на каждый шаг)

# 3. Машина. Образ Ubuntu — укажите скачанный или добавьте -Download (скачает ~3 ГБ с
#    releases.ubuntu.com и сверит SHA-256 по SHA256SUMS — тоже после подтверждения)
.\stand\hyperv\20-vm-broker.ps1 -Iso D:\iso\ubuntu-24.04.3-live-server-amd64.iso

# 4. Консоль машины (vmconnect localhost mlsiem-broker): ответить yes на
#    «Continue with autoinstall?». Дальше без участия: установка ОС (пакеты — через
#    Default Switch), перезагрузка, установка Kafka (архив с downloads.apache.org, проверка
#    SHA-512), брандмауэр, топики. 10–20 минут.

# 5. После установки: отключить Default Switch, извлечь образы, проверить брокер
.\stand\hyperv\30-post-install.ps1

# Проверка в любой момент (только чтение)
uv run mlsiem stand check
```

Ожидаемый результат `stand check`: адрес хоста на `vEthernet (mlsiem-mgmt)`, брокер доступен,
топики `mlsiem.flows` и `mlsiem.flows.rejected` со сроком хранения 168 ч, у машины нет адаптера
в `mlsiem-lab`. Если машина выключена — «брокер недоступен за 10 с — машина выключена?
Start-VM mlsiem-broker».

## Изоляция (FR-003a)

- у брокерной машины адаптеры только `mgmt` (служебная сеть) и `install` (Default Switch,
  отключается шагом 5); в сети стенда `mlsiem-lab` её нет вовсе;
- `mlsiem-lab` — Private: туда не входит даже хост, трафик атак 006 не выйдет за стенд;
- на самой машине — ufw: порт 9092 только из `10.77.0.0/24`, SSH только с `10.77.0.1`.
  Kafka без аутентификации — защита именно изоляцией сетей (вне объёма 005).

## Пересоздать и удалить

```powershell
.\stand\hyperv\90-remove.ps1 -WhatIf      # что будет удалено
.\stand\hyperv\90-remove.ps1              # машина, её диск, адрес хоста, коммутаторы — по шагу
```

После удаления шаги 2–5 дают тот же результат: адреса, MAC-адреса адаптеров, cluster id
Kafka и топики фиксированы в конфиге.

## Если что-то пошло не так

- журнал установки Kafka на машине — `/var/log/mlsiem-install-kafka.log`; повторить установку
  можно командой `sudo bash /usr/local/sbin/mlsiem-install-kafka.sh` (она идемпотентна);
- SSH на машину: `ssh mlsiem@10.77.0.10` (ключ хоста, пароля нет);
- `stand check` пишет «изоляция не проверена» — запустите его от администратора или
  участника группы «Администраторы Hyper-V».

## Машины стенда и сенсор (006)

Поверх брокера и сетей 005 поднимаются две машины в сети стенда `mlsiem-lab` (Private) —
**жертва** и **атакующий** — и **живой сенсор** на брокерной машине. Полная проверка от
пустого стенда до оценки модели — в
[specs/006-lab-stand-live-sensor/quickstart.md](../../specs/006-lab-stand-live-sensor/quickstart.md).

Те же правила, что у брокера: запуск **от администратора**, каждый меняющий шаг спрашивает
подтверждение, `-WhatIf` — только план, повторный запуск безопасен, значения — только из
`configs/stream.yaml` (раздел `lab`).

### Что создаётся и сколько займёт

| Что | Ресурсы |
|---|---|
| машина `mlsiem-victim` (web/SSH/FTP/DNS) в сети стенда, Gen 2, 1 vCPU | **1 ГБ ОЗУ статически**, диск до 10 ГБ |
| машина `mlsiem-attacker` (nmap, ffuf, hydra, slowhttptest, tcpreplay) + COM-порт управления | **1 ГБ ОЗУ статически**, диск до 10 ГБ |
| сенсорный адаптер брокерной машины в `mlsiem-lab` без IP (приёмник зеркала) | **+1 ГБ ОЗУ** брокеру |
| две seed-ISO автоустановки `var\stand\seed-victim.iso`, `seed-attacker.iso` | ~0,1–0,5 МБ |

Образ Ubuntu тот же, что у брокера, — заново не скачивается. При всех поднятых машинах хосту
должно оставаться **≥ 4 ГБ** свободной памяти (SC-009) — это проверяет `stand check`.

### Изоляция (FR-005)

- у машин стенда адаптер только в `mlsiem-lab` (на время установки — ещё Default Switch, его
  отключает шаг пост-установки); служебной сети у них нет — из стенда к хосту и брокеру
  пути нет;
- хост управляет атакующим по **COM-порту** его ВМ (канал гипервизора, не сеть), а не по SSH;
- сенсор слышит сеть стенда через **зеркало портов** Hyper-V, своего адреса в ней не имея;
- `mlsiem lab scenario run` отклоняет сценарий, если хоть одна цель вне `mlsiem-lab`.

### Порядок

```powershell
# Сети и брокер (005) уже должны быть подняты: 10-network.ps1, 20-vm-broker.ps1, 30-post-install.ps1

# 6. Seed-ISO жертвы и атакующего (только файлы)
uv run mlsiem stand seed-iso --role victim
uv run mlsiem stand seed-iso --role attacker

# 7. Машина-жертва. Образ Ubuntu — тот же, что у брокера
.\stand\hyperv\40-vm-victim.ps1 -Iso D:\iso\ubuntu-24.04.3-live-server-amd64.iso -WhatIf
.\stand\hyperv\40-vm-victim.ps1 -Iso D:\iso\ubuntu-24.04.3-live-server-amd64.iso
#    консоль (vmconnect localhost mlsiem-victim) → yes на «Continue with autoinstall?»; затем:
.\stand\hyperv\45-post-install.ps1 -Role victim

# 8. Машина-атакующий (аналогично), с каналом управления по COM-порту
.\stand\hyperv\50-vm-attacker.ps1 -Iso D:\iso\ubuntu-24.04.3-live-server-amd64.iso
.\stand\hyperv\45-post-install.ps1 -Role attacker

# 9. Зеркало портов на сенсор (главный риск — проверить первым, см. quickstart §1)
.\stand\hyperv\60-sensor-adapter.ps1 -WhatIf
.\stand\hyperv\60-sensor-adapter.ps1
#    Если зеркало на этой сборке Hyper-V не доставляет кадры — отдельная ВМ-сенсор (R7a):
.\stand\hyperv\60-sensor-adapter.ps1 -Standalone -Iso D:\iso\ubuntu-24.04.3-live-server-amd64.iso

# Проверка всего стенда (брокер + машины + изоляция + часы + память)
uv run mlsiem stand check

# Сенсор и сценарии
.\stand\hyperv\70-sensor.ps1 start           # живой сенсор на брокерной машине
uv run mlsiem lab demo                        # готовность → контрольный сценарий → остальные
.\stand\hyperv\70-sensor.ps1 stop

# Удалить только машины стенда 006 (брокер и сети 005 не трогает)
.\stand\hyperv\91-remove-lab.ps1 -WhatIf
.\stand\hyperv\91-remove-lab.ps1
```

Скрипты `80-scenario.ps1` и `lib-com.ps1` вызываются самим `mlsiem` (канал управления
атакующим), вручную их запускать не нужно.
