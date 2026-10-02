<#
.SYNOPSIS
    Управление живым сенсором на брокерной (или отдельной) машине: start | stop | status.

.DESCRIPTION
    Вызывает команды `mlsiem stream sensor …` на машине, где живёт сенсор (фича 006, R7),
    и возвращает их вывод на хост (FR-010). Сенсорная машина стоит в служебной сети (у брокера
    она есть), поэтому управление идёт по SSH ключом хоста — это НЕ сеть стенда, изоляция не
    нарушается (сам сенсор без адреса в сети стенда). Для отдельной ВМ-сенсора (R7a) тоже SSH.

    start запускает сенсор (слушает зеркало на lab.sensor.iface), stop завершает сеанс,
    status печатает показатели сенсора. Идемпотентность — на стороне самих команд mlsiem
    (перезапуск продолжает тот же сеанс, FR-018).

.PARAMETER Action
    start | stop | status.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('start', 'stop', 'status')][string]$Action
)
$ErrorActionPreference = 'Stop'
$cfg = & "$PSScriptRoot\Read-StreamConfig.ps1"
$lab = $cfg.lab
if (-not $lab) { throw 'в configs/stream.yaml нет раздела lab' }

# Где живёт сенсор: на брокерной машине (R7) или на отдельной ВМ-сенсоре (R7a). Обе в
# служебной сети, адрес берём по admin_user@<адрес>. Для брокера адрес известен (stand), для
# отдельной ВМ-сенсора — тот же служебный адрес брокера не годится, поэтому R7a требует
# задать адрес сенсора вручную в конфиге при переходе на запасной путь.
$target = if ($lab.sensor.placement -eq 'broker') { "$($cfg.admin_user)@$($cfg.broker_ip)" }
    else { throw 'сенсор на отдельной ВМ (placement=vm): укажите её служебный адрес и путь SSH вручную (R7a)' }

$remote = "cd /opt/mlsiem && uv run mlsiem stream sensor $Action --iface $($lab.sensor.iface)"
if ($Action -ne 'start') { $remote = "cd /opt/mlsiem && uv run mlsiem stream sensor $Action" }

Write-Host "sensor $Action → $target"
& ssh -o ConnectTimeout=10 $target $remote
exit $LASTEXITCODE
