<#
.SYNOPSIS
    Шаг 7: машина-атакующий стенда и канал управления ею с хоста.

.DESCRIPTION
    Создаёт машину lab.attacker.vm (фича 006, research R1, R5, R6):
    - поколение 2, lab.attacker.cpus vCPU, lab.attacker.memory_mb МБ ОЗУ СТАТИЧЕСКИ;
    - диск до lab.attacker.disk_gb ГБ, динамический, в var\stand\;
    - Secure Boot (UEFI CA), адаптеры «lab» (stand.lab_switch) и «install» (Default Switch,
      на время установки) с постоянными MAC из конфига. Служебной сети у машины НЕТ — из
      сети стенда к хосту и брокеру пути нет (изоляция, FR-005);
    - COM-порт 1 → именованный канал \\.\pipe\<машина>-com1: по нему хост отдаёт команды
      раннеру сценариев (сети между хостом и стендом нет, R6). PowerShell Direct к Linux-гостю
      не работает, поэтому именованный канал COM-порта — основной путь управления;
    - два DVD: установочный образ и seed-ISO роли attacker; загрузка с DVD.

    Инструменты и раннер ставит автоустановка (seed-iso --role attacker). Идемпотентен: если
    машина уже есть, ничего не пересоздаёт. Каждое изменение спрашивает подтверждение
    (ConfirmImpact High); -WhatIf — только показать план.

.PARAMETER Iso
    Установочный образ Ubuntu Server 24.04 live-server amd64 (тот же, что для брокера).

.PARAMETER Seed
    Seed-ISO роли attacker (по умолчанию var\stand\seed-attacker.iso).

.EXAMPLE
    .\stand\hyperv\50-vm-attacker.ps1 -Iso D:\iso\ubuntu-24.04.3-live-server-amd64.iso -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$Iso,
    [string]$Seed
)
$ErrorActionPreference = 'Stop'
$cfg = & "$PSScriptRoot\Read-StreamConfig.ps1"
$lab = $cfg.lab
if (-not $lab) { throw 'в configs/stream.yaml нет раздела lab — машины стенда описываются там' }
$vmName = $lab.attacker.vm
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$standDir = Join-Path $repo 'var\stand'
if (-not $Seed) { $Seed = Join-Path $standDir 'seed-attacker.iso' }
$Iso = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Iso)
$Seed = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Seed)
$vhd = Join-Path $standDir "$vmName.vhdx"
# Именованный канал COM-порта: его же имя ждёт 80-scenario.ps1
$pipe = "\\.\pipe\$vmName-com1"

function ConvertTo-HyperVMac([string]$mac) { ($mac -replace '[^0-9A-Fa-f]', '').ToUpper() }

if (-not (Test-Path $Iso)) { throw "нет образа $Iso — он нужен тот же, что для брокера (20-vm-broker.ps1 -Download)" }
if (-not (Test-Path $Seed)) { throw "нет seed-ISO $Seed — соберите его: uv run mlsiem stand seed-iso --role attacker" }

if (Get-VM -Name $vmName -ErrorAction SilentlyContinue) {
    Write-Host "[уже есть] машина $vmName — не пересоздаю (удалить: 91-remove-lab.ps1)"
    return
}
if (-not (Get-VMSwitch -Name $cfg.lab_switch -ErrorAction SilentlyContinue)) {
    throw "нет коммутатора $($cfg.lab_switch) — сначала 10-network.ps1"
}

$what = "Gen2, $($lab.attacker.cpus) vCPU, $($lab.attacker.memory_mb) МБ ОЗУ статически, диск до $($lab.attacker.disk_gb) ГБ ($vhd)"
if ($PSCmdlet.ShouldProcess($vmName, "Создать машину Hyper-V: $what")) {
    New-Item -ItemType Directory -Force $standDir | Out-Null
    New-VM -Name $vmName -Generation 2 -MemoryStartupBytes ([int64]$lab.attacker.memory_mb * 1MB) `
        -NewVHDPath $vhd -NewVHDSizeBytes ([int64]$lab.attacker.disk_gb * 1GB) -SwitchName $cfg.lab_switch | Out-Null
    Set-VMMemory -VMName $vmName -DynamicMemoryEnabled $false
    Set-VMProcessor -VMName $vmName -Count ([int]$lab.attacker.cpus)
    Set-VM -Name $vmName -AutomaticCheckpointsEnabled $false
    Set-VMFirmware -VMName $vmName -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
    Write-Host "[создана] машина $vmName"
}
if ($PSCmdlet.ShouldProcess($vmName, "Адаптеры: lab ($($cfg.lab_switch), MAC $($lab.lab_mac.attacker)) и install (Default Switch, MAC $($lab.lab_mac.attacker_install))")) {
    $first = Get-VMNetworkAdapter -VMName $vmName | Select-Object -First 1
    Rename-VMNetworkAdapter -VMNetworkAdapter $first -NewName 'lab'
    Set-VMNetworkAdapter -VMName $vmName -Name 'lab' -StaticMacAddress (ConvertTo-HyperVMac $lab.lab_mac.attacker)
    Add-VMNetworkAdapter -VMName $vmName -Name 'install' -SwitchName 'Default Switch' `
        -StaticMacAddress (ConvertTo-HyperVMac $lab.lab_mac.attacker_install)
}
# Канал управления: COM-порт гипервизора, не сеть. Так хост запускает сценарии, не нарушая изоляцию
if ($PSCmdlet.ShouldProcess($vmName, "COM-порт 1 → именованный канал $pipe (канал управления, R6)")) {
    Set-VMComPort -VMName $vmName -Number 1 -Path $pipe
}
if ($PSCmdlet.ShouldProcess($vmName, "Подключить DVD: $Iso и $Seed, загрузка с DVD")) {
    Add-VMDvdDrive -VMName $vmName -Path $Iso
    Add-VMDvdDrive -VMName $vmName -Path $Seed
    $dvd = Get-VMDvdDrive -VMName $vmName | Where-Object { $_.Path -eq $Iso } | Select-Object -First 1
    Set-VMFirmware -VMName $vmName -FirstBootDevice $dvd
}
if ($PSCmdlet.ShouldProcess($vmName, 'Запустить машину (начнётся установка Ubuntu)')) {
    Start-VM -Name $vmName
    Write-Host ''
    Write-Host "Машина запущена. Откройте её консоль (vmconnect localhost $vmName) и ответьте"
    Write-Host 'yes на вопрос «Continue with autoinstall?». Установка, инструменты и раннер — 10–15 минут;'
    Write-Host "машина перезагрузится сама. Затем: .\stand\hyperv\45-post-install.ps1 -Role attacker"
}
