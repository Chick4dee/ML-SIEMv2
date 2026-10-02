<#
.SYNOPSIS
    Шаг 6: машина-жертва стенда (web / SSH / FTP / DNS) с автоустановкой Ubuntu Server 24.04.

.DESCRIPTION
    Создаёт машину lab.victim.vm (фича 006, research R1–R4):
    - поколение 2, lab.victim.cpus vCPU, lab.victim.memory_mb МБ ОЗУ СТАТИЧЕСКИ;
    - диск до lab.victim.disk_gb ГБ, динамический, в var\stand\ репозитория;
    - Secure Boot с шаблоном MicrosoftUEFICertificateAuthority — с ним грузится Ubuntu;
    - адаптер «lab» в сети стенда (stand.lab_switch) и адаптер «install» в Default Switch
      (интернет на время установки) с постоянными MAC из конфига — по ним автоустановка
      различает адаптеры. Служебной сети у машины НЕТ: из стенда пути к хосту и брокеру нет;
    - два DVD: установочный образ и seed-ISO роли victim; загрузка с DVD.

    Образ Ubuntu тот же, что у брокера (20-vm-broker.ps1), заново не скачивается. Seed-ISO
    собирается командой `uv run mlsiem stand seed-iso --role victim`.

    Идемпотентен: если машина уже есть, ничего не пересоздаёт. Каждое изменение спрашивает
    подтверждение (ConfirmImpact High); -WhatIf — только показать план.

.PARAMETER Iso
    Установочный образ Ubuntu Server 24.04 live-server amd64 (тот же, что для брокера).

.PARAMETER Seed
    Seed-ISO роли victim (по умолчанию var\stand\seed-victim.iso).

.EXAMPLE
    .\stand\hyperv\40-vm-victim.ps1 -Iso D:\iso\ubuntu-24.04.3-live-server-amd64.iso -WhatIf
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
$vmName = $lab.victim.vm
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$standDir = Join-Path $repo 'var\stand'
if (-not $Seed) { $Seed = Join-Path $standDir 'seed-victim.iso' }
# Hyper-V подключает образы только по полному пути
$Iso = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Iso)
$Seed = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Seed)
$vhd = Join-Path $standDir "$vmName.vhdx"

function ConvertTo-HyperVMac([string]$mac) { ($mac -replace '[^0-9A-Fa-f]', '').ToUpper() }

if (-not (Test-Path $Iso)) { throw "нет образа $Iso — он нужен тот же, что для брокера (20-vm-broker.ps1 -Download)" }
if (-not (Test-Path $Seed)) { throw "нет seed-ISO $Seed — соберите его: uv run mlsiem stand seed-iso --role victim" }

if (Get-VM -Name $vmName -ErrorAction SilentlyContinue) {
    Write-Host "[уже есть] машина $vmName — не пересоздаю (удалить: 91-remove-lab.ps1)"
    return
}
if (-not (Get-VMSwitch -Name $cfg.lab_switch -ErrorAction SilentlyContinue)) {
    throw "нет коммутатора $($cfg.lab_switch) — сначала 10-network.ps1"
}

$what = "Gen2, $($lab.victim.cpus) vCPU, $($lab.victim.memory_mb) МБ ОЗУ статически, диск до $($lab.victim.disk_gb) ГБ ($vhd)"
if ($PSCmdlet.ShouldProcess($vmName, "Создать машину Hyper-V: $what")) {
    New-Item -ItemType Directory -Force $standDir | Out-Null
    New-VM -Name $vmName -Generation 2 -MemoryStartupBytes ([int64]$lab.victim.memory_mb * 1MB) `
        -NewVHDPath $vhd -NewVHDSizeBytes ([int64]$lab.victim.disk_gb * 1GB) -SwitchName $cfg.lab_switch | Out-Null
    Set-VMMemory -VMName $vmName -DynamicMemoryEnabled $false
    Set-VMProcessor -VMName $vmName -Count ([int]$lab.victim.cpus)
    Set-VM -Name $vmName -AutomaticCheckpointsEnabled $false
    Set-VMFirmware -VMName $vmName -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
    Write-Host "[создана] машина $vmName"
}
if ($PSCmdlet.ShouldProcess($vmName, "Адаптеры: lab ($($cfg.lab_switch), MAC $($lab.lab_mac.victim)) и install (Default Switch, MAC $($lab.lab_mac.victim_install))")) {
    $first = Get-VMNetworkAdapter -VMName $vmName | Select-Object -First 1
    Rename-VMNetworkAdapter -VMNetworkAdapter $first -NewName 'lab'
    Set-VMNetworkAdapter -VMName $vmName -Name 'lab' -StaticMacAddress (ConvertTo-HyperVMac $lab.lab_mac.victim)
    Add-VMNetworkAdapter -VMName $vmName -Name 'install' -SwitchName 'Default Switch' `
        -StaticMacAddress (ConvertTo-HyperVMac $lab.lab_mac.victim_install)
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
    Write-Host 'yes на вопрос «Continue with autoinstall?». Установка и службы — 10–15 минут; машина'
    Write-Host "перезагрузится сама. Затем: .\stand\hyperv\45-post-install.ps1 -Role victim"
}
