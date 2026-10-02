<#
.SYNOPSIS
    Шаг 8: сенсор — зеркалирование трафика сети стенда на брокерную машину (или отдельную ВМ).

.DESCRIPTION
    Поднимает приём зеркала портов Hyper-V, чтобы живой сенсор видел весь трафик сети стенда
    (фича 006, research R7 — ГЛАВНЫЙ РИСК фичи):
    - брокерной машине (stand.vm_name) добавляется второй адаптер «sensor» в сети стенда
      (stand.lab_switch) БЕЗ IP-адреса, в режиме приёмника зеркала
      (Set-VMNetworkAdapter -PortMirroring Destination). Сенсор слышит стенд, но своего
      адреса в нём не имеет — изоляция цела (FR-006);
    - адаптерам жертвы и атакующего в сети стенда ставится режим источника зеркала
      (-PortMirroring Source): их кадры копируются на сенсорный адаптер;
    - брокерной машине добавляется lab.sensor.extra_memory_mb МБ ОЗУ под сенсор (R7).

    Порт-мирроринг Hyper-V работает между адаптерами ОДНОГО виртуального коммутатора — здесь
    все три на stand.lab_switch, в том числе на Private-коммутаторе.

    -Standalone (запасной путь R7a): если зеркало на этой сборке Hyper-V не доставляет кадры,
    создаётся отдельная лёгкая ВМ-сенсор (lab.sensor.vm) с адаптером-приёмником в сети стенда
    вместо адаптера на брокере; остальной план не меняется. Для -Standalone нужны -Iso и -Seed
    (seed-ISO роли broker: на сенсорной ВМ тот же пакет).

    Идемпотентен: повторный запуск сообщает «уже есть». Каждое изменение — с подтверждением;
    -WhatIf — только план.

.EXAMPLE
    .\stand\hyperv\60-sensor-adapter.ps1 -WhatIf
    .\stand\hyperv\60-sensor-adapter.ps1
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch]$Standalone,
    [string]$Iso,
    [string]$Seed
)
$ErrorActionPreference = 'Stop'
$cfg = & "$PSScriptRoot\Read-StreamConfig.ps1"
$lab = $cfg.lab
if (-not $lab) { throw 'в configs/stream.yaml нет раздела lab' }

function ConvertTo-HyperVMac([string]$mac) { ($mac -replace '[^0-9A-Fa-f]', '').ToUpper() }

# Источники зеркала: адаптеры жертвы и атакующего в сети стенда
function Set-MirrorSource($vmName) {
    $ad = Get-VMNetworkAdapter -VMName $vmName -ErrorAction SilentlyContinue |
        Where-Object { $_.SwitchName -eq $cfg.lab_switch } | Select-Object -First 1
    if (-not $ad) { Write-Host "[нет] у $vmName адаптера в $($cfg.lab_switch) — пропускаю"; return }
    if ($ad.PortMirroringMode -eq 'Source') { Write-Host "[уже] $vmName — источник зеркала"; return }
    if ($PSCmdlet.ShouldProcess("$vmName/$($ad.Name)", 'Режим источника зеркала (Source)')) {
        Set-VMNetworkAdapter -VMNetworkAdapter $ad -PortMirroring Source
        Write-Host "[источник] $vmName"
    }
}

Set-MirrorSource $lab.victim.vm
Set-MirrorSource $lab.attacker.vm

if (-not $Standalone) {
    # Приёмник зеркала — второй адаптер брокерной машины, без IP
    $broker = $cfg.vm_name
    if (-not (Get-VM -Name $broker -ErrorAction SilentlyContinue)) {
        throw "нет брокерной машины $broker — сначала 20-vm-broker.ps1 (или запустите с -Standalone)"
    }
    $sensor = Get-VMNetworkAdapter -VMName $broker -Name 'sensor' -ErrorAction SilentlyContinue
    if ($sensor) { Write-Host "[уже есть] адаптер sensor у $broker" }
    elseif ($PSCmdlet.ShouldProcess($broker, "Адаптер sensor в $($cfg.lab_switch) без IP, приёмник зеркала (MAC $($lab.lab_mac.sensor))")) {
        Add-VMNetworkAdapter -VMName $broker -Name 'sensor' -SwitchName $cfg.lab_switch `
            -StaticMacAddress (ConvertTo-HyperVMac $lab.lab_mac.sensor)
        Set-VMNetworkAdapter -VMName $broker -Name 'sensor' -PortMirroring Destination
        Write-Host "[создан] приёмник зеркала sensor у $broker"
    }
    # Память под сенсор
    $mb = [int]$lab.sensor.extra_memory_mb
    if ($mb -gt 0) {
        $want = [int64]($cfg.memory_mb + $mb) * 1MB
        $cur = (Get-VMMemory -VMName $broker).Startup
        if ($cur -lt $want) {
            if ($PSCmdlet.ShouldProcess($broker, "Добавить $mb МБ ОЗУ под сенсор (итого $([int]($want/1MB)) МБ)")) {
                if ((Get-VM -Name $broker).State -ne 'Off') {
                    Write-Host "[!] память меняется на выключенной машине — остановите $broker и повторите"
                }
                else { Set-VMMemory -VMName $broker -StartupBytes $want; Write-Host "[память] $broker +$mb МБ" }
            }
        }
        else { Write-Host "[уже] у $broker достаточно памяти под сенсор" }
    }
    Write-Host ''
    Write-Host "Зеркало поднято. Проверьте на брокерной машине, что сенсорный интерфейс видит трафик:"
    Write-Host "  sudo tcpdump -i $($lab.sensor.iface) -c 5   (должны идти кадры жертвы/атакующего)"
    Write-Host "Если кадров нет — зеркало на этой сборке Hyper-V не доставляется: повторите с -Standalone (R7a)."
    return
}

# ------------------------------------------------ R7a: отдельная ВМ-сенсор
$vmName = $lab.sensor.vm
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$standDir = Join-Path $repo 'var\stand'
if (Get-VM -Name $vmName -ErrorAction SilentlyContinue) {
    Write-Host "[уже есть] ВМ-сенсор $vmName — не пересоздаю (удалить: 91-remove-lab.ps1)"
    return
}
if (-not $Iso) { throw 'для -Standalone нужен -Iso (тот же образ Ubuntu) и -Seed (seed-ISO роли broker)' }
if (-not $Seed) { $Seed = Join-Path $standDir 'seed.iso' }
$Iso = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Iso)
$Seed = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Seed)
$vhd = Join-Path $standDir "$vmName.vhdx"
if (-not (Test-Path $Iso)) { throw "нет образа $Iso" }
if (-not (Test-Path $Seed)) { throw "нет seed-ISO $Seed" }

$what = "Gen2, 1 vCPU, 768 МБ ОЗУ статически, диск до 10 ГБ ($vhd)"
if ($PSCmdlet.ShouldProcess($vmName, "Создать отдельную ВМ-сенсор (R7a): $what")) {
    New-Item -ItemType Directory -Force $standDir | Out-Null
    New-VM -Name $vmName -Generation 2 -MemoryStartupBytes (768MB) `
        -NewVHDPath $vhd -NewVHDSizeBytes (10GB) -SwitchName $cfg.lab_switch | Out-Null
    Set-VMMemory -VMName $vmName -DynamicMemoryEnabled $false
    Set-VM -Name $vmName -AutomaticCheckpointsEnabled $false
    Set-VMFirmware -VMName $vmName -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
    Write-Host "[создана] ВМ-сенсор $vmName"
}
if ($PSCmdlet.ShouldProcess($vmName, "Адаптер-приёмник зеркала sensor в $($cfg.lab_switch) (MAC $($lab.lab_mac.sensor))")) {
    $first = Get-VMNetworkAdapter -VMName $vmName | Select-Object -First 1
    Rename-VMNetworkAdapter -VMNetworkAdapter $first -NewName 'sensor'
    Set-VMNetworkAdapter -VMName $vmName -Name 'sensor' -StaticMacAddress (ConvertTo-HyperVMac $lab.lab_mac.sensor) -PortMirroring Destination
}
if ($PSCmdlet.ShouldProcess($vmName, "Подключить DVD: $Iso и $Seed, загрузка с DVD")) {
    Add-VMDvdDrive -VMName $vmName -Path $Iso
    Add-VMDvdDrive -VMName $vmName -Path $Seed
    $dvd = Get-VMDvdDrive -VMName $vmName | Where-Object { $_.Path -eq $Iso } | Select-Object -First 1
    Set-VMFirmware -VMName $vmName -FirstBootDevice $dvd
    Write-Host "[готово] ВМ-сенсор $vmName — запустите её и установите так же, как брокер (R7a)"
}
