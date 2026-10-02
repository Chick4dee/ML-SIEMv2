<#
.SYNOPSIS
    Шаг после установки машины стенда (жертва или атакующий): отрезать от интернета, проверить.

.DESCRIPTION
    После того как автоустановка машины роли завершилась (фича 006):
    - отключает адаптер «install» (Default Switch): интернет был нужен только для пакетов,
      дальше машина живёт ТОЛЬКО в сети стенда (изоляция, FR-005);
    - извлекает оба DVD и ставит загрузку с диска;
    - включает службу синхронизации времени Hyper-V (часы гостя от хоста — машины стенда без
      сети, NTP им неоткуда взять; расхождение часов ломает разметку набора, R13);
    - запускает `uv run mlsiem stand check` (проверит и эту машину, если поднят весь стенд).

    Идемпотентен. Каждое изменение спрашивает подтверждение; -WhatIf — только план.

.PARAMETER Role
    Какая машина: victim или attacker.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidateSet('victim', 'attacker')][string]$Role
)
$ErrorActionPreference = 'Stop'
$cfg = & "$PSScriptRoot\Read-StreamConfig.ps1"
$lab = $cfg.lab
if (-not $lab) { throw 'в configs/stream.yaml нет раздела lab' }
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$vmName = if ($Role -eq 'victim') { $lab.victim.vm } else { $lab.attacker.vm }

$vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
if (-not $vm) { throw "нет машины $vmName — сначала 40-vm-victim.ps1 / 50-vm-attacker.ps1" }

$install = Get-VMNetworkAdapter -VMName $vmName -Name 'install' -ErrorAction SilentlyContinue
if ($install -and $install.SwitchName) {
    if ($PSCmdlet.ShouldProcess("$vmName/install", 'Отключить адаптер Default Switch (машина больше не ходит в интернет)')) {
        Disconnect-VMNetworkAdapter -VMName $vmName -Name 'install'
        Write-Host '[отключён] адаптер install'
    }
}
else { Write-Host '[уже] адаптер install отключён' }

$dvds = Get-VMDvdDrive -VMName $vmName | Where-Object { $_.Path }
if ($dvds) {
    if ($PSCmdlet.ShouldProcess($vmName, 'Извлечь DVD (образ Ubuntu и seed-ISO), загрузка с диска')) {
        $dvds | Set-VMDvdDrive -Path $null
        $disk = Get-VMHardDiskDrive -VMName $vmName | Select-Object -First 1
        Set-VMFirmware -VMName $vmName -FirstBootDevice $disk
        Write-Host '[извлечены] DVD'
    }
}
else { Write-Host '[уже] DVD извлечены' }

# Служба времени Hyper-V: гость синхронизирует часы с хостом без сети (R13)
$timeSvc = Get-VMIntegrationService -VMName $vmName | Where-Object { $_.Name -like '*Time*' -or $_.Name -like '*врем*' }
if ($timeSvc -and -not $timeSvc.Enabled) {
    if ($PSCmdlet.ShouldProcess($vmName, 'Включить службу синхронизации времени Hyper-V (часы гостя от хоста)')) {
        $timeSvc | Enable-VMIntegrationService
        Write-Host '[включена] синхронизация времени'
    }
}
else { Write-Host '[уже] синхронизация времени включена' }

Push-Location $repo
try { & uv run mlsiem stand check; exit $LASTEXITCODE }
finally { Pop-Location }
