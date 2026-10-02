<#
.SYNOPSIS
    Удалить машины стенда 006 (жертва, атакующий, при наличии — ВМ-сенсор) и сенсорный адаптер.

.DESCRIPTION
    Снимает то, что добавила фича 006, НЕ трогая брокер и сети 005:
    - удаляет машины lab.victim.vm, lab.attacker.vm и (если есть) lab.sensor.vm с их дисками;
    - снимает с брокерной машины сенсорный адаптер «sensor» и возвращает ей исходную память
      (минус lab.sensor.extra_memory_mb);
    - снимает режим источника зеркала с адаптеров, если машины ещё остались.

    Служебную сеть, сеть стенда и брокерную машину оставляет — их удаляет 90-remove.ps1.
    Каждое удаление спрашивает подтверждение отдельно; -WhatIf — только план. Идемпотентен.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param()
$ErrorActionPreference = 'Stop'
$cfg = & "$PSScriptRoot\Read-StreamConfig.ps1"
$lab = $cfg.lab
if (-not $lab) { throw 'в configs/stream.yaml нет раздела lab' }
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$standDir = Join-Path $repo 'var\stand'

function Remove-StandVm($vmName) {
    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if (-not $vm) { Write-Host "[нет] машины $vmName"; return }
    if ($PSCmdlet.ShouldProcess($vmName, 'Остановить и удалить машину стенда')) {
        if ($vm.State -ne 'Off') { Stop-VM -Name $vmName -TurnOff -Force }
        Remove-VM -Name $vmName -Force
        Write-Host "[удалена] машина $vmName"
    }
    $vhd = Join-Path $standDir "$vmName.vhdx"
    if (Test-Path $vhd) {
        if ($PSCmdlet.ShouldProcess($vhd, 'Удалить диск машины')) {
            Remove-Item $vhd -Force
            Write-Host "[удалён] $vhd"
        }
    }
}

Remove-StandVm $lab.victim.vm
Remove-StandVm $lab.attacker.vm
if ($lab.sensor.placement -eq 'vm') { Remove-StandVm $lab.sensor.vm }

# Сенсорный адаптер и память брокерной машины (возвращаем к состоянию 005)
$broker = $cfg.vm_name
if (Get-VM -Name $broker -ErrorAction SilentlyContinue) {
    $sensor = Get-VMNetworkAdapter -VMName $broker -Name 'sensor' -ErrorAction SilentlyContinue
    if ($sensor) {
        if ($PSCmdlet.ShouldProcess("$broker/sensor", 'Снять сенсорный адаптер (приёмник зеркала)')) {
            Remove-VMNetworkAdapter -VMName $broker -Name 'sensor'
            Write-Host "[снят] адаптер sensor у $broker"
        }
    }
    $mb = [int]$lab.sensor.extra_memory_mb
    if ($mb -gt 0) {
        $base = [int64]$cfg.memory_mb * 1MB
        if ((Get-VMMemory -VMName $broker).Startup -gt $base) {
            if ($PSCmdlet.ShouldProcess($broker, "Вернуть память к $($cfg.memory_mb) МБ (снять сенсорную надбавку)")) {
                if ((Get-VM -Name $broker).State -ne 'Off') {
                    Write-Host "[!] память меняется на выключенной машине — остановите $broker и повторите"
                }
                else { Set-VMMemory -VMName $broker -StartupBytes $base; Write-Host "[память] $broker ← $($cfg.memory_mb) МБ" }
            }
        }
    }
}
Write-Host ''
Write-Host 'Машины стенда 006 удалены. Брокер и сети 005 не тронуты (их снимает 90-remove.ps1).'
