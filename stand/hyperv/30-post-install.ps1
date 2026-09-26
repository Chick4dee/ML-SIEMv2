<#
.SYNOPSIS
    Шаг 3: после установки — отрезать машину от интернета, извлечь образы, проверить брокер.

.DESCRIPTION
    - отключает адаптер «install» (Default Switch): интернет был нужен только для пакетов и
      архива Kafka, дальше брокер живёт только в служебной сети (research R2);
    - извлекает оба DVD и ставит загрузку с диска;
    - ждёт, пока брокер ответит на порту 9092 (до 10 минут: первая загрузка ставит Kafka);
    - запускает `uv run mlsiem stand check`.

    Идемпотентен. Каждое изменение спрашивает подтверждение; -WhatIf — только план.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [int]$WaitMinutes = 10
)
$ErrorActionPreference = 'Stop'
$cfg = & "$PSScriptRoot\Read-StreamConfig.ps1"
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')

$vm = Get-VM -Name $cfg.vm_name -ErrorAction SilentlyContinue
if (-not $vm) { throw "нет машины $($cfg.vm_name) — сначала 20-vm-broker.ps1" }

# Ждём конца установки: Kafka отвечает на служебном адресе
Write-Host "Жду брокер $($cfg.broker_ip):9092 до $WaitMinutes мин…"
$deadline = (Get-Date).AddMinutes($WaitMinutes)
$up = $false
while ((Get-Date) -lt $deadline) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        $client.ConnectAsync($cfg.broker_ip, 9092).Wait(2000) | Out-Null
        if ($client.Connected) { $up = $true; break }
    } catch { } finally { $client.Dispose() }
    Start-Sleep -Seconds 10
}
if (-not $up) {
    Write-Host "Брокер не ответил за $WaitMinutes мин. Посмотрите консоль машины и журнал /var/log/mlsiem-install-kafka.log;"
    Write-Host 'установочный адаптер НЕ отключаю — он может ещё быть нужен установке.'
    exit 1
}

$install = Get-VMNetworkAdapter -VMName $cfg.vm_name -Name 'install' -ErrorAction SilentlyContinue
if ($install -and $install.SwitchName) {
    if ($PSCmdlet.ShouldProcess("$($cfg.vm_name)/install", 'Отключить адаптер Default Switch (машина больше не ходит в интернет)')) {
        Disconnect-VMNetworkAdapter -VMName $cfg.vm_name -Name 'install'
        Write-Host '[отключён] адаптер install'
    }
}
else { Write-Host '[уже] адаптер install отключён' }

$dvds = Get-VMDvdDrive -VMName $cfg.vm_name | Where-Object { $_.Path }
if ($dvds) {
    if ($PSCmdlet.ShouldProcess($cfg.vm_name, 'Извлечь DVD (образ Ubuntu и seed-ISO), загрузка с диска')) {
        $dvds | Set-VMDvdDrive -Path $null
        $disk = Get-VMHardDiskDrive -VMName $cfg.vm_name | Select-Object -First 1
        Set-VMFirmware -VMName $cfg.vm_name -FirstBootDevice $disk
        Write-Host '[извлечены] DVD'
    }
}
else { Write-Host '[уже] DVD извлечены' }

Push-Location $repo
try { & uv run mlsiem stand check; exit $LASTEXITCODE }
finally { Pop-Location }
