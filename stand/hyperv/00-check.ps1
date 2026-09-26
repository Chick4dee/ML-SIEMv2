<#
.SYNOPSIS
    Шаг 0: проверки и план. НИЧЕГО НЕ МЕНЯЕТ (FR-002).

.DESCRIPTION
    Проверяет, можно ли поднимать брокерную машину: права администратора, включён ли Hyper-V,
    хватает ли свободной памяти и диска, что уже создано (коммутаторы, машина), есть ли образ
    Ubuntu. В конце печатает, что сделают следующие скрипты и сколько ресурсов займут.
    Код возврата: 0 — можно продолжать; 1 — есть препятствия (перечислены).

.PARAMETER Iso
    Путь к установочному образу Ubuntu Server 24.04 (live-server amd64), если он уже скачан.

.EXAMPLE
    .\stand\hyperv\00-check.ps1 -Iso D:\iso\ubuntu-24.04.3-live-server-amd64.iso
#>
param(
    [string]$Iso
)
$ErrorActionPreference = 'Stop'
$cfg = & "$PSScriptRoot\Read-StreamConfig.ps1"
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$problems = New-Object System.Collections.Generic.List[string]

Write-Host "== Проверка перед подъёмом брокерной машины $($cfg.vm_name) (ничего не меняется) =="

# Права администратора: Hyper-V и сетевые адаптеры меняются только от администратора
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) { Write-Host "[ok] PowerShell запущен от администратора" }
else { $problems.Add('PowerShell не от администратора — следующие скрипты запускайте «от имени администратора»') }

# Hyper-V: компонент Windows и модуль PowerShell
$hv = $null
if ($isAdmin) {
    $hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
}
if ($hv -and $hv.State -ne 'Enabled') {
    $problems.Add('Hyper-V не включён: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All (нужна перезагрузка)')
}
elseif (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    $problems.Add('нет модуля Hyper-V для PowerShell — включите компонент Hyper-V (вместе со средствами управления)')
}
else { Write-Host '[ok] Hyper-V включён' }

# Память: машине статически memory_mb, и хосту нужен запас 4 ГБ (SC-007)
$freeMb = [math]::Floor((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024)
$needMb = [int]$cfg.memory_mb + 4096
if ($freeMb -ge $needMb) { Write-Host "[ok] свободно памяти $freeMb МБ (нужно $($cfg.memory_mb) МБ машине + 4096 МБ запаса)" }
else { $problems.Add("свободно памяти $freeMb МБ, а нужно $needMb МБ ($($cfg.memory_mb) машине + 4096 запаса хосту)") }

# Диск: VHDX растёт до disk_gb в var\stand\ репозитория
$drive = (Get-Item $repo).PSDrive
$freeGb = [math]::Floor($drive.Free / 1GB)
if ($freeGb -ge [int]$cfg.disk_gb) { Write-Host "[ok] свободно на диске $($drive.Name): $freeGb ГБ (машине до $($cfg.disk_gb) ГБ)" }
else { $problems.Add("на диске $($drive.Name): свободно $freeGb ГБ, а диску машины нужно до $($cfg.disk_gb) ГБ") }

# Что уже создано (повторный запуск скриптов безопасен — они пропустят готовое)
foreach ($sw in @($cfg.mgmt_switch, $cfg.lab_switch)) {
    if (Get-Command Get-VMSwitch -ErrorAction SilentlyContinue) {
        if (Get-VMSwitch -Name $sw -ErrorAction SilentlyContinue) { Write-Host "[уже есть] коммутатор $sw" }
        else { Write-Host "[будет создан] коммутатор $sw" }
    }
}
if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
    if (Get-VM -Name $cfg.vm_name -ErrorAction SilentlyContinue) { Write-Host "[уже есть] машина $($cfg.vm_name)" }
    else { Write-Host "[будет создана] машина $($cfg.vm_name)" }
}
if ($Iso) {
    if (Test-Path $Iso) { Write-Host "[ok] образ Ubuntu: $Iso" }
    else { $problems.Add("нет файла образа $Iso — скачайте Ubuntu Server 24.04 live-server с releases.ubuntu.com или используйте 20-vm-broker.ps1 -Download") }
}
else {
    Write-Host '[нужен] образ Ubuntu Server 24.04 live-server amd64 (~3 ГБ): укажите -Iso или используйте 20-vm-broker.ps1 -Download'
}

Write-Host ''
Write-Host '== План (каждый шаг спросит подтверждение; -WhatIf — только показать) =='
Write-Host "1. 10-network.ps1: коммутатор $($cfg.mgmt_switch) (Internal, служебная сеть $($cfg.network)),"
Write-Host "   адрес хоста $($cfg.host_ip)/$($cfg.prefix) на vEthernet ($($cfg.mgmt_switch)),"
Write-Host "   коммутатор $($cfg.lab_switch) (Private, сеть стенда — пока пустая, для фичи 006)"
Write-Host "2. uv run mlsiem stand seed-iso: файл var\stand\seed.iso (~100 КБ) — ничего больше не меняет"
Write-Host "3. 20-vm-broker.ps1: машина $($cfg.vm_name) — Gen2, $($cfg.cpus) vCPU, $($cfg.memory_mb) МБ ОЗУ статически,"
Write-Host "   диск до $($cfg.disk_gb) ГБ (var\stand\$($cfg.vm_name).vhdx), адаптеры $($cfg.mgmt_switch) и Default Switch (на время установки)"
Write-Host "   [-Download: скачать образ Ubuntu ~3 ГБ с releases.ubuntu.com и сверить SHA-256]"
Write-Host "4. консоль машины: ответить yes на «Continue with autoinstall?», ждать ~10–20 минут"
Write-Host "5. 30-post-install.ps1: отключить Default Switch, извлечь образы, проверить брокер"

if ($problems.Count -gt 0) {
    Write-Host ''
    Write-Host '== Препятствия =='
    $problems | ForEach-Object { Write-Host " - $_" }
    exit 1
}
Write-Host ''
Write-Host 'Препятствий нет — можно запускать 10-network.ps1.'
exit 0
