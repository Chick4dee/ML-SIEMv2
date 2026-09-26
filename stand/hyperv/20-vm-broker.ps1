<#
.SYNOPSIS
    Шаг 2: брокерная машина Hyper-V с автоустановкой Ubuntu Server 24.04.

.DESCRIPTION
    Создаёт машину stand.vm_name (research R1, R3):
    - поколение 2, stand.cpus vCPU, stand.memory_mb МБ ОЗУ СТАТИЧЕСКИ (динамическая память
      мешает JVM брокера и делает расход памяти хоста непредсказуемым, SC-007);
    - диск до stand.disk_gb ГБ, динамический, в var\stand\ репозитория;
    - Secure Boot с шаблоном MicrosoftUEFICertificateAuthority — с ним грузится Ubuntu;
    - адаптер «mgmt» в служебной сети и адаптер «install» в Default Switch (интернет на время
      установки) с постоянными MAC из конфига — по ним автоустановка их различает;
    - два DVD: установочный образ и seed-ISO автоустановки; загрузка с DVD.

    -Download: скачать образ Ubuntu 24.04 live-server с releases.ubuntu.com и сверить SHA-256
    по SHA256SUMS. Это ~3 ГБ — только после подтверждения.

    Идемпотентен: если машина уже есть, ничего не пересоздаёт. Каждое изменение спрашивает
    подтверждение (ConfirmImpact High); -WhatIf — только показать план.

.PARAMETER Iso
    Установочный образ Ubuntu Server 24.04 live-server amd64 (или куда его скачать с -Download).

.PARAMETER Seed
    Seed-ISO автоустановки (по умолчанию var\stand\seed.iso — `uv run mlsiem stand seed-iso`).

.EXAMPLE
    .\stand\hyperv\20-vm-broker.ps1 -Iso D:\iso\ubuntu-24.04.3-live-server-amd64.iso -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$Iso,
    [string]$Seed,
    [switch]$Download
)
$ErrorActionPreference = 'Stop'
$cfg = & "$PSScriptRoot\Read-StreamConfig.ps1"
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$standDir = Join-Path $repo 'var\stand'
if (-not $Seed) { $Seed = Join-Path $standDir 'seed.iso' }
# Hyper-V подключает образы только по полному пути: «var\stand\x.iso» превращаем в полный
$Iso = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Iso)
$Seed = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Seed)
$vhd = Join-Path $standDir "$($cfg.vm_name).vhdx"
$releases = 'https://releases.ubuntu.com/24.04'

function ConvertTo-HyperVMac([string]$mac) { ($mac -replace '[^0-9A-Fa-f]', '').ToUpper() }

# ------------------------------------------------ образ Ubuntu
if (-not (Test-Path $Iso)) {
    if (-not $Download) {
        throw "нет образа $Iso — скачайте Ubuntu Server 24.04 live-server amd64 с $releases или повторите с -Download"
    }
    # Список сумм маленький — он и говорит, как сейчас называется актуальный образ 24.04.x
    # Файл сумм сервер отдаёт без типа содержимого — Invoke-WebRequest в PowerShell 5.1 вернул
    # бы байты; WebClient читает его строкой. В списке несколько выпусков 24.04.x (по
    # возрастанию) — берём последний, самый свежий
    $sums = (New-Object Net.WebClient).DownloadString("$releases/SHA256SUMS")
    $line = ($sums -split "`n") | Where-Object { $_ -match 'live-server-amd64\.iso' } | Select-Object -Last 1
    if (-not $line) { throw "в $releases/SHA256SUMS нет образа live-server-amd64" }
    $expected, $name = ($line.Trim() -split '\s+\*?', 2)
    if ($PSCmdlet.ShouldProcess("$releases/$name", "Скачать образ Ubuntu (~3 ГБ) в $Iso")) {
        New-Item -ItemType Directory -Force (Split-Path $Iso) | Out-Null
        $ProgressPreference = 'SilentlyContinue'  # иначе прогресс-бар замедляет закачку в разы
        Invoke-WebRequest -UseBasicParsing "$releases/$name" -OutFile $Iso
        $actual = (Get-FileHash -Algorithm SHA256 $Iso).Hash.ToLower()
        if ($actual -ne $expected.ToLower()) {
            Remove-Item $Iso
            throw "SHA-256 образа не совпала с $releases/SHA256SUMS — файл удалён, повторите закачку"
        }
        Write-Host "[скачан] $Iso, SHA-256 сверена"
    }
}
if (-not (Test-Path $Seed)) {
    throw "нет seed-ISO $Seed — соберите его: uv run mlsiem stand seed-iso"
}

# ------------------------------------------------ машина
if (Get-VM -Name $cfg.vm_name -ErrorAction SilentlyContinue) {
    Write-Host "[уже есть] машина $($cfg.vm_name) — не пересоздаю (удалить: 90-remove.ps1)"
    return
}
if (-not (Get-VMSwitch -Name $cfg.mgmt_switch -ErrorAction SilentlyContinue)) {
    throw "нет коммутатора $($cfg.mgmt_switch) — сначала 10-network.ps1"
}

$what = "Gen2, $($cfg.cpus) vCPU, $($cfg.memory_mb) МБ ОЗУ статически, диск до $($cfg.disk_gb) ГБ ($vhd)"
if ($PSCmdlet.ShouldProcess($cfg.vm_name, "Создать машину Hyper-V: $what")) {
    New-Item -ItemType Directory -Force $standDir | Out-Null
    New-VM -Name $cfg.vm_name -Generation 2 -MemoryStartupBytes ([int64]$cfg.memory_mb * 1MB) `
        -NewVHDPath $vhd -NewVHDSizeBytes ([int64]$cfg.disk_gb * 1GB) -SwitchName $cfg.mgmt_switch | Out-Null
    Set-VMMemory -VMName $cfg.vm_name -DynamicMemoryEnabled $false
    Set-VMProcessor -VMName $cfg.vm_name -Count ([int]$cfg.cpus)
    Set-VM -Name $cfg.vm_name -AutomaticCheckpointsEnabled $false
    Set-VMFirmware -VMName $cfg.vm_name -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
    Write-Host "[создана] машина $($cfg.vm_name)"
}
if ($PSCmdlet.ShouldProcess($cfg.vm_name, "Адаптеры: mgmt ($($cfg.mgmt_switch), MAC $($cfg.mgmt_mac)) и install (Default Switch, MAC $($cfg.install_mac))")) {
    $first = Get-VMNetworkAdapter -VMName $cfg.vm_name | Select-Object -First 1
    Rename-VMNetworkAdapter -VMNetworkAdapter $first -NewName 'mgmt'
    Set-VMNetworkAdapter -VMName $cfg.vm_name -Name 'mgmt' -StaticMacAddress (ConvertTo-HyperVMac $cfg.mgmt_mac)
    Add-VMNetworkAdapter -VMName $cfg.vm_name -Name 'install' -SwitchName 'Default Switch' `
        -StaticMacAddress (ConvertTo-HyperVMac $cfg.install_mac)
}
if ($PSCmdlet.ShouldProcess($cfg.vm_name, "Подключить DVD: $Iso и $Seed, загрузка с DVD")) {
    Add-VMDvdDrive -VMName $cfg.vm_name -Path $Iso
    Add-VMDvdDrive -VMName $cfg.vm_name -Path $Seed
    $dvd = Get-VMDvdDrive -VMName $cfg.vm_name | Where-Object { $_.Path -eq $Iso } | Select-Object -First 1
    Set-VMFirmware -VMName $cfg.vm_name -FirstBootDevice $dvd
}
if ($PSCmdlet.ShouldProcess($cfg.vm_name, 'Запустить машину (начнётся установка Ubuntu)')) {
    Start-VM -Name $cfg.vm_name
    Write-Host ''
    Write-Host "Машина запущена. Откройте её консоль (vmconnect localhost $($cfg.vm_name)) и ответьте"
    Write-Host 'yes на вопрос «Continue with autoinstall?». Установка и Kafka — 10–20 минут; машина'
    Write-Host 'перезагрузится сама. Затем: .\stand\hyperv\30-post-install.ps1'
}
