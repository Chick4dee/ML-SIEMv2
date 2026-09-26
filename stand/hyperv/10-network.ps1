<#
.SYNOPSIS
    Шаг 1: сети стенда — служебная (Internal) с адресом хоста и сеть стенда (Private).

.DESCRIPTION
    Создаёт (research R2, FR-003a):
    - коммутатор stand.mgmt_switch типа Internal — служебная сеть: хост, брокер, позже сенсор.
      Internal значит «виртуальные машины + сам хост», без выхода во внешнюю сеть;
    - адрес хоста stand.host_ip/prefix на его адаптере vEthernet (<mgmt_switch>);
    - коммутатор stand.lab_switch типа Private — сеть стенда для фичи 006 (атакующий, жертвы,
      интерфейс сенсора на прослушивание). Private — потому что туда НЕ должен попадать даже
      хост: трафик атак не должен выходить за пределы стенда, а брокер из этой сети не виден.

    Идемпотентен: готовое пропускается с пометкой «уже есть». Каждое изменение спрашивает
    подтверждение (ConfirmImpact High); -WhatIf — только показать план.

.EXAMPLE
    .\stand\hyperv\10-network.ps1 -WhatIf
    .\stand\hyperv\10-network.ps1
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param()
$ErrorActionPreference = 'Stop'
$cfg = & "$PSScriptRoot\Read-StreamConfig.ps1"
$alias = "vEthernet ($($cfg.mgmt_switch))"

# Служебная сеть
if (Get-VMSwitch -Name $cfg.mgmt_switch -ErrorAction SilentlyContinue) {
    Write-Host "[уже есть] коммутатор $($cfg.mgmt_switch)"
}
elseif ($PSCmdlet.ShouldProcess($cfg.mgmt_switch, 'Создать коммутатор Hyper-V типа Internal (служебная сеть: хост + брокер)')) {
    New-VMSwitch -Name $cfg.mgmt_switch -SwitchType Internal | Out-Null
    Write-Host "[создан] коммутатор $($cfg.mgmt_switch)"
}

# Адрес хоста в служебной сети (статический: DHCP в ней нет)
$hasIp = Get-NetIPAddress -InterfaceAlias $alias -IPAddress $cfg.host_ip -ErrorAction SilentlyContinue
if ($hasIp) {
    Write-Host "[уже есть] адрес $($cfg.host_ip)/$($cfg.prefix) на $alias"
}
elseif ($PSCmdlet.ShouldProcess($alias, "Назначить хосту адрес $($cfg.host_ip)/$($cfg.prefix)")) {
    New-NetIPAddress -InterfaceAlias $alias -IPAddress $cfg.host_ip -PrefixLength ([int]$cfg.prefix) | Out-Null
    Write-Host "[создан] адрес $($cfg.host_ip)/$($cfg.prefix) на $alias"
}

# Сеть стенда — Private: ни хоста, ни брокера в ней нет
if (Get-VMSwitch -Name $cfg.lab_switch -ErrorAction SilentlyContinue) {
    Write-Host "[уже есть] коммутатор $($cfg.lab_switch)"
}
elseif ($PSCmdlet.ShouldProcess($cfg.lab_switch, 'Создать коммутатор Hyper-V типа Private (сеть стенда для фичи 006, хост в неё не входит)')) {
    New-VMSwitch -Name $cfg.lab_switch -SwitchType Private | Out-Null
    Write-Host "[создан] коммутатор $($cfg.lab_switch)"
}

Write-Host 'Готово. Дальше: uv run mlsiem stand seed-iso, затем 20-vm-broker.ps1.'
