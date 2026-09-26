<#
.SYNOPSIS
    Удалить стенд: брокерную машину, её диск, адрес хоста и коммутаторы.

.DESCRIPTION
    Каждое удаление спрашивает подтверждение отдельно (ConfirmImpact High) — можно, например,
    удалить машину, но оставить сети. -WhatIf — только показать, что было бы удалено.
    Идемпотентен: отсутствующее пропускается. Сообщения в топиках пропадут вместе с машиной.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param()
$ErrorActionPreference = 'Stop'
$cfg = & "$PSScriptRoot\Read-StreamConfig.ps1"
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$vhd = Join-Path $repo "var\stand\$($cfg.vm_name).vhdx"
$alias = "vEthernet ($($cfg.mgmt_switch))"

$vm = Get-VM -Name $cfg.vm_name -ErrorAction SilentlyContinue
if ($vm) {
    if ($PSCmdlet.ShouldProcess($cfg.vm_name, 'Остановить и удалить машину (данные брокера пропадут)')) {
        if ($vm.State -ne 'Off') { Stop-VM -Name $cfg.vm_name -TurnOff -Force }
        Remove-VM -Name $cfg.vm_name -Force
        Write-Host "[удалена] машина $($cfg.vm_name)"
    }
}
else { Write-Host "[нет] машины $($cfg.vm_name)" }

if (Test-Path $vhd) {
    if ($PSCmdlet.ShouldProcess($vhd, 'Удалить диск машины')) {
        Remove-Item $vhd -Force
        Write-Host "[удалён] $vhd"
    }
}

$ip = Get-NetIPAddress -InterfaceAlias $alias -IPAddress $cfg.host_ip -ErrorAction SilentlyContinue
if ($ip) {
    if ($PSCmdlet.ShouldProcess($alias, "Снять адрес хоста $($cfg.host_ip)")) {
        Remove-NetIPAddress -InterfaceAlias $alias -IPAddress $cfg.host_ip -Confirm:$false
    }
}

foreach ($sw in @($cfg.lab_switch, $cfg.mgmt_switch)) {
    if (Get-VMSwitch -Name $sw -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess($sw, 'Удалить коммутатор Hyper-V')) {
            Remove-VMSwitch -Name $sw -Force
            Write-Host "[удалён] коммутатор $sw"
        }
    }
    else { Write-Host "[нет] коммутатора $sw" }
}
