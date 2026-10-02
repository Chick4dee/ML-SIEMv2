<#
.SYNOPSIS
    Канал управления сценариями на атакующей машине (фича 006, research R6, FR-010/FR-015).

.DESCRIPTION
    Передаёт раннеру на атакующей машине один JSON-запрос по каналу COM-порта (сети к хосту
    нет — изоляция FR-005) и печатает JSON-ответ последней строкой. Вызывается самим mlsiem
    (`mlsiem.lab.channel.ScriptChannel`), поэтому запрос приходит base64 в -RequestB64, а не
    как готовый JSON: так в нём могут быть любые символы без возни с экранированием в
    PowerShell. Параметр -Channel выбирает транспорт: com (по умолчанию) или direct (запасной,
    только для Windows-гостя, research R6).

    Только запускает сценарий/команду на машине — на хосте ничего не меняет.

.PARAMETER Vm
    Имя машины (обычно lab.attacker.vm).

.PARAMETER RequestB64
    JSON-запрос раннеру в base64 (см. протокол в src/mlsiem/lab/runner.py).

.PARAMETER Channel
    com | direct — транспорт канала управления.

.PARAMETER TimeoutS
    Сколько ждать ответ (для сценария — с запасом сверх его duration_limit_s).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Vm,
    [Parameter(Mandatory)][string]$RequestB64,
    [ValidateSet('com', 'direct')][string]$Channel = 'com',
    [int]$TimeoutS = 20
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib-com.ps1"

$line = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($RequestB64))
if ($Channel -eq 'direct') {
    $reply = Invoke-ComDirectRequest -Vm $Vm -Line $line -TimeoutS $TimeoutS
}
else {
    $reply = Invoke-ComRequest -Vm $Vm -Line $line -TimeoutS $TimeoutS
}
# Последней строкой — ответ раннера: его читает ScriptChannel
Write-Output $reply
