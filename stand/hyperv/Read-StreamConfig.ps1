<#
.SYNOPSIS
    Читает разделы stand и lab из configs/stream.yaml и отдаёт его объектом PowerShell.

.DESCRIPTION
    Все скрипты стенда берут имена машин, коммутаторов, адреса и ресурсы только отсюда —
    в самих скриптах чисел и имён нет (FR-023). YAML читает тот же код, что и `mlsiem`
    (`mlsiem.stream.config.load_stream_config`), через `uv run python`: так конфиг
    проверяется одинаково, и в PowerShell не нужен отдельный модуль YAML.
    Ничего в системе не меняет.

.EXAMPLE
    $cfg = & "$PSScriptRoot\Read-StreamConfig.ps1"
    $cfg.vm_name
#>
param(
    [string]$Config = (Join-Path $PSScriptRoot '..\..\configs\stream.yaml')
)
$ErrorActionPreference = 'Stop'

$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$configPath = Resolve-Path $Config
# Только одинарные кавычки внутри: PowerShell 5.1 срезает двойные в аргументах внешних программ
$code = @'
import json, sys
from mlsiem.stream.config import load_stream_config
cfg = load_stream_config(sys.argv[1])
out = dict(vars(cfg.stand))
out['network'] = str(cfg.stand.network)
out['bootstrap'] = cfg.broker.bootstrap
out['connect_timeout_s'] = cfg.broker.connect_timeout_s
# Фича 006: машины стенда и сенсор (раздел lab) — тем же объектом, как $cfg.lab.victim.vm
if cfg.lab is not None:
    out['lab'] = cfg.raw['lab']
print(json.dumps(out))
'@

Push-Location $repo
try {
    $json = & uv run --quiet python -c $code $configPath
    if ($LASTEXITCODE -ne 0) {
        throw "не удалось прочитать $configPath (код $LASTEXITCODE) — проверьте конфиг: uv run mlsiem stand check"
    }
    $json | ConvertFrom-Json
}
finally {
    Pop-Location
}
