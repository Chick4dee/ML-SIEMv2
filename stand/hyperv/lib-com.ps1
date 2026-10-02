<#
.SYNOPSIS
    Общий код канала управления машинами стенда по COM-порту (фича 006, research R6).

.DESCRIPTION
    Точка «строка-запрос → строка-ответ» для раннера на машине стенда без сети к хосту.
    Хост пишет JSON-строку в именованный канал COM-порта ВМ (\\.\pipe\<машина>-com1) и читает
    строку-ответ. Этот путь работает с Linux-гостем (в отличие от PowerShell Direct, который
    только для Windows-гостей). Дот-сорсится другими скриптами стенда (70-, 80-).

    Ничего не меняет на машине напрямую: команды исполняет раннер в госте.
#>

function Invoke-ComRequest {
    <#
    .SYNOPSIS
        Отправить одну строку-запрос в канал COM-порта машины и вернуть строку-ответ.
    #>
    param(
        [Parameter(Mandatory)][string]$Vm,
        [Parameter(Mandatory)][string]$Line,
        [int]$TimeoutS = 20
    )
    $pipeName = "$Vm-com1"
    $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect([Math]::Min($TimeoutS, 10) * 1000)
    }
    catch {
        throw "канал $pipeName не открылся за время ожидания — машина $Vm выключена или COM-порт не настроен (50-vm-attacker.ps1)?"
    }
    try {
        $writer = New-Object System.IO.StreamWriter($client)
        $writer.AutoFlush = $true
        $reader = New-Object System.IO.StreamReader($client)
        $writer.WriteLine($Line)
        # Ждём ответ до TimeoutS: раннер отвечает одной строкой
        $deadline = (Get-Date).AddSeconds($TimeoutS)
        while ((Get-Date) -lt $deadline) {
            $reply = $reader.ReadLine()
            if ($reply) { return $reply }
            Start-Sleep -Milliseconds 100
        }
        throw "машина $Vm не ответила за $TimeoutS с — раннер не запущен? (на машине проверьте службу раннера: systemctl --type=service)"
    }
    finally {
        $client.Dispose()
    }
}

function Invoke-ComDirectRequest {
    <#
    .SYNOPSIS
        Запасной путь R6 для Windows-гостя: тот же протокол через PowerShell Direct.
        Для Linux-гостя не используется; оставлен по плану (research R6).
    #>
    param(
        [Parameter(Mandatory)][string]$Vm,
        [Parameter(Mandatory)][string]$Line,
        [int]$TimeoutS = 20
    )
    throw 'PowerShell Direct к этому гостю недоступен — используйте канал COM-порта (-Channel com)'
}
