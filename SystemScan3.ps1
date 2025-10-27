# filename: SystemAudit_min.ps1

# Путь к отчёту
$Report = Join-Path $env:USERPROFILE "Desktop\SystemAudit.txt"

# Начинаем файл с пустой строкой, задаём кодировку UTF-8
Set-Content -Path $Report -Value "" -Encoding UTF8

# Функция: безопасно дописать команду PowerShell в UTF-8
function Append-PowerShell {
    param([ScriptBlock]$Cmd)
    & $Cmd | Out-File -FilePath $Report -Append -Encoding UTF8
}

# Функция: дописать вывод консольной утилиты (cmd.exe) как UTF-8
function Append-External {
    param([string]$CommandLine)
    # Переключаем на UTF-8 внутри cmd и пишем вывод в файл в UTF-8
    cmd /c "chcp 65001 > nul & $CommandLine" | Out-File -FilePath $Report -Append -Encoding UTF8
}

# Сбор базовой информации
Append-PowerShell { systeminfo }
Append-PowerShell { Get-NetIPConfiguration }
Append-PowerShell { Get-NetRoute }
Append-PowerShell { Get-DnsClientServerAddress }
Append-External   "netstat -ano"
Append-PowerShell { Get-ScheduledTask }
Append-PowerShell { Get-Service }
Append-PowerShell { Get-PSDrive -PSProvider 'FileSystem' }

# SFC (админ-права рекомендуются)
Append-External   "sfc /scannow"
