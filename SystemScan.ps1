# === Проверка состояния Windows и сети ===
$Report = "$env:USERPROFILE\Desktop\SystemAudit_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').txt"

# Проверка версии системы
Add-Content $Report "=== Сведения о системе ==="
systeminfo | Out-String | Add-Content $Report

# Проверка активных маршрутов
Add-Content $Report "`n=== Активные маршруты ==="
Get-NetRoute -AddressFamily IPv4 | Out-String | Add-Content $Report

# Проверка DNS-серверов
Add-Content $Report "`n=== DNS-серверы ==="
Get-DnsClientServerAddress | Out-String | Add-Content $Report

# Проверка автозагрузки
Add-Content $Report "`n=== Автозагрузка ==="
wmic startup get caption,command | Out-String | Add-Content $Report

# Проверка служб, не относящихся к Microsoft и основным вендорам
Add-Content $Report "`n=== Нестандартные службы ==="
Get-WmiObject win32_service |
        Where-Object {
            $_.State -eq 'Running' -and
                    $_.StartMode -eq 'Auto' -and
                    ($_.PathName -notmatch 'Microsoft|Windows|ASUS|Gigabyte|Realtek|NVIDIA|Docker|Intel|AdGuard|UPSMON|Armoury')
        } |
        Select-Object Name, DisplayName, PathName, StartMode, State |
        Out-String | Add-Content $Report

# Проверка системных файлов
Add-Content $Report "`n=== Проверка целостности системных файлов (SFC /Scannow) ==="
sfc /scannow | Out-String | Add-Content $Report

# Проверка сетевых соединений
Add-Content $Report "`n=== Текущие сетевые соединения (netstat) ==="
netstat -ano | Out-String | Add-Content $Report

# Проверка центра безопасности
Add-Content $Report "`n=== Служба безопасности Windows ==="
Get-Service | Where-Object { $_.DisplayName -like "*Defender*" -or $_.DisplayName -like "*Security*" } | Out-String | Add-Content $Report

# Финал
Add-Content $Report "`n=== Проверка завершена успешно ==="
Write-Host "Отчёт сохранён: $Report"
