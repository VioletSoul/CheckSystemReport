# === Автоматическая диагностика системы ===
$Report = "$env:USERPROFILE\Desktop\CheckSystemReport_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').txt"
Start-Transcript -Path $Report

Write-Host "`n==== Проверка сети ===="
Get-NetIPConfiguration | Format-Table InterfaceAlias, IPv4Address, IPv4DefaultGateway, DnsServer

Write-Host "`n==== Проверка маршрутов ===="
Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -eq "0.0.0.0/0" | Format-Table ifIndex, DestinationPrefix, NextHop

Write-Host "`n==== Проверка DNS ===="
Get-DnsClientServerAddress | Format-Table InterfaceAlias, ServerAddresses -AutoSize

Write-Host "`n==== Проверка активных соединений ===="
netstat -ano | findstr "ESTABLISHED"

Write-Host "`n==== Проверка автозагрузки ===="
wmic startup get caption,command | sort

Write-Host "`n==== Проверка нестандартных служб ===="
Get-WmiObject win32_service |
        Where-Object {
            $_.State -eq 'Running' -and
                    $_.StartMode -eq 'Auto' -and
                    ($_.PathName -notmatch 'Microsoft|Windows|ASUS|Gigabyte|Realtek|Intel|AdGuard|UPSMON|NVIDIA|Armoury|Docker|Steam')
        } | Select-Object Name, DisplayName, PathName | Format-Table -AutoSize

Write-Host "`n==== Проверка системных файлов и целостности ===="
sfc /scannow

Write-Host "`n==== Проверка центра безопасности ===="
Get-Service | Where-Object { $_.DisplayName -like "*Defender*" -or $_.DisplayName -like "*Security*" } | Format-Table Name, Status, StartType

Stop-Transcript
Write-Host "`nОтчёт сохранён на рабочий стол: $Report"
