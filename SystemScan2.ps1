# Сохраняем файл отчёта на рабочий стол
$Report = "$env:USERPROFILE\Desktop\SystemAudit.txt"

# Начинаем отчёт с параметрами системы
systeminfo         | Out-File $Report -Append
Get-NetIPConfiguration | Out-File $Report -Append
Get-NetRoute           | Out-File $Report -Append
Get-DnsClientServerAddress | Out-File $Report -Append
netstat -ano           | Out-File $Report -Append
Get-ScheduledTask      | Out-File $Report -Append
Get-Service            | Out-File $Report -Append
Get-PSDrive -PSProvider 'FileSystem' | Out-File $Report -Append
