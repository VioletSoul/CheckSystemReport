$Report = "$env:USERPROFILE\Desktop\SystemAudit_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"

Write-Host "Step 1: System Information..."
"=== System Information ===" | Add-Content $Report
systeminfo | Out-String | Add-Content $Report

Write-Host "Step 2: Network Configuration..."
"`n=== Network Configuration ===" | Add-Content $Report
Get-NetIPConfiguration | Format-Table InterfaceAlias, IPv4Address, IPv4DefaultGateway, DnsServer | Out-String | Add-Content $Report

Write-Host "Step 3: Active Routes..."
"`n=== Active Routes (IPv4) ===" | Add-Content $Report
Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -eq "0.0.0.0/0" | Format-Table ifIndex, DestinationPrefix, NextHop | Out-String | Add-Content $Report

Write-Host "Step 4: DNS Servers..."
"`n=== DNS Servers ===" | Add-Content $Report
Get-DnsClientServerAddress | Format-Table InterfaceAlias, ServerAddresses -AutoSize | Out-String | Add-Content $Report

Write-Host "Step 5: Active Network Connections..."
"`n=== Active Network Connections ===" | Add-Content $Report
netstat -ano | findstr "ESTABLISHED" | Out-String | Add-Content $Report

Write-Host "Step 6: Startup Programs..."
"`n=== Startup Programs (Autostart) ===" | Add-Content $Report
wmic startup get caption,command | sort | Out-String | Add-Content $Report

Write-Host "Step 7: Non-standard Running Services..."
"`n=== Non-standard Running Services (Auto-start) ===" | Add-Content $Report
Get-WmiObject win32_service |
        Where-Object {
            $_.State -eq 'Running' -and
                    $_.StartMode -eq 'Auto' -and
                    ($_.PathName -notmatch 'Microsoft|Windows|ASUS|Gigabyte|Realtek|Intel|AdGuard|UPSMON|NVIDIA|Armoury|Docker|Steam|SecurityHealth')
        } | Select-Object Name, DisplayName, PathName | Format-Table -AutoSize | Out-String | Add-Content $Report

Write-Host "Step 8: System File Integrity (SFC)... (may take a while)"
"`n=== Integrity Check of System Files (SFC) ===" | Add-Content $Report
sfc /scannow | Out-String | Add-Content $Report

Write-Host "Step 9: Windows Defender Status..."
"`n=== Windows Defender Status ===" | Add-Content $Report
Get-Service | Where-Object { $_.DisplayName -like "*Defender*" -or $_.DisplayName -like "*Security*" } | Format-Table Name, Status, StartType | Out-String | Add-Content $Report

Write-Host "Step 10: Scheduled Tasks..."
"`n=== Running Scheduled Tasks (Summary) ===" | Add-Content $Report
Get-ScheduledTask | Where-Object State -eq 'Ready' | Select-Object TaskName, State, LastRunTime | Sort-Object LastRunTime | Out-String | Add-Content $Report

Write-Host "Step 11: Disk Space Overview..."
"`n=== Disk Space Overview ===" | Add-Content $Report
Get-PSDrive -PSProvider 'FileSystem' | Select-Object Name, Used, Free | Out-String | Add-Content $Report

Write-Host ""
Write-Host "Script completed! Report saved: $Report"
