# filename: SystemAudit.ps1
Set-StrictMode -Version Latest

$timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$desktop   = [Environment]::GetFolderPath('Desktop')
$Report    = Join-Path -Path $desktop -ChildPath "SystemAudit_$timestamp.txt"
Set-Content -Path $Report -Value "" -Encoding UTF8

function Append-Report {
    param([Parameter(Mandatory=$true)][string]$Text)
    Add-Content -Path $Report -Value $Text -Encoding UTF8
}

function Append-CommandOutput {
    param([Parameter(Mandatory=$true)][ScriptBlock]$Command, [int]$Width = 500)
    try {
        $result = & $Command | Out-String -Width $Width
        Append-Report ($result.TrimEnd())
    } catch {
        Append-Report ("ERROR: {0}" -f $_.Exception.Message)
    }
}

# Внешние консольные утилиты часто печатают в OEM CP (866/1251). Конвертируем к UTF-8.
function Invoke-ExternalUtf8 {
    param([Parameter(Mandatory=$true)][string]$CommandLine, [int]$Width = 500)
    # Сохраняем текущую кодовую страницу (строка вида "Active code page: 866")
    $oldCp = chcp
    try {
        # Переключаем на UTF-8
        $output = cmd /c "chcp 65001 > nul & $CommandLine"
        # Собираем в строку и возвращаем
        return ($output | Out-String -Width $Width).TrimEnd()
    } catch {
        return ("ERROR: {0}" -f $_.Exception.Message)
    } finally {
        # Возврат прежней CP
        $match = ($oldCp | Select-String -Pattern '\d+')
        if ($match) {
            $cp = $match.Matches[0].Value
            cmd /c "chcp $cp > nul" | Out-Null
        }
    }
}

Write-Host "Step 1: System Information..."
Append-Report "=== System Information ==="
Append-CommandOutput { systeminfo }

Write-Host "Step 2: Network Configuration..."
Append-Report "`n=== Network Configuration ==="
Append-CommandOutput { Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DnsServer }

Write-Host "Step 3: Active Routes..."
Append-Report "`n=== Active Routes (IPv4) ==="
Append-CommandOutput { Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -eq "0.0.0.0/0" | Select-Object IfIndex, DestinationPrefix, NextHop }

Write-Host "Step 4: DNS Servers..."
Append-Report "`n=== DNS Servers ==="
Append-CommandOutput { Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses }

Write-Host "Step 5: Active Network Connections..."
Append-Report "`n=== Active Network Connections (ESTABLISHED) ==="
$netstatOut = Invoke-ExternalUtf8 "netstat -ano | findstr ESTABLISHED"
Append-Report $netstatOut

Write-Host "Step 6: Startup Programs..."
Append-Report "`n=== Startup Programs (Autostart) ==="
function Get-StartupItems {
    $items = @()

    foreach ($root in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')) {
        if (Test-Path $root) {
            $props = Get-ItemProperty -Path $root
            foreach ($name in $props.PSObject.Properties.Name) {
                if ($name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                $items += [pscustomobject]@{
                    Source   = $root
                    Caption  = $name
                    Command  = $props.$name
                }
            }
        }
    }

    $startupPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($p in $startupPaths) {
        if (Test-Path $p) {
            Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | ForEach-Object {
                $items += [pscustomobject]@{
                    Source   = $p
                    Caption  = $_.Name
                    Command  = $_.FullName
                }
            }
        }
    }

    try {
        $logonTasks = Get-ScheduledTask | Where-Object { $_.Triggers | Where-Object { $_.TriggerType -eq 'Logon' } }
        foreach ($t in $logonTasks) {
            $actions = $t.Actions | ForEach-Object {
                if ($_.PSObject.Properties.Match('Execute').Count -gt 0) { $_.Execute } else { $_.Command }
            }
            $items += [pscustomobject]@{
                Source   = "ScheduledTask"
                Caption  = $t.TaskName
                Command  = ($actions -join '; ')
            }
        }
    } catch {}

    $items | Sort-Object Caption
}
Append-CommandOutput { Get-StartupItems | Format-Table Source, Caption, Command -AutoSize }

Write-Host "Step 7: Non-standard Running Services..."
Append-Report "`n=== Non-standard Running Services (Auto-start) ==="
Append-CommandOutput {
    $exclude = 'Microsoft|Windows|ASUS|Gigabyte|Realtek|Intel|AdGuard|UPSMON|NVIDIA|Armoury|Docker|Steam|SecurityHealth'
    Get-CimInstance -ClassName Win32_Service |
            Where-Object {
                $_.State -eq 'Running' -and
                        $_.StartMode -eq 'Auto' -and
                        ($_.PathName -notmatch $exclude)
            } |
            Select-Object Name, DisplayName, PathName |
            Sort-Object DisplayName
}

Write-Host "Step 8: System File Integrity (SFC)... (may take a while)"
Append-Report "`n=== Integrity Check of System Files (SFC) ==="
# Важно: запускать PowerShell с правами администратора
$sfcOut = Invoke-ExternalUtf8 "sfc /scannow"
Append-Report $sfcOut

Write-Host "Step 9: Windows Defender Status..."
Append-Report "`n=== Windows Defender Status ==="
Append-CommandOutput {
    Get-Service |
            Where-Object { $_.DisplayName -like "*Defender*" -or $_.DisplayName -like "*Security*" } |
            Select-Object Name, Status, StartType
}

Write-Host "Step 10: Scheduled Tasks..."
Append-Report "`n=== Running Scheduled Tasks (Summary) ==="
Append-CommandOutput {
    Get-ScheduledTask |
            Where-Object State -eq 'Ready' |
            Select-Object TaskName, State, LastRunTime |
            Sort-Object LastRunTime
}

Write-Host "Step 11: Disk Space Overview..."
Append-Report "`n=== Disk Space Overview ==="
Append-CommandOutput {
    Get-PSDrive -PSProvider 'FileSystem' |
            Select-Object Name,
            @{n='Used(GB)';e={[math]::Round(($_.Used/1GB),2)}},
            @{n='Free(GB)';e={[math]::Round(($_.Free/1GB),2)}},
            @{n='Total(GB)';e={[math]::Round((($_.Used + $_.Free)/1GB),2)}}
}

Write-Host ""
Write-Host "Script completed! Report saved: $Report"
Append-Report "`nScript completed at $(Get-Date). Report saved: $Report"
