# filename: SystemAudit_English_Win11_Progress.ps1
# Purpose: English-only UTF-8 system audit for Windows 11 with robust error handling and console progress.

Set-StrictMode -Version Latest

# Report file (UTF-8)
$timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$desktop   = [Environment]::GetFolderPath('Desktop')
$Report    = Join-Path $desktop "SystemAudit_$timestamp.txt"
Set-Content -Path $Report -Value "" -Encoding UTF8

# ==== Progress helpers ====
function Write-StepStart {
    param([string]$Title)
    $ts = (Get-Date).ToString('u')
    Write-Host ("[{0}] >> {1} ..." -f $ts, $Title)
    Add-Content -Path $Report -Value ("`n=== {0} ===" -f $Title) -Encoding UTF8
}
function Write-StepDone {
    param([string]$Title)
    $ts = (Get-Date).ToString('u')
    Write-Host ("[{0}] << {1} done" -f $ts, $Title)
}

# ==== Report helpers ====
function Append-Text {
    param([Parameter(Mandatory=$true)][string]$Text)
    Add-Content -Path $Report -Value $Text -Encoding UTF8
}
function Append-PS {
    param([Parameter(Mandatory=$true)][ScriptBlock]$Cmd, [int]$Width = 600)
    try {
        $out = & $Cmd | Out-String -Width $Width
        if ($out) { Append-Text ($out.TrimEnd()) } else { Append-Text "No data." }
    } catch {
        Append-Text ("ERROR: {0}" -f $_.Exception.Message)
    }
}
function Append-EXT {
    param([Parameter(Mandatory=$true)][string]$CommandLine, [int]$Width = 600)
    try {
        # Run external command under cmd in UTF-8 to avoid Cyrillic/OEM mess
        $output = cmd /c "chcp 65001 > nul & $CommandLine"
        $outStr = ($output | Out-String -Width $Width).TrimEnd()
        if ($outStr) { Append-Text $outStr } else { Append-Text "No data." }
    } catch {
        Append-Text ("ERROR: {0}" -f $_.Exception.Message)
    }
}

# ==== 0) Elevation info ====
Write-StepStart "Execution Context"
Append-PS {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    [pscustomobject]@{ IsElevated = $isAdmin }
}
Write-StepDone "Execution Context"

# ==== 1) System information ====
Write-StepStart "System Information"
Append-PS {
    Get-CimInstance Win32_OperatingSystem | Select-Object `
        Caption, Version, BuildNumber, OSArchitecture,
    @{n='InstallDate';e={([Management.ManagementDateTimeConverter]::ToDateTime($_.InstallDate)).ToString('u')}},
    @{n='LastBootUpTime';e={([Management.ManagementDateTimeConverter]::ToDateTime($_.LastBootUpTime)).ToString('u')}},
    @{n='UptimeDays';e={[math]::Round((New-TimeSpan -Start ([Management.ManagementDateTimeConverter]::ToDateTime($_.LastBootUpTime)) -End (Get-Date)).TotalDays,2)}}
}
Append-PS { Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, Username, Domain, TotalPhysicalMemory }
Append-PS { Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed }
Append-PS { Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer, Capacity, Speed, PartNumber }
Append-PS { Get-CimInstance Win32_BIOS | Select-Object Manufacturer, Name, Version, SMBIOSBIOSVersion, ReleaseDate }
Append-PS { Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace }
Write-StepDone "System Information"

# ==== 2) Drivers, processes, services ====
Write-StepStart "Drivers"
Append-PS { Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, DriverProviderName, DriverDate | Sort-Object DeviceName }
Write-StepDone "Drivers"

Write-StepStart "Top Processes"
Append-PS { Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 Name, Id, CPU, WS, PM, StartTime }
Append-PS { Get-Process | Sort-Object WS -Descending  | Select-Object -First 25 Name, Id, CPU, WS, PM, StartTime }
Write-StepDone "Top Processes"

Write-StepStart "Running Services"
Append-PS { Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, DisplayName, Status, StartType | Sort-Object DisplayName }
Write-StepDone "Running Services"

# ==== 3) Networking ====
Write-StepStart "Network Configuration"
Append-PS { Get-NetIPConfiguration | Select-Object InterfaceAlias, InterfaceDescription, IPv4Address, IPv6Address, IPv4DefaultGateway, DnsServer }
Append-PS { Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -eq '0.0.0.0/0' | Select-Object ifIndex, DestinationPrefix, NextHop, RouteMetric }
Append-EXT "arp -a"
Write-StepDone "Network Configuration"

Write-StepStart "Firewall Rules"
Append-PS {
    try {
        Get-NetFirewallRule -Enabled True -Direction Inbound | Select-Object DisplayName, Action, Enabled, Direction, Profile | Sort-Object DisplayName
    } catch {
        "ERROR: Get-NetFirewallRule failed: $($_.Exception.Message)"
    }
}
Write-StepDone "Firewall Rules"

Write-StepStart "TCP Ports and Connections"
Append-EXT "netstat -ano | findstr LISTENING"
Append-EXT "netstat -ano | findstr ESTABLISHED"
Write-StepDone "TCP Ports and Connections"

# ==== 4) Defender / Security ====
Write-StepStart "Microsoft Defender"
Append-PS {
    Get-Service | Where-Object { $_.Name -like 'WinDefend' -or $_.DisplayName -like '*Defender*' -or $_.DisplayName -like '*Security*' } | Select-Object Name, DisplayName, Status, StartType
}
Append-PS {
    try {
        Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, AntivirusSignatureLastUpdated, AntivirusSignatureVersion, IsTamperProtected, RealTimeProtectionEnabled, DefenderSignaturesOutOfDate
    } catch {
        "ERROR: Get-MpComputerStatus unavailable: $($_.Exception.Message)"
    }
}
Append-PS {
    try {
        Get-MpThreatDetection | Select-Object ThreatName, InitialDetectionTime, LastThreatStatusChangeTime, Severity, Resources | Sort-Object LastThreatStatusChangeTime
    } catch {
        "ERROR: Get-MpThreatDetection unavailable: $($_.Exception.Message)"
    }
}
Write-StepDone "Microsoft Defender"

# ==== 5) Autostart ====
Write-StepStart "Autostart Inventory"
Append-PS {
    $items = @()
    foreach ($root in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')) {
        if (Test-Path $root) {
            $props = Get-ItemProperty -Path $root
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                $items += [pscustomobject]@{ Source=$root; Name=$p.Name; Command=$p.Value }
            }
        }
    }
    if ($items.Count -gt 0) { $items | Sort-Object Name } else { "No autostart entries in Run keys." }
}
Append-PS {
    $paths = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
    $files = Get-ChildItem -Path $paths -File -ErrorAction SilentlyContinue | Select-Object Directory, Name, FullName
    if ($files) { $files } else { "No items in Startup folders." }
}
Append-PS {
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.Triggers | Where-Object { $_.TriggerType -eq 'Logon' } }
        if ($tasks) {
            foreach ($t in $tasks) {
                $actions = @()
                foreach ($a in $t.Actions) {
                    $exec = $null
                    if ($a.PSObject.Properties.Match('Execute').Count -gt 0) { $exec = $a.Execute }
                    elseif ($a.PSObject.Properties.Match('Command').Count -gt 0) { $exec = $a.Command }
                    else { $exec = $a.ToString() }
                    $args = $null
                    if ($a.PSObject.Properties.Match('Arguments').Count -gt 0) { $args = $a.Arguments }
                    $actions += ($exec + ($(if ($args) { " $args" } else { "" })))
                }
                [pscustomobject]@{ TaskName=$t.TaskName; TaskPath=$t.TaskPath; Actions=($actions -join ' ; ') }
            }
        } else {
            "No Logon-triggered scheduled tasks."
        }
    } catch {
        "ERROR: Scheduled tasks enumeration failed: $($_.Exception.Message)"
    }
}
Append-PS {
    $exclude = 'Microsoft|Windows'
    $svc = Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and ($_.PathName -notmatch $exclude) } | Select-Object Name, DisplayName, State, StartMode, PathName | Sort-Object DisplayName
    if ($svc) { $svc } else { "No non-Microsoft auto-start services found." }
}
Write-StepDone "Autostart Inventory"

# ==== 6) Scheduled tasks summary ====
Write-StepStart "Scheduled Tasks Summary"
Append-PS {
    try {
        $data = Get-ScheduledTask | Where-Object { $_.State -in @('Ready','Running') } | Select-Object TaskName, State, LastRunTime | Sort-Object LastRunTime
        if ($data) { $data } else { "No tasks in Ready/Running state." }
    } catch {
        "ERROR: Scheduled tasks summary failed: $($_.Exception.Message)"
    }
}
Write-StepDone "Scheduled Tasks Summary"

# ==== 7) DISM & SFC (English-only output + CBS summary) ====
Write-StepStart "DISM Health Scan"
Append-EXT "dism /online /cleanup-image /scanhealth"
Write-StepDone "DISM Health Scan"

Write-StepStart "SFC Scan"
Append-EXT "sfc /scannow"
Write-StepDone "SFC Scan"

Write-StepStart "SFC English Summary (CBS.log)"
Append-PS {
    try {
        $cbsPath = Join-Path $env:WINDIR "Logs\CBS\CBS.log"
        if (-not (Test-Path $cbsPath)) {
            "CBS.log not found at $cbsPath"
            return
        }
        # CBS.log is typically UTF-16 LE; use Unicode encoding in PS
        $lines = Get-Content -Path $cbsPath -Encoding Unicode -ErrorAction Stop
        $sfcLines = $lines | Where-Object { $_ -match '\bSFC\b' }
        if ($sfcLines.Count -eq 0) {
            "No SFC entries found in CBS.log."
            return
        }
        $tail = $sfcLines | Select-Object -Last 200
        $tail
        ""
        $text = ($tail -join "`n")
        $summary = @()
        if ($text -match 'Windows Resource Protection found integrity violations') { $summary += 'Detected: integrity violations found.' }
        if ($text -match 'Windows Resource Protection did not find any integrity violations') { $summary += 'OK: no integrity violations detected.' }
        if ($text -match 'Windows Resource Protection found corrupt files and successfully repaired them') { $summary += 'Fixed: corrupt files were repaired.' }
        if ($text -match 'Windows Resource Protection could not perform the requested operation') { $summary += 'Error: could not perform the requested operation.' }
        if ($text -match 'Repair complete') { $summary += 'Repair complete.' }
        if ($summary.Count -gt 0) { "Summary: " + ($summary -join ' ') } else { "Summary: No standard English status tokens found in last SFC-related entries." }
    } catch {
        "ERROR: CBS parsing failed: $($_.Exception.Message)"
    }
}
Write-StepDone "SFC English Summary (CBS.log)"

# ==== 8) Updates & Events ====
Write-StepStart "Installed Updates"
Append-PS {
    try {
        $hf = Get-HotFix | Select-Object Description, HotFixID, InstalledOn | Sort-Object InstalledOn
        if ($hf) { $hf } else { "No hotfix entries." }
    } catch {
        "ERROR: Get-HotFix failed: $($_.Exception.Message)"
    }
}
Write-StepDone "Installed Updates"

Write-StepStart "System Event Log Errors"
Append-PS {
    try {
        $events = Get-WinEvent -LogName System -MaxEvents 500 | Where-Object { $_.LevelDisplayName -eq 'Error' } | Select-Object -First 200 TimeCreated, ProviderName, Id, LevelDisplayName, Message
        if ($events) { $events } else { "No error events found in the last entries." }
    } catch {
        "ERROR: Get-WinEvent failed: $($_.Exception.Message)"
    }
}
Write-StepDone "System Event Log Errors"

# ==== 9) Disk space overview ====
Write-StepStart "Disk Space Overview"
Append-PS {
    Get-PSDrive -PSProvider FileSystem | Select-Object Name,
    @{n='Used(GB)';e={[math]::Round(($_.Used/1GB),2)}},
    @{n='Free(GB)';e={[math]::Round(($_.Free/1GB),2)}},
    @{n='Total(GB)';e={[math]::Round((($_.Used + $_.Free)/1GB),2)}}
}
Write-StepDone "Disk Space Overview"

# Final stamp
Append-Text ("`nReport generated at {0} (UTC: {1})" -f (Get-Date).ToString('u'), [DateTime]::UtcNow.ToString('u'))
Write-Host ("[{0}] >> Report generated: {1}" -f (Get-Date).ToString('u'), $Report)
