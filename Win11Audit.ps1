# filename: SystemAudit_English_Win11.ps1

# Strict mode for safer scripting
Set-StrictMode -Version Latest

# Report path (UTF-8)
$timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$desktop   = [Environment]::GetFolderPath('Desktop')
$Report    = Join-Path $desktop "SystemAudit_$timestamp.txt"
Set-Content -Path $Report -Value "" -Encoding UTF8

# Helper: append plain text to report (UTF-8)
function Append-Text {
    param([Parameter(Mandatory=$true)][string]$Text)
    Add-Content -Path $Report -Value $Text -Encoding UTF8
}

# Helper: append PowerShell command output (UTF-8)
function Append-PS {
    param([Parameter(Mandatory=$true)][ScriptBlock]$Cmd, [int]$Width = 500)
    try {
        $out = & $Cmd | Out-String -Width $Width
        Append-Text ($out.TrimEnd())
    } catch {
        Append-Text ("ERROR: {0}" -f $_.Exception.Message)
    }
}

# Helper: append external console tool output as UTF-8 (forces OEM to UTF-8 via chcp)
function Append-EXT {
    param([Parameter(Mandatory=$true)][string]$CommandLine, [int]$Width = 500)
    try {
        # Run the external command under cmd with UTF-8 code page and capture stdout
        $output = cmd /c "chcp 65001 > nul & $CommandLine"
        Append-Text (($output | Out-String -Width $Width).TrimEnd())
    } catch {
        Append-Text ("ERROR: {0}" -f $_.Exception.Message)
    }
}

# Helper: English headings
function H { param([string]$Title) Append-Text ("`n=== {0} ===" -f $Title) }

# 1) System info
H "System Information"
Append-PS { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, @{n='InstallDate';e={([Management.ManagementDateTimeConverter]::ToDateTime($_.InstallDate)).ToString('u')}}, @{n='LastBootUpTime';e={([Management.ManagementDateTimeConverter]::ToDateTime($_.LastBootUpTime)).ToString('u')}}, @{n='UptimeDays';e={[math]::Round((New-TimeSpan -Start ([Management.ManagementDateTimeConverter]::ToDateTime($_.LastBootUpTime)) -End (Get-Date)).TotalDays,2)}} }
Append-PS { Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, Username, Domain, TotalPhysicalMemory }
Append-PS { Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed }
Append-PS { Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer, Capacity, Speed, PartNumber }
Append-PS { Get-CimInstance Win32_BIOS | Select-Object Manufacturer, Name, Version, SMBIOSBIOSVersion, ReleaseDate }
Append-PS { Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free }
Append-PS { Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace }
Append-PS { Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, DriverProviderName, DriverDate | Sort-Object DeviceName }

# 2) Processes and services
H "Processes (top CPU and memory)"
Append-PS { Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 Name, Id, CPU, WS, PM, StartTime }
Append-PS { Get-Process | Sort-Object WS -Descending | Select-Object -First 25 Name, Id, CPU, WS, PM, StartTime }

H "Services (Running)"
Append-PS { Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, DisplayName, Status, StartType | Sort-Object DisplayName }

# 3) Networking
H "Network Configuration"
Append-PS { Get-NetIPConfiguration | Select-Object InterfaceAlias, InterfaceDescription, IPv4Address, IPv6Address, IPv4DefaultGateway, DnsServer }

H "Active Routes (IPv4 default gateways)"
Append-PS { Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -eq '0.0.0.0/0' | Select-Object ifIndex, DestinationPrefix, NextHop, RouteMetric }

H "ARP Table"
Append-EXT "arp -a"

H "Firewall Rules (enabled, inbound)"
Append-PS { Get-NetFirewallRule -Enabled True -Direction Inbound | Select-Object DisplayName, Action, Enabled, Direction, Profile | Sort-Object DisplayName }

H "Listening TCP ports"
Append-EXT "netstat -ano | findstr LISTENING"

H "Established TCP connections"
Append-EXT "netstat -ano | findstr ESTABLISHED"

# 4) Security (Windows Defender / Microsoft Defender)
H "Microsoft Defender Status"
Append-PS { Get-Service | Where-Object { $_.Name -like 'WinDefend' -or $_.DisplayName -like '*Defender*' -or $_.DisplayName -like '*Security*' } | Select-Object Name, DisplayName, Status, StartType }
Append-PS {
    try {
        Get-MpComputerStatus | Select-Object AMRunningMode, AntispywareEnabled, AntispywareSignatureLastUpdated, AntispywareSignatureVersion, AntivirusEnabled, AntivirusSignatureLastUpdated, AntivirusSignatureVersion, IsTamperProtected, RealTimeProtectionEnabled, DefenderSignaturesOutOfDate
    } catch {
        "Defender module unavailable (Get-MpComputerStatus): $($_.Exception.Message)"
    }
}
Append-PS {
    try {
        Get-MpThreatDetection | Select-Object ThreatName, InitialDetectionTime, LastThreatStatusChangeTime, Severity, Resources | Sort-Object LastThreatStatusChangeTime
    } catch {
        "Defender threat list unavailable (Get-MpThreatDetection): $($_.Exception.Message)"
    }
}

# 5) Autostart inventory
H "Autostart (Registry Run keys)"
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
    $items | Sort-Object Name
}

H "Autostart (Startup Folders)"
Append-PS {
    $paths = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
    Get-ChildItem -Path $paths -File -ErrorAction SilentlyContinue | Select-Object Directory, Name, FullName
}

H "Autostart (Logon scheduled tasks)"
Append-PS {
    try {
        Get-ScheduledTask | Where-Object { $_.Triggers | Where-Object { $_.TriggerType -eq 'Logon' } } | ForEach-Object {
            $actions = $_.Actions | ForEach-Object {
                if ($_.PSObject.Properties.Match('Execute').Count -gt 0) { $_.Execute } elseif ($_.PSObject.Properties.Match('Command').Count -gt 0) { $_.Command } else { $_.ToString() }
            }
            [pscustomobject]@{ TaskName=$_.TaskName; TaskPath=$_.TaskPath; Actions=($actions -join '; ') }
        }
    } catch {
        "Scheduled tasks enumeration failed: $($_.Exception.Message)"
    }
}

H "Auto-start Services (non-Microsoft)"
Append-PS {
    $exclude = 'Microsoft|Windows'
    Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and ($_.PathName -notmatch $exclude) } | Select-Object Name, DisplayName, State, StartMode, PathName | Sort-Object DisplayName
}

# 6) Scheduled tasks summary
H "Scheduled Tasks (Ready/Running with last run times)"
Append-PS {
    try {
        Get-ScheduledTask | Where-Object { $_.State -in @('Ready','Running') } | Select-Object TaskName, State, LastRunTime | Sort-Object LastRunTime
    } catch {
        "Scheduled tasks summary failed: $($_.Exception.Message)"
    }
}

# 7) Component Store / Health (DISM) and SFC (English summary)
H "DISM Component Store Health (English)"
# Run DISM in cmd with UTF-8; DISM messages come in English if system language is English, else may still be localized.
# To avoid Cyrillic in the report, we rely on CBS.log for SFC and let DISM output pass through UTF-8.
Append-EXT "dism /online /cleanup-image /scanhealth"

H "System File Checker (SFC) run"
Append-EXT "sfc /scannow"

H "SFC English Summary from CBS.log"
Append-PS {
    try {
        $cbsPath = "$env:WINDIR\Logs\CBS\CBS.log"
        if (Test-Path $cbsPath) {
            # CBS.log is Unicode; extract SFC lines and summarize status in English-style tokens
            $lines = Get-Content -Path $cbsPath -Encoding Unicode -ErrorAction Stop
            $sfcLines = $lines | Where-Object { $_ -match '^\d{4}-\d{2}-\d{2}.*\sSFC' }
            if ($sfcLines.Count -gt 0) {
                # Print last 200 SFC-related lines for context
                $tail = $sfcLines | Select-Object -Last 200
                $tail
                ""
                # Try to detect common statuses
                $summary = @()
                if ($tail -match 'Windows Resource Protection found integrity violations') { $summary += 'Detected: Windows Resource Protection found integrity violations.' }
                if ($tail -match 'Windows Resource Protection did not find any integrity violations') { $summary += 'OK: Windows Resource Protection did not find any integrity violations.' }
                if ($tail -match 'Windows Resource Protection found corrupt files and successfully repaired them') { $summary += 'Fixed: WRP found corrupt files and successfully repaired them.' }
                if ($tail -match 'Windows Resource Protection could not perform the requested operation') { $summary += 'Error: WRP could not perform the requested operation.' }
                if ($summary.Count -gt 0) { "Summary: " + ($summary -join ' ') } else { "Summary: No standard English status tokens found in last SFC messages." }
            } else {
                "No SFC entries found in CBS.log."
            }
        } else {
            "CBS.log not found at $cbsPath"
        }
    } catch {
        "CBS parsing failed: $($_.Exception.Message)"
    }
}

# 8) Updates and event logs
H "Installed Updates (Hotfixes)"
Append-PS { Get-HotFix | Select-Object Description, HotFixID, InstalledOn | Sort-Object InstalledOn }

H "System Event Log Errors (last 200)"
Append-PS {
    try {
        Get-WinEvent -LogName System -MaxEvents 200 | Where-Object { $_.LevelDisplayName -eq 'Error' } | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message
    } catch {
        "Event log read failed: $($_.Exception.Message)"
    }
}

# 9) Disk usage overview (friendly sizes)
H "Disk Space Overview (GB)"
Append-PS {
    Get-PSDrive -PSProvider FileSystem | Select-Object Name,
    @{n='Used(GB)';e={[math]::Round(($_.Used/1GB),2)}},
    @{n='Free(GB)';e={[math]::Round(($_.Free/1GB),2)}},
    @{n='Total(GB)';e={[math]::Round((($_.Used + $_.Free)/1GB),2)}}
}

# Administrative rights reminder (SFC/DISM need admin)
H "Execution Context"
Append-PS {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    [pscustomobject]@{ IsElevated = $isAdmin }
}

# Final stamp
Append-Text ("`nReport generated at {0} (UTC: {1})" -f (Get-Date).ToString('u'), [DateTime]::UtcNow.ToString('u'))

Write-Host "Report generated: $Report"
