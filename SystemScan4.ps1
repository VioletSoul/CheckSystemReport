# filename: SystemAudit.ps1

$Report = Join-Path $env:USERPROFILE "Desktop\SystemAudit.txt"
Set-Content -Path $Report -Value "" -Encoding UTF8

function H($title) { "`n=== $title ===`n" | Out-File $Report -Append -Encoding UTF8 }
function Append-PowerShell { param([ScriptBlock]$Cmd); & $Cmd | Out-File $Report -Append -Encoding UTF8 }
function Append-External   { param([string]$CommandLine); cmd /c "chcp 65001 > nul & $CommandLine" | Out-File $Report -Append -Encoding UTF8 }

H "System Information"
Append-PowerShell { systeminfo }

H "Network Configuration"
Append-PowerShell { Get-NetIPConfiguration }

H "Active Routes"
Append-PowerShell { Get-NetRoute }

H "DNS Servers"
Append-PowerShell { Get-DnsClientServerAddress }

H "Active Network Connections"
Append-External   "netstat -ano"

H "Scheduled Tasks"
Append-PowerShell { Get-ScheduledTask }

H "Services"
Append-PowerShell { Get-Service }

H "Disk Space Overview"
Append-PowerShell { Get-PSDrive -PSProvider 'FileSystem' }

H "Integrity Check of System Files (SFC)"
Append-External   "sfc /scannow"

"`nReport generated at $(Get-Date)" | Out-File $Report -Append -Encoding UTF8
