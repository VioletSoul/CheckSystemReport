# Win11 System Audit Script

![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat&logo=powershell&logoColor=white)
![Windows 11](https://img.shields.io/badge/Windows-11-00adef?style=flat&logo=windows11&logoColor=white)
![DISM](https://img.shields.io/badge/DISM-✓-blue)
![SFC](https://img.shields.io/badge/SFC-✓-green)
![Logging](https://img.shields.io/badge/Report-UTF8-lightgrey)
![License](https://img.shields.io/badge/License-MIT-blue)

**Win11Audit.ps1** is a compact Windows 11 diagnostic tool written in PowerShell.  
It collects detailed system, hardware, network, and security information, performs integrity checks (DISM/SFC), and generates a clean UTF-8 report saved to the Desktop.

---

## Key Features

- **System Information**
    - OS version, uptime, installation date
    - CPU, RAM, BIOS, disks
    - Drivers and top processes

- **Network Diagnostics**
    - IP configuration
    - Routes, ARP table
    - Firewall rules
    - TCP listening and active sessions

- **Security Status**
    - Microsoft Defender real-time protection
    - Signature versions
    - Detection history (if available)

- **Autostart & Scheduled Tasks**
    - Run/RunOnce registry entries
    - Startup folders
    - Logon-triggered scheduled tasks
    - Non-Microsoft autostart services

- **System Health Checks**
    - DISM /scanhealth with live progress
    - SFC /scannow with progress
    - Clean English summary parsed from CBS.log

- **Error-Resilient Execution**
    - Extensive try/catch
    - Fallback outputs when data is missing
    - UTF-8 enforced for all external commands

---

## Report Format

The script creates a file such as:
```
SystemAudit_2025-01-12_14-22-57.txt
```
Containing:

1. Execution context
2. System information
3. Hardware and drivers
4. Processes and services
5. Network configuration
6. Firewall and TCP sessions
7. Microsoft Defender status
8. Autostart inventory
9. Scheduled tasks
10. DISM & SFC integrity results
11. Event Log errors
12. Disk space overview
13. Final timestamp

---

## Requirements

- Windows 11
- PowerShell 5.1 or PowerShell 7+
- Administrator rights recommended for DISM/SFC

---

## Running the Script

1. Download or clone the repository.
2. Open PowerShell as **Administrator**.
3. Run the script: `.\Win11Audit.ps1`
4. The report will appear on your Desktop.

---

## Usage Example

After launching the script:

- You’ll see step-by-step status messages with clean formatting.
- DISM and SFC show real progress bars.
- The final report contains system health, hardware info, network settings, Defender status, autostart items, event logs, and integrity results.

---

## License

MIT License

---

## Contact

Open an issue in the repository for suggestions or questions.

---

**Win11 System Audit Script** — a clean, fast, readable Windows 11 diagnostic tool.