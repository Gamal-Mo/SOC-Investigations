# Investigation ID: INV-0002

## Title
Interactive PowerShell Usage

## Date
2026-07-22

---

# Lab Environment

- SIEM: Elastic Security
- Endpoint: Windows 10
- Log Source: Sysmon & PowerShell Operational Logs
- Host: DESKTOP-0DFKSAT

---

# Objective

Determine whether the observed interactive PowerShell activity is benign or suspicious.

---

# Summary

User **gamal** on **DESKTOP-0DFKSAT** launched `powershell.exe` from `explorer.exe`. During the session, the user executed the PowerShell cmdlets `Get-Process`, `Get-Service`, and `Get-Date`. No suspicious behavior or malicious indicators were identified during this investigation.

---

# Evidence

| Field | Value |
|------|------|
| User | gamal |
| Host | DESKTOP-0DFKSAT |
| Process | powershell.exe |
| Parent Process | explorer.exe |
| Process ID (PID) | 4268 |
| Parent PID | 4944 |
| Executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| Dataset | windows.sysmon_operational |
| Event ID | 1 |

---

# KQL Queries Used

## Identify PowerShell process creation

```kql
event.dataset:"windows.sysmon_operational"
and event.code:"1"
and process.name:"powershell.exe"
```

## Review PowerShell Operational Logs

```kql
event.dataset:"windows.powershell_operational"
and winlog.process.pid:4268
```

## Filter Get-Process command

```kql
event.dataset:"windows.powershell_operational"
and powershell.command.name:"Get-Process"
```

---

# Timeline

| Time | Activity |
|------|----------|
| 2026-07-22 12:35:17.765 | Explorer.exe launched powershell.exe |
| 2026-07-22 12:35:31.005 | User executed the `Get-Process` PowerShell cmdlet |
| 2026-07-22 12:35:31.798 | User executed the `Get-Service` PowerShell cmdlet |
| 2026-07-22 12:35:32.333 | User executed the `Get-Date` PowerShell cmdlet |

---

# Investigation

The investigation began by identifying the creation of `powershell.exe` using Sysmon Event ID 1.

The parent process was `explorer.exe`, indicating that PowerShell was launched interactively by the logged-in user.

A pivot using the process ID (`4268`) and event timestamps led to the corresponding PowerShell Operational logs. These logs confirmed that the following PowerShell cmdlets were executed:

- Get-Process
- Get-Service
- Get-Date

The PowerShell Operational logs also provided additional context, including the executed command names, the user account, and the PowerShell engine information.

No encoded commands, obfuscated scripts, suspicious command-line arguments, or unexpected child processes were observed during the investigation.

---

# Analysis

The observed activity is consistent with normal interactive PowerShell usage.

The executed cmdlets are legitimate administrative commands commonly used to retrieve information about running processes, Windows services, and the current system date and time.

The parent-child relationship (`explorer.exe` → `powershell.exe`) is expected for a user-initiated PowerShell session.

No indicators of persistence, privilege escalation, defense evasion, or malicious execution were identified within the scope of this investigation.

---

# Verdict

**Classification:** Benign

**Confidence:** High

**Escalation Required:** No

---

# Lessons Learned

- Investigated interactive PowerShell execution using Sysmon Event ID 1.
- Correlated Sysmon telemetry with PowerShell Operational logs.
- Distinguished between PowerShell cmdlets and Windows processes.
- Practiced pivoting using Process IDs and timestamps.
- Confirmed that legitimate PowerShell cmdlets generate operational log events.
- Improved KQL filtering skills for PowerShell investigations.
