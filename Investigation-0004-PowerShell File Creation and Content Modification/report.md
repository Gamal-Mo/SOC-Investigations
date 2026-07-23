# Investigation ID: INV-0004

# Title

PowerShell File Creation and Content Modification

# Date

2026-07-23

# Lab Environment

- SIEM: Elastic Security
- Endpoint: Windows 10 Pro
- Log Sources:
  - Sysmon Operational
  - Windows PowerShell Operational
- Host: DESKTOP-0DFKSAT

---

# Objective

Investigate a PowerShell session that created a directory, generated a text file, and wrote data into the file. Determine whether the activity is legitimate or suspicious.

---

# Summary

User **gamal** launched **powershell.exe** interactively from **explorer.exe**.

During the session, PowerShell executed several file system operations:

- Created a directory named **SOCLab**
- Created a text file named **notes.txt**
- Wrote the string **"SOC Investigation Lab"** into the file

Sysmon Event ID 11 confirmed the file creation, while PowerShell Operational logs recorded the executed cmdlets.

No indicators of malicious behavior were identified.

---

# Evidence

| Field | Value |
|-------|-------|
| User | gamal |
| Host | DESKTOP-0DFKSAT |
| Process | powershell.exe |
| Parent Process | explorer.exe |
| Process ID | 460 |
| Parent PID | 4888 |
| Executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| Directory Created | C:\Users\gamal\Desktop\SOCLab |
| File Created | notes.txt |
| File Path | C:\Users\gamal\Desktop\SOCLab\notes.txt |
| File Content | SOC Investigation Lab |
| Sysmon Event | Event ID 1, Event ID 11 |
| PowerShell Log | Windows PowerShell Operational |

---

# KQL Queries Used

### Find PowerShell Process Creation

```kql
event.dataset:"windows.sysmon_operational"
and event.code:"1"
and process.pid:460
```

### Find File Creation Events

```kql
event.dataset:"windows.sysmon_operational"
and event.code:"11"
and process.pid:460
```

### Review PowerShell Operational Logs

```kql
event.dataset:"windows.powershell_operational"
and winlog.process.pid:460
```

---

# Timeline

| Time | Activity |
|------|----------|
| 2026-07-23 09:09:33 | PowerShell process created |
| 2026-07-23 09:09:33 | New-Item created the SOCLab directory |
| 2026-07-23 09:09:38 | New-Item created notes.txt |
| 2026-07-23 09:09:55 | Sysmon Event ID 11 confirmed notes.txt creation |
| 2026-07-23 09:10:09 | Set-Content wrote "SOC Investigation Lab" into notes.txt |

---

# Investigation

The investigation began by identifying a PowerShell process using Sysmon Event ID 1.

The parent process was **explorer.exe**, indicating an interactive PowerShell session initiated by the logged-in user.

Using the PowerShell process ID (460), the investigation pivoted to Windows PowerShell Operational logs.

The logs showed the execution of the following cmdlets:

- New-Item (Directory)
- New-Item (File)
- Set-Content

PowerShell Script Block Logging captured the full commands, including the destination path and parameters.

Sysmon Event ID 11 confirmed that **notes.txt** was successfully created at:

```
C:\Users\gamal\Desktop\SOCLab\notes.txt
```

The Set-Content cmdlet subsequently wrote the string:

```
SOC Investigation Lab
```

into the newly created file.

No encoded commands, obfuscated scripts, external downloads, or suspicious child processes were observed during the investigation.

---

# Analysis

The activity is consistent with normal administrative PowerShell usage.

Correlation between Sysmon Process Creation, PowerShell Operational logs, and Sysmon FileCreate events confirmed the complete execution flow from process launch to file creation and content modification.

The observed commands are legitimate PowerShell cmdlets commonly used for file management and automation.

No evidence of persistence, privilege escalation, defense evasion, or malicious execution was identified.

---

# Verdict

**Classification:** Benign

**Confidence:** High

**Escalation Required:** No

---

# Lessons Learned

- Investigated PowerShell activity using multiple telemetry sources.
- Correlated Sysmon Event ID 1 with Event ID 11.
- Used Process ID to pivot across log sources.
- Verified PowerShell Script Block Logging.
- Confirmed directory creation, file creation, and file modification.
- Practiced reconstructing an attack timeline using Elastic Security.
- Improved KQL filtering and investigation workflow.
