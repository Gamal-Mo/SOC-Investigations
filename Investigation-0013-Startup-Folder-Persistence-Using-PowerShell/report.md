# Investigation Report — INV-0013

## Title

Startup Folder Persistence Using PowerShell (`Copy-Item`)

---

## Date

2026-07-29

---

## Lab Environment

- **SIEM:** Elastic Security
- **Endpoint:** Windows 10 Pro
- **Hostname:** DESKTOP-0DFKSAT
- **User:** gamal
- **Log Sources**
  - Microsoft-Windows-Sysmon
  - Windows PowerShell Operational

---

## Objective

Investigate the use of PowerShell to establish persistence by copying an executable into the current user's Startup folder and correlate the activity using Sysmon and PowerShell Operational logs.

---

## Summary

An elevated PowerShell session was used to copy the legitimate Windows executable **notepad.exe** into the current user's Startup folder using the `Copy-Item` cmdlet.

PowerShell Operational logging successfully captured the executed cmdlet, including both the source and destination paths.

Sysmon Event ID 11 confirmed the creation of the new executable inside the Startup folder, while Sysmon Event ID 1 recorded the PowerShell process responsible for the action.

The copied executable will automatically execute the next time the user logs on, demonstrating a common persistence technique frequently abused by malware.

The activity was intentionally performed inside a controlled SOC laboratory.

---

# Evidence

| Field | Value |
|--------|-------|
| User | gamal |
| Process | powershell.exe |
| Parent Process | RuntimeBroker.exe |
| Command | Copy-Item |
| Source File | C:\Windows\System32\notepad.exe |
| Destination | C:\Users\gamal\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\notepad.exe |
| Persistence Method | Startup Folder |
| Investigation Type | Benign Lab Simulation |

---

# Attack Simulation

The following PowerShell command was executed.

```powershell
Copy-Item "$env:SystemRoot\System32\notepad.exe" `
"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\notepad.exe"
```

---

## Command Explanation

| Parameter | Description |
|-----------|-------------|
| Copy-Item | Copies a file from one location to another. |
| Source | Original executable (`notepad.exe`). |
| Destination | Startup folder where Windows automatically executes programs after user logon. |

---

# KQL Queries Used

## Process Creation

```kql
event.dataset:"windows.sysmon_operational"
and event.code:1
and process.name:"powershell.exe"
```

---

## PowerShell Cmdlet

```kql
event.dataset:"windows.powershell_operational"
and message:*Copy-Item*
```

---

## Startup File Creation

```kql
event.dataset:"windows.sysmon_operational"
and event.code:11
and file.path:*Startup*
```

---

## Search by File Name

```kql
event.dataset:"windows.powershell_operational"
and message:"notepad.exe"
```

---

## Correlation

```kql
process.entity_id:"{5f2fec87-e009-6a69-0401-000000001e00}"
```

---

# Timeline

| Time | Activity |
|------|----------|
| 14:12:09 | PowerShell process created |
| 14:12:11 | PowerShell executed `Copy-Item` |
| 14:12:11 | Sysmon recorded creation of `Startup\notepad.exe` |
| 14:12:21 | PowerShell Module Logging captured parameter binding |
| Next User Logon | Windows will automatically launch `notepad.exe` from the Startup folder |

---

# Investigation

The investigation began after identifying a newly created PowerShell process through Sysmon Event ID 1.

The parent process was identified as **RuntimeBroker.exe**, which is consistent with launching an elevated PowerShell instance through the Windows Start menu/UAC workflow.

PowerShell Operational logging captured the execution of the `Copy-Item` cmdlet and recorded both the source executable (`C:\Windows\System32\notepad.exe`) and the destination path inside the Startup folder.

Sysmon Event ID 11 confirmed that PowerShell created a new executable at:

```
C:\Users\gamal\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\notepad.exe
```

Correlation using the PowerShell `process.entity_id` showed that all observed events belonged to the same interactive PowerShell session.

This technique establishes persistence because any executable placed inside the Startup folder is automatically executed when the user signs in to Windows.

---

# Analysis

The reconstructed execution flow is shown below.

```text
User
    │
    ▼
RuntimeBroker.exe
    │
    ▼
powershell.exe
    │
    ▼
Copy-Item
    │
    ▼
Startup Folder
    │
    ▼
notepad.exe
    │
    ▼
Automatic Execution
(Next User Logon)
```

This investigation demonstrates one of the simplest persistence mechanisms available on Windows.

Unlike Registry Run Keys or Scheduled Tasks, the attacker simply copies an executable into the Startup folder. Windows Explorer automatically executes the file during the next interactive logon.

Correlation between Sysmon and PowerShell Operational logs provided complete visibility into the attack chain, including process creation, command execution, and file creation.

---

# Verdict

**Classification:** Benign (Lab Simulation)

**Confidence:** High

**Escalation Required:** No

---

# MITRE ATT&CK

| Technique | Description |
|------------|-------------|
| T1547.001 | Registry Run Keys / Startup Folder |
| T1059.001 | PowerShell |

---

# Lessons Learned

- Investigated a common Windows persistence technique.
- Learned how malware can abuse the Startup folder.
- Correlated Sysmon and PowerShell Operational logs.
- Used `process.entity_id` to reconstruct the PowerShell session.
- Verified file creation using Sysmon Event ID 11.
- Identified the complete persistence workflow from command execution to automatic execution at user logon.
