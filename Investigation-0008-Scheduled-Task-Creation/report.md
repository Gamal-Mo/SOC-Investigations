# Investigation Report — INV-0007

## Title

Scheduled Task Creation Using schtasks.exe

---

## Date

2026-07-27

---

## Lab Environment

- SIEM: Elastic Security
- Endpoint: Windows 10
- Log Sources:
  - Sysmon Operational
- Host: DESKTOP-0DFKSAT

---

## Objective

Investigate the creation of a scheduled task using `schtasks.exe`, identify the related Sysmon events, and understand how Windows creates scheduled task files through the Task Scheduler service.

---

## Summary

User **gamal** manually created a scheduled task named **SOC-Lab-Task** using the Windows `schtasks.exe` utility.

The investigation identified two important Sysmon events:

1. **Process Creation (Event ID 1)** showing the execution of `schtasks.exe`.
2. **File Creation (Event ID 11)** showing the creation of the scheduled task file by **svchost.exe**, which hosts the Windows Task Scheduler service.

The investigation demonstrates that `schtasks.exe` requests the creation of the task, while the Task Scheduler service performs the actual file creation.

No malicious behavior was observed.

---

# Evidence

| Field | Value |
|--------|-------|
| User | gamal |
| Host | DESKTOP-0DFKSAT |
| Process | schtasks.exe |
| Executed Command | `schtasks /create /tn "SOC-Lab-Task" /tr "notepad.exe" /sc once /st 23:59` |
| Task Name | SOC-Lab-Task |
| Scheduled Program | notepad.exe |
| Process Event | Sysmon Event ID 1 |
| File Event | Sysmon Event ID 11 |
| Created File | `C:\Windows\System32\Tasks\SOC-Lab-Task` |

---

# KQL Queries Used

## Find schtasks execution

```kql
event.dataset:"windows.sysmon_operational"
and event.code:1
and process.name:"schtasks.exe"
```

---

## Find scheduled task file creation

```kql
event.dataset:"windows.sysmon_operational"
and event.code:11
and file.path:*SOC-Lab-Task*
```

---

## Search by task name

```kql
SOC-Lab-Task
```

---

# Timeline

| Time | Activity |
|------|----------|
| 2026-07-27 | User executed `schtasks.exe` |
| 2026-07-27 | Sysmon logged Process Create (Event ID 1) |
| 2026-07-27 | Task Scheduler service processed the request |
| 2026-07-27 | Sysmon logged File Create (Event ID 11) |
| 2026-07-27 | Scheduled task file created in `C:\Windows\System32\Tasks` |

---

# Investigation

The investigation started after manually creating a scheduled task using the following command:

```powershell
schtasks /create /tn "SOC-Lab-Task" /tr "notepad.exe" /sc once /st 23:59
```

Sysmon Event ID 1 recorded the execution of **schtasks.exe** and captured the full command line.

The command instructed Windows to create a scheduled task named **SOC-Lab-Task** that launches **notepad.exe** one time at **23:59**.

The investigation then searched for the created task name.

Sysmon Event ID 11 recorded the creation of the task file:

```
C:\Windows\System32\Tasks\SOC-Lab-Task
```

Interestingly, the file was **not** created by `schtasks.exe`.

Instead, it was created by:

```
svchost.exe
```

running as

```
NT AUTHORITY\SYSTEM
```

This occurs because the **Task Scheduler service**, hosted inside `svchost.exe`, performs the actual creation of scheduled task files after receiving the request from `schtasks.exe`.

The investigation confirmed the complete execution flow from user command to task creation.

---

# Analysis

Windows separates the **request** to create a scheduled task from the **actual implementation**.

The process `schtasks.exe` acts as a client utility that sends the task creation request.

The Task Scheduler service, running inside `svchost.exe`, receives this request and creates the task file under:

```
C:\Windows\System32\Tasks\
```

Understanding this relationship is important during threat hunting because attackers frequently abuse scheduled tasks for persistence.

SOC analysts should expect to observe:

- `schtasks.exe` initiating the request.
- `svchost.exe` creating the scheduled task file.

This behavior is normal for legitimate task creation.

---

# Verdict

**Classification:** Benign

**Confidence:** High

**Escalation Required:** No

---

# MITRE ATT&CK

| Technique | Description |
|------------|-------------|
| T1053.005 | Scheduled Task |

---

# Lessons Learned

- Investigated scheduled task creation using `schtasks.exe`.
- Identified Sysmon Process Create (Event ID 1).
- Identified Sysmon File Create (Event ID 11).
- Learned that `schtasks.exe` requests task creation but does not create the task file itself.
- Understood that the Task Scheduler service, hosted by `svchost.exe`, creates scheduled task files.
- Learned where scheduled tasks are stored in Windows.
- Practiced correlating multiple Sysmon events to reconstruct an activity.
