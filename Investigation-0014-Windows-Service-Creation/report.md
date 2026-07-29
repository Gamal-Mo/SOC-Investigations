# Investigation Report — INV-0014

## Title

Windows Service Creation Using `sc.exe`

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
  - Windows System

---

## Objective

Investigate the creation of a Windows service using the Windows Service Control utility (`sc.exe`) and correlate the activity using Sysmon and Windows System logs to understand how Windows internally creates and registers a new service.

---

## Summary

An elevated PowerShell session was used to execute the Windows Service Control utility (`sc.exe`) to create a new Windows service named **SOCLabService**.

Sysmon Event ID 1 successfully captured the execution of `sc.exe`, including the parent process and the complete command line used during service creation.

Although the request originated from `sc.exe`, Sysmon Event ID 13 confirmed that the required registry modifications were performed by **services.exe**, the Windows Service Control Manager responsible for managing Windows services.

Windows System Event ID **7045** confirmed the successful installation of the service and recorded its executable path, startup configuration, and service account.

This investigation demonstrates how service creation generates telemetry across multiple Windows components and highlights the importance of correlating process creation, registry modifications, and native Windows events.

The activity was intentionally performed inside a controlled SOC laboratory.

---

# Evidence

| Field | Value |
|--------|-------|
| User | gamal |
| Process | sc.exe |
| Parent Process | powershell.exe |
| Service Name | SOCLabService |
| Executable | C:\Windows\System32\notepad.exe |
| Registry Path | HKLM\System\CurrentControlSet\Services\SOCLabService |
| Persistence Method | Windows Service |
| Investigation Type | Benign Lab Simulation |

---

# Attack Simulation

The following command was executed.

```powershell
sc.exe create SOCLabService binPath= "C:\Windows\System32\notepad.exe" start= demand
```

---

## Command Explanation

| Parameter | Description |
|-----------|-------------|
| `sc.exe` | Windows Service Control utility. |
| `create` | Creates a new Windows service. |
| `SOCLabService` | Name assigned to the service. |
| `binPath=` | Specifies the executable associated with the service. |
| `start= demand` | Configures the service for manual startup. |

---

# KQL Queries Used

## Process Creation

```kql
event.dataset:"windows.sysmon_operational"
and event.code:1
and process.name:"sc.exe"
```

---

## Registry Modification

```kql
event.dataset:"windows.sysmon_operational"
and event.code:13
and registry.key:*SOCLabService*
```

---

## Service Installation

```kql
event.dataset:"system.system"
and winlog.event_id:7045
```

---

## Search by Service Name

```kql
SOCLabService
```

---

## Correlation

```kql
process.name:("sc.exe" or "services.exe")
```

---

# Timeline

| Time | Activity |
|------|----------|
| 14:47:53 | PowerShell executed `sc.exe create` |
| 14:47:54 | Sysmon recorded creation of `sc.exe` |
| 14:47:54 | Sysmon recorded registry modifications performed by `services.exe` |
| 14:47:54 | Windows System logged Event ID 7045 confirming service installation |

---

# Investigation

The investigation began after identifying a newly created **sc.exe** process through Sysmon Event ID 1.

The parent process was identified as **powershell.exe**, confirming that the service creation originated from an interactive PowerShell session.

Sysmon captured the complete command line used to create the service, including the service name, executable path, and startup configuration.

Sysmon Event ID 13 confirmed that **services.exe** created the required registry values under:

```text
HKLM\System\CurrentControlSet\Services\SOCLabService
```

The registry modifications included the **ImagePath** value, which specifies the executable associated with the service, and the **Start** value, which defines the startup mode.

Windows System Event ID **7045** confirmed that the new service was successfully installed and recorded the service name, executable path, startup type, and service account.

Correlation between Sysmon Process Creation, Registry Modification events, and Windows System logs reconstructed the complete service creation workflow.

---

# Analysis

The reconstructed execution flow is shown below.

```text
User
    │
    ▼
powershell.exe
    │
    ▼
sc.exe
    │
    ▼
services.exe
(Service Control Manager)
    │
    ├──────────────┐
    ▼              ▼
Registry      Event ID 7045
(Event 13)    Service Installed
```

This investigation demonstrates how Windows internally processes service creation requests.

Unlike directly editing the Registry, `sc.exe` sends a request to the Windows Service Control Manager. The Service Control Manager (`services.exe`) performs the registry modifications required to register the new service and then generates the corresponding Windows System events.

Correlation between Sysmon and Windows System logs provided complete visibility into the attack chain, including process creation, registry modification, and successful service installation.

---

# Verdict

**Classification:** Benign (Lab Simulation)

**Confidence:** High

**Escalation Required:** No

---

# MITRE ATT&CK

| Technique | Description |
|------------|-------------|
| T1543.003 | Create or Modify System Process: Windows Service |

---

# Lessons Learned

- Investigated a common Windows persistence technique.
- Learned how Windows services are created using `sc.exe`.
- Correlated Sysmon Process Creation, Registry Modification, and Windows System logs.
- Verified registry modifications using Sysmon Event ID 13.
- Confirmed service installation using Windows System Event ID 7045.
- Identified the complete workflow from command execution to Windows Service registration.
