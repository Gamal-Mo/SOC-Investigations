# Investigation Report — INV-0012

## Title

BITS Job Abuse Investigation Using PowerShell (`Start-BitsTransfer`)

---

## Date

2026-07-29

---

## Lab Environment

- **SIEM:** Elastic Security
- **Endpoint:** Windows 10 Pro
- **Host:** DESKTOP-0DFKSAT
- **User:** gamal
- **Log Sources**
  - Sysmon Operational
  - Windows PowerShell Operational

---

## Objective

Investigate the execution of the PowerShell `Start-BitsTransfer` cmdlet, correlate PowerShell, Sysmon, and DNS telemetry, and understand how the Windows Background Intelligent Transfer Service (BITS) performs file downloads.

---

## Summary

A PowerShell session was used to execute the `Start-BitsTransfer` cmdlet in an attempt to download content from **https://example.com**.

Unlike previous investigations involving `certutil.exe`, PowerShell only created the BITS job. The actual transfer activity was performed by the Windows Background Intelligent Transfer Service (BITS), which runs inside **svchost.exe**.

Telemetry confirmed:

- Interactive PowerShell execution.
- Successful invocation of `Start-BitsTransfer`.
- Creation of a temporary BITS download file.
- DNS resolution performed by the BITS service.

No Sysmon Event ID 3 (Network Connection) was observed during the investigation.

The activity was intentionally generated in a controlled SOC laboratory.

---

# Evidence

| Field | Value |
|--------|-------|
| User | gamal |
| Initial Process | powershell.exe |
| BITS Host Process | svchost.exe |
| PowerShell Cmdlet | Start-BitsTransfer |
| Source URL | https://example.com |
| Destination | C:\Users\gamal\Desktop\SOCLab\bits-example.html |
| Temporary File | BIT52DC.tmp |
| DNS Query | example.com |
| Network Event | Not Collected |
| Investigation Type | Benign Lab Simulation |

---

# Attack Simulation

The following command was executed from an elevated PowerShell session.

```powershell
Start-BitsTransfer `
-Source "https://example.com" `
-Destination "$env:USERPROFILE\Desktop\SOCLab\bits-example.html"
```

---

## Command Explanation

| Parameter | Description |
|-----------|-------------|
| Start-BitsTransfer | Creates a Background Intelligent Transfer Service (BITS) job. |
| -Source | Remote file location. |
| -Destination | Local destination path. |

Unlike traditional download utilities, this cmdlet does not download the file itself. Instead, it creates a BITS job that is executed by the Windows BITS service.

---

# KQL Queries Used

## Process Creation

```kql
event.dataset:"windows.sysmon_operational"
and event.code:1
and process.name:"powershell.exe"
```

---

## PowerShell Cmdlet Execution

```kql
event.dataset:"windows.powershell_operational"
and message:*Start-BitsTransfer*
```

---

## File Creation

```kql
event.dataset:"windows.sysmon_operational"
and event.code:11
```

---

## DNS Resolution

```kql
event.dataset:"windows.sysmon_operational"
and event.code:22
and dns.question.name:"example.com"
```

---

## Correlation

```kql
process.entity_id:"{5f2fec87-46a3-6a6a-1500-000000001d00}"
```

---

# Timeline

| Time | Activity |
|------|----------|
| 11:39:29 | PowerShell process started |
| 11:39:41 | PowerShell executed `Start-BitsTransfer` |
| 11:39:40 | BITS service created temporary file `BIT52DC.tmp` |
| 11:39:41 | BITS service resolved `example.com` |
| N/A | No Sysmon Network Connection event observed |

---

# Investigation

The investigation began by identifying a new PowerShell process using Sysmon Event ID 1.

PowerShell Operational logging confirmed that the `Start-BitsTransfer` cmdlet was executed with the source URL **https://example.com** and destination **bits-example.html**.

Unlike `certutil.exe`, the cmdlet did not perform the download directly. Instead, PowerShell created a BITS job that was processed by the Windows Background Intelligent Transfer Service hosted inside **svchost.exe**.

Sysmon Event ID 11 confirmed that **svchost.exe** created the temporary file **BIT52DC.tmp**, indicating that the BITS service initiated the download process.

Sysmon Event ID 22 showed that **svchost.exe** successfully resolved **example.com** through DNS.

No Sysmon Event ID 3 (Network Connection) was recorded during the investigation. Based on the available telemetry, this is most likely due to the current Sysmon configuration or filtering of `svchost.exe` network events rather than evidence that no network communication occurred.

---

# Analysis

The execution flow reconstructed during the investigation is shown below.

```text
PowerShell
        │
        ▼
Start-BitsTransfer
(PowerShell Cmdlet)
        │
        ▼
BITS Service
(svchost.exe)
        │
        ├── Temporary File Created
        │
        ├── DNS Resolution
        │
        └── Network Connection
             (Not Collected)
```

This investigation demonstrates the importance of correlating multiple telemetry sources.

Unlike previous download techniques such as `certutil.exe`, the PowerShell cmdlet simply creates a BITS job. The Windows BITS service then performs the download in the background.

Although no network connection event was collected, PowerShell logging, Sysmon file creation, and DNS events collectively provide strong evidence that the BITS workflow was initiated successfully.

---

# Verdict

**Classification:** Benign (Lab Simulation)

**Confidence:** High

**Escalation Required:** No

---

# MITRE ATT&CK

| Technique | Description |
|------------|-------------|
| T1197 | BITS Jobs |
| T1105 | Ingress Tool Transfer |
| T1059.001 | PowerShell |

---

# Lessons Learned

- Learned how the Windows Background Intelligent Transfer Service (BITS) operates.
- Understood that `Start-BitsTransfer` creates a BITS job rather than performing the download itself.
- Correlated PowerShell Operational logs with Sysmon telemetry.
- Identified `svchost.exe` as the process hosting the BITS service.
- Observed temporary file creation during the download process.
- Verified DNS resolution performed by the BITS service.
- Identified telemetry limitations caused by the current Sysmon configuration.

