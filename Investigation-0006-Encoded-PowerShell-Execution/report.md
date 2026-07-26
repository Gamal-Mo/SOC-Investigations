# Investigation Report — INV-0006

## Title

Encoded PowerShell Command Execution

---

## Date

2026-07-26

---

## Lab Environment

- SIEM: Elastic Security
- Endpoint: Windows 10
- Log Sources:
  - Sysmon Operational
  - Windows PowerShell Operational
- Host: DESKTOP-0DFKSAT

---

## Objective

Investigate a PowerShell process executed with the `-EncodedCommand` parameter and determine whether the activity is malicious or benign.

---

## Summary

User **gamal** executed **powershell.exe** with the `-EncodedCommand` argument.

The Base64-encoded command was extracted from the process command line, decoded using CyberChef, and identified as the legitimate PowerShell cmdlet:

```
Get-Process
```

Correlation using `process.entity_id` linked the PowerShell process creation event with the corresponding PowerShell Operational logs.

No malicious behavior, persistence mechanisms, privilege escalation, or suspicious network activity were observed.

---

# Evidence

| Field | Value |
|--------|-------|
| User | gamal |
| Host | DESKTOP-0DFKSAT |
| Process | powershell.exe |
| Parent Process | explorer.exe |
| Executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| Event ID | 1 |
| Dataset | windows.sysmon_operational |
| Technique | PowerShell Encoded Command |
| Decoded Command | Get-Process |

---

# KQL Queries Used

## Locate PowerShell process creation

```kql
event.dataset:"windows.sysmon_operational"
and event.code:1
and process.command_line:*EncodedCommand*
```

---

## Pivot using Process Entity ID

```kql
process.entity_id:"<entity_id>"
```

---

## Review PowerShell Operational Logs

```kql
event.dataset:"windows.powershell_operational"
```

---

# Timeline

| Time | Activity |
|------|----------|
| 2026-07-26 | PowerShell launched with `-EncodedCommand` |
| 2026-07-26 | Sysmon Event ID 1 recorded process creation |
| 2026-07-26 | Base64 command extracted |
| 2026-07-26 | Base64 decoded using CyberChef |
| 2026-07-26 | PowerShell Operational logs confirmed `Get-Process` execution |

---

# Investigation

The investigation began by identifying a PowerShell process launched with the `-EncodedCommand` parameter using Sysmon Event ID 1.

The process command line contained a Base64-encoded string.

The encoded value was copied into CyberChef and decoded using:

- From Base64
- Decode Text (UTF-16LE)

The decoded command was:

```powershell
Get-Process
```

The investigation then pivoted using the process entity identifier (`process.entity_id`) to retrieve all telemetry related to the same PowerShell process.

PowerShell Operational logs confirmed execution of the decoded command through the `CommandInvocation(Get-Process)` event.

No additional suspicious commands, encoded payloads, child processes, or network connections were identified.

---

# Analysis

PowerShell encoded commands are frequently used by attackers to hide malicious activity and evade simple detections.

Although the command was encoded, the decoded payload contained only the legitimate administrative cmdlet:

```powershell
Get-Process
```

The command simply enumerates running processes and does not perform any malicious action.

The correlation between Sysmon process creation and PowerShell Operational logs confirmed the decoded command and verified the complete execution chain.

No indicators of compromise were identified.

---

# Verdict

**Classification:** Benign

**Confidence:** High

**Escalation Required:** No

---

# MITRE ATT&CK

| Technique | Description |
|------------|-------------|
| T1059.001 | PowerShell |

---

# Lessons Learned

- Investigated PowerShell execution using the `-EncodedCommand` parameter.
- Extracted Base64 payloads from Sysmon process creation events.
- Decoded PowerShell commands using CyberChef.
- Correlated Sysmon telemetry with PowerShell Operational logs.
- Used `process.entity_id` to pivot across events belonging to the same process.
- Understood how attackers commonly obfuscate PowerShell commands using Base64 encoding.
