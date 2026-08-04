# Investigation Report — INV-0016

## Title

Local Administrator Account Creation Using PowerShell

---

## Date

2026-08-04

---

## Lab Environment

- **SIEM:** Elastic Security
- **Endpoint:** Windows 10 Pro
- **Hostname:** DESKTOP-0DFKSAT
- **User:** gamal

### Log Sources

- Microsoft-Windows-Security-Auditing
- Microsoft-Windows-Sysmon
- Windows PowerShell Operational

---

# Objective

Investigate the creation of a new local administrator account using native Windows commands executed from PowerShell and reconstruct the complete attack chain using Windows Security Logs, Sysmon, and PowerShell Operational logs.

---

# Summary

An elevated PowerShell session was used to create a new local user account named **socadmin**, assign a password, and add the account to the local **Administrators** group.

PowerShell Script Block Logging recorded the executed commands, Sysmon captured the underlying process creation (`net1.exe`), and Windows Security Logs documented every stage of the account lifecycle including creation, password assignment, account activation, and group membership modification.

The activity represents a common privilege escalation and persistence technique frequently observed during post-exploitation.

The activity was intentionally performed inside a controlled SOC laboratory.

---

# Evidence

| Field | Value |
|--------|-------|
| User | gamal |
| Target Account | socadmin |
| Process | powershell.exe |
| Child Process | net1.exe |
| Commands | `net user` / `net localgroup` |
| Created Account | socadmin |
| Added Group | Administrators |
| Investigation Type | Benign Lab Simulation |

---

# Attack Simulation

The following commands were executed.

```powershell
net user socadmin P@ssw0rd123! /add

net localgroup Administrators socadmin /add
```

---

# Command Explanation

| Command | Purpose |
|----------|----------|
| net user /add | Creates a new local Windows account |
| net localgroup Administrators /add | Adds the account to the local Administrators group |

---

# KQL Queries Used

## User Account Created

```kql
event.dataset:"system.security"
and event.code:4720
```

---

## User Account Enabled

```kql
event.dataset:"system.security"
and event.code:4722
```

---

## Password Set

```kql
event.dataset:"system.security"
and event.code:4724
```

---

## Group Membership Added

```kql
event.dataset:"system.security"
and event.code:4732
```

---

## Sysmon Process Creation

```kql
event.dataset:"windows.sysmon_operational"
and event.code:1
and process.name:"net1.exe"
```

---

## PowerShell Script Block Logging

```kql
event.dataset:"windows.powershell_operational"
and message:*socadmin*
```

---

# Timeline

| Time | Activity |
|------|----------|
| 15:33:16 | User account **socadmin** created (4720) |
| 15:33:16 | Password assigned (4724) |
| 15:33:16 | Account enabled (4722) |
| 15:33:45 | PowerShell executed `net localgroup Administrators socadmin /add` |
| 15:33:45 | Sysmon recorded execution of `net1.exe` |
| 15:33:45 | Event 4732 added the account to the default Users group |
| 15:33:45 | Event 4732 added the account to the Administrators group |

---

# Investigation

The investigation began after reviewing PowerShell Script Block Logging, which recorded execution of the `net user` command used to create a new local account named **socadmin**.

Windows Security Event ID 4720 confirmed successful account creation. Immediately afterward, Event ID 4724 recorded the assignment of a password, followed by Event ID 4722 confirming that the account was enabled.

PowerShell Script Block Logging later captured execution of the `net localgroup Administrators socadmin /add` command.

Sysmon Event ID 1 recorded execution of `net1.exe`, providing process-level visibility into the command responsible for modifying local group membership.

Windows Security Event ID 4732 documented two group membership changes. The first added the new account to the default **Users** group, while the second confirmed that **socadmin** was successfully added to the local **Administrators** group.

Correlation across PowerShell Operational logs, Sysmon, and Windows Security logs reconstructed the complete privilege escalation workflow from account creation through administrator assignment.

---

# Analysis

```
Administrator PowerShell
        │
        ▼
net user socadmin /add
        │
        ▼
4720
Account Created
        │
        ▼
4724
Password Set
        │
        ▼
4722
Account Enabled
        │
        ▼
net localgroup Administrators socadmin /add
        │
        ▼
Sysmon Event ID 1
(net1.exe)
        │
        ▼
4732
Users Group
        │
        ▼
4732
Administrators Group
```

This activity demonstrates a common attacker technique used after gaining administrative access to a compromised Windows system.

Creating a secondary administrator account provides long-term persistence and allows continued privileged access even if the original credentials are revoked.

Correlation of multiple log sources provides complete visibility into the attack lifecycle.

---

# Verdict

**Classification:** Benign (Lab Simulation)

**Confidence:** High

**Escalation Required:** No

---

# MITRE ATT&CK

| Technique | Description |
|------------|-------------|
| T1136.001 | Create Local Account |
| T1098 | Account Manipulation |
| T1059.001 | PowerShell |

---

# Lessons Learned

- Investigated local account creation using Windows native commands.
- Correlated PowerShell Operational logs with Sysmon process creation.
- Identified Windows Security events related to account lifecycle.
- Learned how attackers establish privileged persistence through local administrator accounts.
- Reconstructed the complete attack chain across multiple log sources.
