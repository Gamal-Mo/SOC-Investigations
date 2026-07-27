# Investigation Report — INV-0007

## Title

Local User Account Creation Investigation

---

## Date

2026-07-27

---

## Lab Environment

- **SIEM:** Elastic Security
- **Endpoint:** Windows 10 Pro
- **Host:** DESKTOP-0DFKSAT
- **Log Source:** Windows Security Event Log
- **Provider:** Microsoft-Windows-Security-Auditing

---

## Objective

Investigate the creation of a new local Windows user account, verify whether the account was enabled, determine its group memberships, and identify any evidence of privilege escalation.

---

## Summary

User **gamal** created a new local Windows account named **socuser** using the Windows `net user` command.

Windows Security logs confirmed that the account was successfully created and enabled immediately after creation.

Further investigation showed that the account was automatically added to the default **Builtin Users** group and was **not** granted administrative privileges.

No suspicious activity or privilege escalation was observed during the investigation.

---

# Evidence

| Field | Value |
|--------|-------|
| User | gamal |
| Host | DESKTOP-0DFKSAT |
| Created Account | socuser |
| Event Provider | Microsoft-Windows-Security-Auditing |
| Log Source | Windows Security |
| Event IDs | 4720, 4722, 4728, 4732, 4798 |
| Local Group | Builtin Users |
| Administrative Privileges | Not Assigned |

---

# Attack Simulation

The following command was executed from an elevated PowerShell session.

```cmd
net user socuser P@ssw0rd123! /add
```

---

# KQL Queries Used

## Locate User Creation

```kql
event.dataset:"system.security"
and event.code:4720
```

---

## Verify Account Enablement

```kql
event.dataset:"system.security"
and event.code:4722
```

---

## Check Security Group Membership

```kql
event.dataset:"system.security"
and event.code:4728
```

---

## Check Local Group Membership

```kql
event.dataset:"system.security"
and event.code:4732
```

---

## Review Account Enumeration

```kql
event.dataset:"system.security"
and event.code:4798
```

---

# Timeline

| Time | Activity |
|------|----------|
| 11:02:57 | Event ID 4720 – Local user account created |
| 11:02:57 | Event ID 4722 – User account enabled |
| 11:02:57 | Event ID 4728 – Added to security-enabled group |
| 11:02:57 | Event ID 4732 – Added to Builtin Users group |
| 11:03:54 | Event ID 4798 – User account enumeration |
| 11:04:52 | Event ID 4798 – User account enumeration |
| 11:05:52 | Event ID 4798 – User account enumeration |

---

# Investigation

The investigation began after identifying **Windows Security Event ID 4720**, indicating that a new local account had been created.

The event showed that user **gamal** created the account **socuser**.

Subsequent Windows Security events were reviewed to reconstruct the complete account lifecycle.

**Event ID 4722** confirmed that the newly created account was enabled immediately after creation.

**Event ID 4728** indicated that Windows added the account to a security-enabled group during the provisioning process.

To determine whether the account received elevated privileges, **Event ID 4732** was analyzed.

The event confirmed that **socuser** was added only to the **Builtin Users** group.

No evidence showed that the account was added to the **Administrators** group.

Finally, several **Event ID 4798** events were observed, indicating user account enumeration after account creation.

No suspicious follow-up activity was identified.

---

# Analysis

Creating a local user account is a common administrative operation but is also a technique frequently abused by attackers for persistence.

For this reason, **Event ID 4720 should never be analyzed in isolation.**

Correlating multiple account management events provided a complete understanding of the activity.

The investigation confirmed:

- The account was intentionally created by the administrator.
- The account was enabled successfully.
- The account received only the default **Builtin Users** membership.
- No privileged group membership was assigned.
- No evidence of persistence or privilege escalation was identified.

---

# Verdict

**Classification:** Benign

**Confidence:** High

**Escalation Required:** No

---

# MITRE ATT&CK

| Technique | Description |
|------------|-------------|
| T1136.001 | Create Account: Local Account |

---

# Lessons Learned

- Investigated Windows Security account management events.
- Correlated multiple Security Event IDs to reconstruct the complete account lifecycle.
- Distinguished between default user group membership and privileged group assignment.
- Verified account enablement after creation.
- Confirmed that the newly created account did not receive administrative privileges.
- Reinforced the importance of investigating related events instead of relying on a single Event ID.
