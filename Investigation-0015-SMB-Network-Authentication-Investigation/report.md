# Investigation Report — INV-0015

## Title

SMB Network Authentication Investigation (Failed and Successful Logons)

---

## Date

2026-08-04

---

## Lab Environment

- **SIEM:** Elastic Security
- **Endpoint:** Windows 10 Pro
- **Hostname:** DESKTOP-0DFKSAT
- **Source Host:** LAPTOP-HMLU2C6L
- **User:** gamal
- **Log Sources**
  - Windows Security Log

---

## Objective

Investigate Windows SMB network authentication events by correlating failed and successful NTLM logon attempts using Windows Security Event IDs 4625 and 4624.

---

## Summary

A remote system (**LAPTOP-HMLU2C6L**) attempted to authenticate to the SMB service hosted on **DESKTOP-0DFKSAT** using the account **gamal**.

Several authentication attempts initially failed because invalid credentials were supplied. Windows generated multiple Security Event ID **4625** events indicating failed NTLM network logons.

After correcting the credentials, the authentication succeeded and Windows generated Event ID **4624**, confirming a successful Network Logon (Logon Type 3).

The activity was intentionally generated inside a controlled SOC laboratory to understand SMB authentication behavior.

---

# Evidence

| Field | Value |
|--------|-------|
| Username | gamal |
| Authentication Protocol | NTLM |
| Logon Type | 3 (Network) |
| Source Workstation | LAPTOP-HMLU2C6L |
| Source Address | fe80::e62e:1916:426a:9435 |
| Destination Host | DESKTOP-0DFKSAT |
| Failure Events | Event ID 4625 |
| Successful Events | Event ID 4624 |
| Investigation Type | Benign Lab Simulation |

---

# Attack Simulation

The following SMB authentication attempts were performed.

1. Multiple login attempts using an incorrect password.
2. Authentication using the correct credentials.
3. Verification of both failed and successful Windows Security events.

---

## Authentication Flow

```text
Client (LAPTOP-HMLU2C6L)
          │
          ▼
 SMB Connection
          │
          ▼
 NTLM Authentication
          │
     Wrong Password
          │
          ▼
 Event ID 4625
          │
 Correct Password
          │
          ▼
 Event ID 4624
```

---

# KQL Queries Used

## Failed SMB Logons

```kql
event.dataset:"system.security"
and event.code:4625
and winlog.logon.type:"Network"
```

---

## Successful SMB Logons

```kql
event.dataset:"system.security"
and event.code:4624
and winlog.logon.type:"Network"
```

---

## Failed Authentication for User

```kql
event.dataset:"system.security"
and event.code:4625
and user.name:"gamal"
```

---

## Successful Authentication for User

```kql
event.dataset:"system.security"
and event.code:4624
and user.name:"gamal"
```

---

## NTLM Authentication Events

```kql
event.dataset:"system.security"
and winlog.event_data.AuthenticationPackageName:"NTLM"
```

---

# Timeline

| Time | Activity |
|------|----------|
| 14:12:50 | First failed SMB authentication (4625) |
| 14:12:53 | Additional failed authentication |
| 14:12:55 | Another failed authentication |
| 14:13:05 | Successful SMB authentication (4624) |
| 14:13:24 | Additional successful authentication |

---

# Investigation

The investigation began after identifying multiple Windows Security Event ID **4625** events indicating failed network logons.

Analysis of the Security log showed:

- Authentication Package: **NTLM**
- Logon Type: **3 (Network)**
- Source Workstation: **LAPTOP-HMLU2C6L**
- Target User: **gamal**

The failure status codes observed were:

```
Status:     0xC000006D
SubStatus:  0xC000006A
```

These values indicate that Windows successfully located the account but rejected the authentication because an incorrect password was supplied.

Later events showed Windows Security Event ID **4624**, confirming that authentication succeeded after valid credentials were provided.

The successful authentication retained the same characteristics:

- Authentication Package: NTLM
- Logon Type: Network (3)
- Same source workstation
- Same destination host

This sequence demonstrates the complete SMB authentication lifecycle from failed authentication to successful access.

---

# Analysis

The reconstructed authentication workflow is shown below.

```text
LAPTOP-HMLU2C6L
        │
        ▼
SMB Authentication Request
        │
        ▼
NTLM Authentication
        │
        ▼
Wrong Password
        │
        ▼
Security Event 4625
(Authentication Failed)
        │
Correct Password
        │
        ▼
Security Event 4624
(Authentication Successful)
```

The investigation demonstrates how Windows records both failed and successful network authentication attempts.

Event ID **4625** provides valuable information such as the source workstation, authentication package, failure reason, and status codes that help analysts determine why authentication failed.

Event ID **4624** confirms successful authentication and establishes that access was ultimately granted.

Monitoring repeated sequences of 4625 events followed by a 4624 event is important because this pattern may indicate password guessing, user error, or the early stages of a brute-force attack.

---

# Verdict

**Classification:** Benign (Lab Simulation)

**Confidence:** High

**Escalation Required:** No

---

# MITRE ATT&CK

| Technique | Description |
|------------|-------------|
| T1110 | Brute Force |
| T1021.002 | SMB / Windows Admin Shares |
| T1078 | Valid Accounts |

---

# Lessons Learned

- Investigated Windows Security Event IDs 4624 and 4625.
- Learned the meaning of Logon Type 3 (Network).
- Understood the NTLM authentication process.
- Learned the difference between Status and SubStatus values.
- Correlated failed authentication with later successful authentication.
- Identified the source workstation responsible for the authentication attempts.
