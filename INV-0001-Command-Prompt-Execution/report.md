# Investigation ID: INV-0001

## Title
Command Prompt Execution

## Date
2026-07-22

---

# Summary

User **gamal** on **DESKTOP-0DFKSAT** launched `cmd.exe` from `explorer.exe`. The process executed the expected child processes (`whoami.exe` and `hostname.exe`) before terminating. No suspicious behavior or malicious indicators were identified during this investigation.

---

# Lab Environment

- SIEM: Elastic Security
- Endpoint: Windows 10
- Log Source: Sysmon
- Dataset: `windows.sysmon_operational`

---

# Objective

Determine whether the observed Command Prompt activity is benign or suspicious.

---

# Evidence

| Field | Value |
|-------|-------|
| User | gamal |
| Host | DESKTOP-0DFKSAT |
| Process | cmd.exe |
| Parent Process | explorer.exe |
| Process ID (PID) | 3532 |
| Parent PID | 4860 |
| Executable | C:\Windows\System32\cmd.exe |
| Command Line | *Not captured / Not documented* |
| Dataset | windows.sysmon_operational |
| Event ID | 1 |

---

# Timeline

| Time | Activity |
|------|----------|
| 2026-07-22 04:38:18.368 | Explorer.exe started cmd.exe |
| 2026-07-22 04:38:24.861 | cmd.exe launched whoami.exe |
| 2026-07-22 04:38:41.759 | cmd.exe launched hostname.exe |

---

# Investigation

### Initial Findings

The investigation began by identifying the creation of `cmd.exe` (Sysmon Event ID 1).

The parent process was `explorer.exe`, indicating that the Command Prompt was launched interactively by the logged-in user.

A pivot using the parent process ID revealed that `cmd.exe` spawned two child processes:

- whoami.exe
- hostname.exe

Both are legitimate Windows utilities commonly used to retrieve system and user information.

---

# Analysis

The parent-child relationship is consistent with normal interactive user activity.

No suspicious command-line arguments were observed during this investigation.

The executed child processes (`whoami.exe` and `hostname.exe`) are legitimate Windows binaries and are commonly used for administrative or troubleshooting purposes.

No evidence of persistence, privilege escalation, or suspicious behavior was observed during the scope of this investigation.

---

# Verdict

**Classification:** Benign

**Confidence:** High

**Escalation Required:** No

---

# Recommendations

- No further action is required.
- Close the investigation.
- Continue monitoring for unusual child processes spawned from `cmd.exe`.
