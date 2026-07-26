# Investigation ID: INV-0005

# Title

PowerShell Web Request and File Download Investigation

# Date

2026-07-26

# Lab Environment

- SIEM: Elastic Security
- Endpoint: Windows 10 Pro
- Log Sources:
  - Sysmon Operational
  - Windows PowerShell Operational
- Host: DESKTOP-0DFKSAT

---

# Objective

Investigate a PowerShell session that downloaded web content using the **Invoke-WebRequest** cmdlet, verify the associated network connection and downloaded file, and determine whether the activity is legitimate or suspicious.

---

# Summary

User **gamal** launched **powershell.exe** interactively from **explorer.exe**.

During the session, PowerShell executed the **Invoke-WebRequest** cmdlet to download content from:

- https://example.com/

The downloaded content was saved locally as:

- **example.html**

inside the **SOCLab** directory.

Sysmon Event ID 3 confirmed the outbound HTTPS connection, while Sysmon Event ID 11 confirmed successful file creation.

Threat Intelligence analysis using VirusTotal confirmed that both the destination URL and IP address were clean.

No indicators of malicious behavior were identified.

---

# Evidence

| Field | Value |
|-------|-------|
| User | gamal |
| Host | DESKTOP-0DFKSAT |
| Host IP | 192.168.1.75 |
| Process | powershell.exe |
| Parent Process | explorer.exe |
| Process ID | 7960 |
| Parent PID | 3004 |
| Executable | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| PowerShell Command | Invoke-WebRequest |
| URL | https://example.com/ |
| Destination IP | 104.20.23.154 |
| Destination Port | 443 |
| Protocol | TCP |
| Downloaded File | example.html |
| File Path | C:\Users\gamal\Desktop\SOCLab\example.html |
| Sysmon Events | Event ID 1, Event ID 3, Event ID 11 |
| PowerShell Log | Windows PowerShell Operational |
| Threat Intelligence | VirusTotal (0 detections) |

---

# KQL Queries Used

### Find PowerShell Process Creation

```kql
event.dataset:"windows.sysmon_operational"
and event.code:"1"
and process.pid:7960
```

### Find Network Connection

```kql
event.dataset:"windows.sysmon_operational"
and event.code:"3"
and process.pid:7960
```

### Find File Creation Events

```kql
event.dataset:"windows.sysmon_operational"
and event.code:"11"
and process.pid:7960
```

### Review PowerShell Operational Logs

```kql
event.dataset:"windows.powershell_operational"
and winlog.process.pid:7960
```

---

# Timeline

| Time | Activity |
|------|----------|
| 2026-07-26 08:57:41 | PowerShell process created |
| 2026-07-26 08:58:24 | HTTPS connection established to 104.20.23.154:443 |
| 2026-07-26 08:58:25 | Invoke-WebRequest downloaded content from https://example.com/ |
| 2026-07-26 08:58:24 | Sysmon Event ID 11 confirmed creation of example.html |
| 2026-07-26 08:59 | VirusTotal verified the URL and IP as clean |

---

# Investigation

The investigation began by identifying a PowerShell process using Sysmon Event ID 1.

The parent process was **explorer.exe**, indicating that the PowerShell session was launched interactively by the logged-in user.

Using the PowerShell Process ID (**7960**), the investigation pivoted to Windows PowerShell Operational logs.

PowerShell Script Block Logging recorded execution of the following cmdlet:

- Invoke-WebRequest

The recorded command downloaded content from:

```
https://example.com/
```

and saved the response to:

```
C:\Users\gamal\Desktop\SOCLab\example.html
```

Sysmon Event ID 3 confirmed that the same PowerShell process initiated an outbound HTTPS connection to:

```
104.20.23.154:443
```

Sysmon Event ID 11 confirmed that **example.html** was successfully created in the **SOCLab** directory.

The destination URL and IP address were investigated using VirusTotal. Both returned **0 detections**, indicating that neither the website nor the IP address is currently associated with known malicious activity.

No encoded commands, obfuscated scripts, privilege escalation, persistence mechanisms, or suspicious child processes were observed during the investigation.

---

# Analysis

The observed activity is consistent with normal PowerShell usage.

Correlation between Sysmon Process Creation, Network Connection, File Creation, and Windows PowerShell Operational logs confirmed the complete execution flow from process launch to network communication and file download.

The downloaded content originated from **https://example.com/**, a legitimate testing website, and Threat Intelligence analysis verified that both the destination URL and IP address were clean.

No evidence of persistence, privilege escalation, defense evasion, lateral movement, or malicious execution was identified.

---

# Verdict

**Classification:** Benign

**Confidence:** High

**Escalation Required:** No

---

# Lessons Learned

- Investigated PowerShell web download activity using multiple telemetry sources.
- Correlated Sysmon Event ID 1, Event ID 3, and Event ID 11.
- Used Process ID to pivot across multiple log sources.
- Verified PowerShell Script Block Logging.
- Confirmed outbound HTTPS communication initiated by PowerShell.
- Verified downloaded resources using VirusTotal.
- Practiced correlating process, network, and file events to reconstruct the complete attack timeline.
- Improved KQL filtering, event correlation, and IOC verification workflow.
