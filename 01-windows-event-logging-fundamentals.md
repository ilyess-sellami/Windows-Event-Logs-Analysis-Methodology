# Windows Event Logging Fundamentals

## Why Windows Event Logs Matter

During a DFIR investigation, Windows Event Logs are one of the most valuable evidence sources available on a system. Almost every important activity performed on a Windows machine can generate logs, including user authentication, process execution, service creation, scheduled tasks, PowerShell activity, network connections, and security policy changes.

For SOC analysts and incident responders, event logs help answer critical questions such as:

- Who logged into the system?
- Was the login successful or failed?
- Which process executed before the incident?
- Did malware create persistence?
- Was PowerShell used maliciously?
- Did the attacker clear the logs?

---

## Windows Event Logging Architecture

Windows stores logs inside structured log files managed by the Windows Event Log service.

| **Log Category** | **Purpose**                                                         |
| ---------------- | ------------------------------------------------------------------- |
| Security         | Authentication, privilege usage, account activity, process creation |
| System           | Drivers, services, system startup/shutdown                          |
| Application      | Application-generated events                                        |
| Setup            | Windows installation and update events                              |
| Forwarded Events | Logs collected from remote systems                                  |

These logs are usually viewed through:

- Event Viewer (``eventvwr.msc``)
- PowerShell
- ``wevtutil``
- SIEM platforms (Splunk, Sentinel, QRadar, ELK)

---

## Log Files Location

Windows event logs are stored as ``.evtx`` files in:

```bash
C:\Windows\System32\winevt\Logs\
```

Examples:

```bash
Security.evtx
System.evtx
Application.evtx
Microsoft-Windows-PowerShell%4Operational.evtx
Microsoft-Windows-Sysmon%4Operational.evtx
```

During evidence collection, investigators often acquire these ``.evtx`` files for offline analysis.

---

## Structure of a Windows Event

Each event contains multiple fields useful during investigations. Typical fields include :

| **Field** | **Description**                             |
| --------- | ------------------------------------------- |
| Timestamp | When the event occurred                     |
| Event ID  | Type of activity                            |
| Source    | Service or application generating the event |
| User      | Account associated with the activity        |
| Computer  | Hostname                                    |
| Level     | Information, Warning, Error                 |
| Message   | Detailed event description                  |

---

## Understanding Event IDs

Each Windows event contains an Event ID that identifies the type of activity that occurred. Examples:

| Event ID | Meaning                         |
| -------- | ------------------------------- |
| 4624     | Successful logon                |
| 4625     | Failed logon                    |
| 4688     | Process creation                |
| 7045     | New service installed           |
| 4104     | PowerShell script block logging |
| 1102     | Event logs cleared              |

Event IDs are extremely important in SOC operations because detections and alerts are usually built around them. For example:

- Multiple ``4625`` events from the same source may indicate brute-force activity.
- A ``7045`` event may indicate malware persistence through service installation.
- A ``1102`` event is often considered highly suspicious because attackers sometimes clear logs to hide evidence.