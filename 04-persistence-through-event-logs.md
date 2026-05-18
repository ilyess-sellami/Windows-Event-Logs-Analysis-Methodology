# Persistence Through Event Logs

## Why Persistence Matter

After gaining initial access to a system, attackers often try to maintain long-term access even after reboots, user logoffs, or security investigations. This technique is known as persistence.

Persistence mechanisms allow attackers to:

- Reconnect to compromised systems later
- Survive system restarts & maintain remote access
- Re-execute malware automatically

Windows Event Logs are extremely valuable for identifying persistence activity because many persistence techniques generate authentication, process creation, registry, service, or scheduled task events.

---

## Common Persistence Techniques

Attackers commonly abuse:

- Scheduled Tasks
- Windows Services
- Registry Run Keys
- Startup Folders
- WMI Event Subscriptions
- PowerShell Profiles
- DLL Hijacking

---

## Scheduled Task Persistence

Scheduled Tasks are one of the most commonly abused persistence mechanisms in Windows environments. Attackers use them to automatically execute malware, scripts, or remote access tools at specific times, during user logon, or after system startup.

One of the main events used for detecting this technique inludes:

| Event ID | Description                              |
| -------- | ---------------------------------------- |
| 4698     | A scheduled task was created             |
| 4699     | A scheduled task was deleted             |
| 4700     | A scheduled task was enabled             |
| 4701     | A scheduled task was disabled            |
| 4702     | A scheduled task was updated or modified |

Investigators should analyze:

- Task name & user account that created the task
- Command executed by the task
- Creation timestamp
- Parent process responsible for task creation

Common suspicious indicators include:

- PowerShell or CMD execution
- Tasks executing from Temp, AppData, or Public folders
- Random or misleading task names
- Tasks created shortly after suspicious logins

Example suspicious command:

```powershell
powershell.exe -ExecutionPolicy Bypass -File updater.ps1
```

---

## Windows Service Persistence

Attackers frequently install malicious Windows services to maintain persistence because services can automatically start when the operating system boots. This technique is widely used by malware families, ransomware operators, and remote access trojans.

The main events associated with service-based persistence and service management are:

| Event ID | Description                                                   |
| -------- | ------------------------------------------------------------- |
| 7045     | A new service was installed                                   |
| 7036     | A service changed state (started or stopped)                  |
| 7040     | Service startup type was changed                              |
| 7035     | A service control request was sent                            |
| 4697     | A service was installed on the system                         |
| 4657     | Registry service configuration modified (if auditing enabled) |

Investigators should verify:

- Service name & executable path
- Startup type
- User account involved
- Parent process that installed the service

Suspicious indicators may include:

- Executables inside writable directories
- Unknown service names
- Unsigned binaries
- Services created by scripting engines or command interpreters

Example suspicious path:

```bash
C:\Users\Public\svchost.exe
```

---

## Registry Run Key Persistence

Registry Run Keys are commonly abused to automatically execute malware when users log into Windows. Attackers modify registry autorun locations to ensure their payloads execute every time the system starts or the user authenticates.

Common registry locations include:

```bash
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

Registry auditing may generate several useful events related to persistence and registry modifications:

| Event ID | Description                           |
| -------- | ------------------------------------- |
| 4657     | Registry value modified               |
| 4663     | Attempt to access a registry object   |
| 4656     | Handle to a registry object requested |
| 4658     | Handle to a registry object closed    |

Investigators should look for:

- Executables inside ``AppData`` or ``Temp``
- PowerShell commands stored in Run keys
- Random value names
- Newly created autorun entries

Example suspicious registry value:

```bash
Updater = C:\Users\John\AppData\Roaming\payload.exe
```

---

## Startup Folder Persistence

Windows Startup folders automatically execute files when users log into the system. Attackers abuse these folders to launch malware, scripts, or malicious shortcuts during startup.

Common Startup folder location:

```bash
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
```

Attackers may place:

- Executables
- Batch scripts
- PowerShell launchers
- Malicious ``.lnk`` shortcut files

Detection methodology includes analyzing:

- File creation activity
- Process execution events (``4688``)
- Suspicious shortcut targets
- Recently modified Startup folder files

---

## WMI Event Subscription Persistence

Windows Startup folders automatically execute files when users log into the system. Attackers abuse these folders to launch malware, scripts, or malicious shortcuts during startup.

Common Startup folder location:

```bash
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
```

Attackers may place:

- Executables
- Batch scripts
- PowerShell launchers
- Malicious ``.lnk`` shortcut files

Detection methodology includes analyzing:

- File creation activity
- Process execution events (``4688``)
- Suspicious shortcut targets
- Recently modified Startup folder files

---

## WMI Event Subscription Persistence

Windows Management Instrumentation (WMI) can be abused to create stealthy persistence mechanisms that automatically execute malicious code when specific system events occur. Advanced attackers prefer WMI because it is difficult to detect and often bypasses traditional startup monitoring.

Common WMI persistence components include:

- Event Filters
- Event Consumers
- Filter-to-Consumer Bindings

Suspicious activity may generate:

- PowerShell execution logs
- WMI operational logs
- Process creation events (``4688``)

Investigators should look for:

- Unknown WMI consumers
- PowerShell spawned through WMI
- Event-triggered script execution
- Suspicious persistence without obvious startup entries

---

## PowerShell-Based Persistence

Attackers commonly use PowerShell for persistence because it is built into Windows and provides powerful automation capabilities. Malicious PowerShell persistence can execute scripts silently during startup or user authentication.

Common techniques include:

- PowerShell profiles
- Encoded startup commands
- Scheduled PowerShell execution
- Registry-based PowerShell launchers

Important events include:

| Event ID | Description                     |
| -------- | ------------------------------- |
| 4104     | PowerShell script block logging |
| 4688     | Process creation                |

Suspicious indicators may include:

- ExecutionPolicy Bypass
- Encoded commands
- Base64 strings
- Hidden PowerShell windows
- PowerShell execution during startup

Example suspicious command:

```powershell
powershell.exe -enc SQBFAFgA(...)
```

---

## DLL Hijacking Persistence

DLL hijacking occurs when attackers place malicious DLL files in locations where legitimate applications will automatically load them. This allows malicious code to execute whenever the targeted application starts.

Attackers abuse this technique because:

- DLL loading is normal Windows behavior
- Malicious DLLs may appear legitimate
- Execution occurs indirectly through trusted applications

Detection methodology includes analyzing:

- Process creation events (4688)
- Sysmon image load events
- Unusual DLL paths
- Applications loading DLLs from writable directories

Suspicious indicators:

- DLLs inside ``Temp`` or user directories
- Legitimate applications loading unknown modules
- Recently dropped DLL files before malware execution