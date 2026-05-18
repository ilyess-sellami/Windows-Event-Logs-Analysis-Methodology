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