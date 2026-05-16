# Authentication and Logon Analysis

## Why Authentication Logs Matter

Authentication events are among **the most important logs** during SOC monitoring and DFIR investigations. Attackers almost always interact with authentication mechanisms at some stage of the attack, whether through brute-force attempts, stolen credentials, lateral movement, remote access, or privilege escalation.

By analyzing logon events, investigators can identify:

- Unauthorized access attempts
- Suspicious remote logins
- Brute-force activity
- Lateral movement between systems
- Abuse of privileged accounts

Authentication analysis is often the starting point for reconstructing the attacker’s initial access and movement inside the environment.

---

## Main Authentication Event IDs

Most authentication-related events are found inside **Windows Logs → Security**

<img src="docs/windows-security-event-logs.png" alt="Windows Security Event Logs" />

The following Event IDs are commonly analyzed during investigations:

| Event ID | Description                              |
| -------- | ---------------------------------------- |
| 4624     | Successful logon                         |
| 4625     | Failed logon                             |
| 4634     | Logoff                                   |
| 4647     | User initiated logoff                    |
| 4648     | Logon using explicit credentials         |
| 4672     | Special privileges assigned to new logon |
| 4768     | Kerberos authentication ticket requested |
| 4769     | Kerberos service ticket requested        |
| 4771     | Kerberos pre-authentication failed       |
| 4776     | NTLM authentication attempt              |

---

## Event ID 4624 — Successful Logon

This event indicates that a user successfully authenticated to the system.

Important fields:

| Field                  | Description              |
| ---------------------- | ------------------------ |
| Account Name           | Username involved        |
| Logon Type             | Type of access           |
| Source Network Address | Remote IP address        |
| Workstation Name       | Source machine           |
| Logon Process          | Authentication mechanism |

---

## Event ID 4625 — Failed Logon

This event records failed authentication attempts.

Important fields:

| Field                  | Description               |
| ---------------------- | ------------------------- |
| Account Name           | Target username           |
| Failure Reason         | Why authentication failed |
| Source Network Address | Attacker IP               |
| Status/Substatus       | Technical failure code    |

This event is very important for detecting:

- Brute-force attacks
- Password spraying
- Invalid account usage
- Enumeration attempts

---

## Event ID 4672 — Privileged Logon

Generated when a user logs in with administrative privileges.

Privileges may include:

- ``SeDebugPrivilege``
- ``SeBackupPrivilege``
- ``SeTakeOwnershipPrivilege``

Important investigation questions:

- Should this user normally have admin privileges?
- Is the login source expected?
- Did suspicious processes execute after the session started?

Example correlation:

- ``4672`` : A privileged session was established with administrative rights.
- ``4688`` : A new ``cmd.exe`` process was created containing suspicious activity.
- ``7045`` : A suspicious service was installed on the system.

---

## Understanding Logon Types

Logon Type is extremely important because it explains how access occurred.

| Logon Type | Meaning                             |
| ---------- | ----------------------------------- |
| 2          | Interactive local logon             |
| 3          | Network logon (SMB, shared folders) |
| 4          | Batch logon                         |
| 5          | Service logon                       |
| 7          | Unlock workstation                  |
| 8          | NetworkCleartext                    |
| 9          | NewCredentials                      |
| 10         | RemoteInteractive (RDP)             |
| 11         | CachedInteractive                   |

- **Logon Type 2 — Interactive Logon :** This logon type is generated when a user logs directly into the machine using the keyboard and screen physically attached to the system.
- **Logon Type 3 — Network Logon :** This is one of the most important logon types in DFIR investigations, it's generated during network-based authentication such as SMB access, Shared folder access, PsExec usage and Remote administrative activity
- **Logon Type 4 — Batch Logon :** Generated when scheduled tasks or batch jobs execute under a user account. Investigators should verify whether the task is legitimate because attackers sometimes abuse scheduled tasks for persistence.
- **Logon Type 5 — Service Logon :** This event occurs when a service starts under a specific account, attackers often abuse services to maintain persistence after compromise.
- **Logon Type 7 — Unlock Workstation :** Generated when a user unlocks an already logged-in workstation. Usually considered normal user activity, but timestamps can still help investigators understand user presence during an incident timeline.
- **Logon Type 8 — NetworkCleartext :** Occurs when credentials are sent in cleartext form to the authentication package. This does not always mean the password traveled unencrypted over the network, but it may still indicate insecure authentication methods.
- **Logon Type 9 — NewCredentials :** Generated when a user runs a process using alternate credentials while keeping the current local identity.
- **Logon Type 10 — RemoteInteractive (RDP) :** This logon type indicates Remote Desktop Protocol (RDP) access. RDP is heavily targeted by attackers because it provides direct interactive access to systems.

---

## Kerberos Authentication Events

In Active Directory environments, Kerberos events become very important.

- Event ID : **4768 → Kerberos Ticket Granting Ticket (TGT) requested.**
- Event ID : **4769 → Kerberos service ticket requested.**
- Event ID : **4771 → Kerberos pre-authentication failed.**

These logs help detect:

- Kerberoasting
- Password attacks
- Suspicious ticket requests
- Lateral movement

Example indicator:
- Large number of ``4769`` requests targeting service accounts.

---

## Detecting Brute Force Activity 

A brute-force attack is a technique where an attacker repeatedly tries multiple passwords against a user account until the correct password is found

Common brute-force indicators:

- Large number of ``4625`` events
- Same source IP targeting many accounts
- Repeated failures against a single account
- Successful ``4624`` immediately after failures

For example:

```text
50x Event ID ``4625`` from ``192.168.1.50`` followed by Event ID ``4624`` **→ Possible successful brute-force compromise**
```

SOC analysts should correlate timestamps, usernames, and source IP addresses to identify attack patterns.

---

## Detecting Password Spraying Activity

Password spraying is different from traditional brute-force attacks. Instead of trying many passwords against a single account, attackers attempt to use one common password against many different usernames.

Common indicators of password spraying include:

- Authentication attempts targeting many different usernames
- Same source IP address involved in multiple failures
- Small number of attempts per account
- Similar timestamps between events
- Repeated Event ID ``4625`` entries across multiple users

For example: 

```text
Instead of attacking one account repeatedly: admin → 50 passwords

Attackers may attempt: 50 usernames → Password123

```

---

## Detecting Lateral Movement

Lateral movement occurs when an attacker moves from one system to another after gaining initial access to the environment. Instead of staying on a single compromised machine, attackers use legitimate authentication protocols and administrative tools to access additional hosts, escalate privileges, and reach sensitive systems.

Common attacker techniques include:

- SMB access
- Remote Desktop Protocol (RDP)
- PsExec
- WMI
- WinRM
- Remote service creation

Suspicious indicators may include:

- Same account authenticating to multiple hosts in a short period
- Logon Type 3 events across several systems
- Logon Type 10 (RDP) access to sensitive servers
- Administrative accounts authenticating outside normal working hours
- Explicit credential usage events (4648)
- Privileged logons (4672) appearing after remote access

Example investigation scenario:

```text
4624 Logon Type 3 detected on SERVER-01
→ Same account authenticates to SERVER-02
→ 4648 explicit credentials used
→ 4672 privileged session created
→ 4688 PowerShell execution detected
```
