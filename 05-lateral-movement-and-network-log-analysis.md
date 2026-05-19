# Lateral Movement and Network Log Analysis

## Why Lateral Movement Matters

After compromising an initial system, attackers often attempt to move across the network to access additional machines, escalate privileges, steal sensitive data, or reach critical infrastructure. This phase of the attack is known as lateral movement.

Lateral movement is one of the most important stages to detect because it usually indicates that the attacker already has valid access inside the environment.

Attackers commonly abuse legitimate Windows protocols and administrative tools to blend with normal network activity.

Common lateral movement techniques include:

- SMB
- RDP
- PsExec
- WMI
- WinRM
- Remote services
- PowerShell remoting

Windows Event Logs and network-related logs provide valuable visibility into these activities.

---

## SMB-Based Lateral Movement

Server Message Block (SMB) is commonly used for file sharing and remote administration in Windows environments. Attackers frequently abuse SMB to move between systems, copy payloads, and execute remote commands.

Important events associated with SMB activity include:

| Event ID | Description                |
| -------- | -------------------------- |
| 4624     | Successful logon           |
| 4625     | Failed logon               |
| 5140     | Shared object accessed     |
| 5145     | Detailed file share access |
| 4672     | Privileged logon           |

Investigators should focus on:

- **Logon Type 3** events
- Administrative share access (``ADMIN$``, ``C$``)
- Same account authenticating across multiple systems
- File transfers to remote hosts
- Access from unusual systems

---

## RDP Lateral Movement

Remote Desktop Protocol (RDP) provides attackers with interactive remote access to systems.

Attackers commonly use RDP after obtaining valid credentials through:

- Brute-force attacks
- Password spraying
- Credential dumping
- Phishing

Important events include:

| Event ID | Description          |
| -------- | -------------------- |
| 4624     | Successful logon     |
| 4625     | Failed logon         |
| 4778     | Session reconnected  |
| 4779     | Session disconnected |
| 4672     | Privileged logon     |

Investigators should analyze:

- **Logon Type 10** events
- External source IP addresses
- Unusual login times
- Rare administrator activity
- Multiple RDP logins across servers

---

## PsExec-Based Lateral Movement

PsExec is a legitimate administrative tool commonly abused by attackers for remote command execution.

PsExec activity often generates:

- SMB authentication events
- Remote service creation
- Process execution logs

Important indicators include:

| Event ID | Description       |
| -------- | ----------------- |
| 4624     | Network logon     |
| 7045     | Service installed |
| 4688     | Process creation  |

Investigators should look for:

- ``PSEXESVC`` service creation
- ``ADMIN$`` share access
- Remote CMD or PowerShell execution
- Same account authenticating across many systems

---

## WMI-Based Lateral Movement

Windows Management Instrumentation (WMI) allows remote system administration and is frequently abused for stealthy remote execution.

Attackers use WMI to:

- Execute remote commands
- Launch PowerShell payloads
- Deploy malware remotely

Important indicators may include:

- WMI Operational logs
- PowerShell execution
- Remote process creation
- Suspicious parent-child relationships

---

## WinRM and PowerShell Remoting

Windows Remote Management (WinRM) enables remote PowerShell execution and administrative access.

Attackers frequently abuse WinRM for:

- Remote command execution
- Fileless attacks
- Lateral movement

Suspicious indicators include:

- PowerShell remoting activity
- Encoded commands
- Remote PowerShell sessions
- Administrative access from workstations

---

## Correlating Lateral Movement Activity

Single events rarely prove lateral movement alone. Investigators should correlate:

- Authentication events
- Network connections
- Process creation logs
- Service installation events
- PowerShell activity
- Shared folder access

Example investigation timeline:

```text
4624 Logon Type 3
→ 5140 ADMIN$ share accessed
→ 7045 service installed
→ 4688 powershell.exe executed
→ Sysmon Event 3 outbound connection
```