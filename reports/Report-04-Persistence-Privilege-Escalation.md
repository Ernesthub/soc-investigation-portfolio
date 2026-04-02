# Report-04: Persistence Mechanisms & Privilege Escalation Detection

## Overview

This investigation focused on detecting persistence mechanisms and post-exploitation privilege-related activity on a Windows 10 endpoint using Sysmon telemetry and Splunk Enterprise.

Attackers commonly establish persistence after gaining initial access so they can survive reboots, maintain execution, and prepare for later stages such as privilege escalation or lateral movement. This lab simulated several persistence techniques and privilege enumeration behaviors to validate detection logic in a SOC environment.

The investigation covered the following techniques:

- Registry Run Key persistence
- Startup folder persistence
- Scheduled task creation
- Privilege enumeration activity

---

## Lab Environment

| Component | Description |
|---|---|
| SIEM Platform | Splunk Enterprise |
| Endpoint Monitoring | Sysmon |
| Endpoint System | Windows 10 |
| Log Forwarding | Splunk Universal Forwarder |
| Virtualization | VMware Workstation |
| Log Source | Microsoft-Windows-Sysmon/Operational |

---

## Detection Strategy

This investigation used multiple Sysmon events to monitor post-exploitation behavior:

| Sysmon Event ID | Description |
|---|---|
| 1 | Process Creation |
| 11 | File Creation |
| 13 | Registry Value Set |

These events allowed detection of persistence and privilege-related activity from different behavioral angles.

---

## Simulated Activities

### 1. Registry Run Key Persistence

A registry value was added under the Windows Run key to simulate persistence.

```powershell
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "powershell.exe"
```

This causes PowerShell to launch automatically when the user logs in.

## 2. Startup Folder Persistence

A test executable was copied into the user Startup folder to simulate startup-based persistence.

```copy C:\Windows\System32\notepad.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe"```

Files in this folder execute automatically when the user logs in.



## 3. Scheduled Task Persistence

A scheduled task was created to repeatedly execute an application.

```schtasks /create /tn SplunkTestTask /tr C:\Windows\System32\notepad.exe /sc once /st 00:00 /f```

This simulates attacker use of scheduled tasks to re-establish execution.



## 4. Privilege Enumeration

Privilege-related reconnaissance was simulated using:

```whoami /priv```

This command is commonly used by attackers to determine current privileges and identify escalation opportunities.
