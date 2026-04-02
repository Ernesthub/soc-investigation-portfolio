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

## Detection Queries
### Detect Registry Run Key Persistence

```index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13
TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*"
| table _time host TargetObject Details Image
| sort - _time
```

## Detect Startup Folder Persistence
```index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11
TargetFilename="*\\Startup\\evil.exe"
| table _time host Image TargetFilename
| sort - _time
```

## Detect Scheduled Task Creation
```index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*\\schtasks.exe"
| table _time host CommandLine
| sort - _time
```

## Detect Privilege Enumeration
```index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
CommandLine="*whoami.exe* /priv*"
| table _time host Image CommandLine
| sort - _time
```

## Evidence Collected
Registry Run Key Persistence

A Sysmon Event ID 13 event confirmed modification of the Run key:

Field	Value
Host	Windows-10
TargetObject	HKU...\Software\Microsoft\Windows\CurrentVersion\Run\Updater
Details	powershell.exe
Image	reg.exe

This confirms creation of a registry-based persistence mechanism.


## Startup Folder Persistence

A Sysmon Event ID 11 event confirmed a file creation within the user Startup folder:

Field	| Value
Host	| Windows-10
Image	| powershell.exe
TargetFilename |	C:\Users\Ernest\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe

This validates startup folder persistence.


## Scheduled Task Creation

A Sysmon Event ID 1 event captured scheduled task creation:

Field	| Value
Host	| Windows-10
CommandLine	| schtasks.exe /create /tn SplunkTestTask /tr C:\Windows\System32\notepad.exe /sc once /st 00:00 /f

This confirms persistence through scheduled task creation.


## Privilege Enumeration

A Sysmon Event ID 1 event captured privilege enumeration activity:

Field |	Value
Host	| Windows-10
Image	| whoami.exe
CommandLine |	whoami.exe /priv

This command is frequently used by attackers to inspect available privileges after compromise.


## Timeline of Events
Time	| Event
15:13:10	| Registry Run key persistence created
18:29:55	| Scheduled task created
19:15:35	| Startup folder persistence file created
Multiple times| 	Privilege enumeration via whoami /priv
Analysis

The investigation successfully detected multiple persistence mechanisms and privilege-related actions using Sysmon telemetry.

## Key Observations
- The Run key persistence event clearly showed reg.exe setting powershell.exe as the value for Updater
- Scheduled task creation was captured as command-line execution of schtasks.exe
- Startup folder persistence required refinement of the search query to isolate the exact file evil.exe
- Privilege enumeration using whoami /priv was reliably detected through Sysmon Event ID 1


## Detection Insight

Some broader searches returned legitimate system-generated activity, especially around startup-related PowerShell profile files. This highlighted an important SOC principle:

  Effective detection requires distinguishing between benign system artifacts and true persistence mechanisms.

Refining the query to target the exact test artifact (evil.exe) provided clean, high-confidence evidence.


## MITRE ATT&CK Mapping
Technique ID	| Technique Name
T1547.001	| Registry Run Keys / Startup Folder
T1053.005	| Scheduled Task
T1033	System | Owner/User Discovery
T1069	| Permission Groups Discovery


## Risk Assessment
- Activity	Risk Level	Reason
- Registry Run key	High	Auto-start persistence
- Startup folder file	High	User-logon execution
- Scheduled task	High	Repeatable execution path
- Privilege enumeration	Medium	Post-compromise recon


## Recommendations
- Monitor Run key changes under CurrentVersion\Run
- Alert on file creation in user Startup folders
- Monitor scheduled task creation, especially tasks executing PowerShell or uncommon binaries
- Baseline legitimate admin activity to reduce false positives
- Correlate persistence creation with subsequent network or PowerShell activity
- Enable additional PowerShell logging for stronger post-exploitation visibility


## Conclusion

This investigation demonstrated how common persistence and privilege-related behaviors can be detected using Sysmon and Splunk in a lab environment.

The simulated activities closely reflect post-exploitation techniques used by attackers to maintain access and prepare for further actions. The lab also reinforced the importance of refining searches to separate benign system activity from malicious persistence indicators.

This exercise strengthened practical SOC skills in:

- persistence detection
- privilege-related reconnaissance monitoring
- endpoint telemetry analysis
- investigation refinement
- SIEM-based threat hunting


## Skills Demonstrated
- SIEM log analysis using Splunk
- Sysmon-based endpoint monitoring
- Registry persistence detection
- Startup folder persistence detection
- Scheduled task abuse detection
- Privilege enumeration analysis
- SOC-style investigation and tuning
