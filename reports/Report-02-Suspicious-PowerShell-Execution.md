**Alert Summary**
During routine monitoring of endpoint telemetry in the Splunk SIEM platform, a PowerShell execution event was detected on the Windows 10 host. The event originated from the Sysmon operational log and included command-line arguments suggesting potentially suspicious activity. Specifically, PowerShell was executed using command-line flags commonly associated with attacker techniques.

The activity was investigated to determine whether it represented normal administrative behavior or potential malicious execution.

Environment Component	Description
- SIEM	Splunk Enterprise
- Endpoint Monitoring	Sysmon
- Log Source	Microsoft-Windows-Sysmon/Operational
- Host	Windows-10
- Forwarder	Splunk Universal Forwarder
- Detection Type	Process Creation Monitoring
- Detection Method

The following Splunk query was used to detect PowerShell executions:

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*powershell.exe"
| table _time host User ParentImage CommandLine
| sort -_time

This query filters Sysmon Event ID 1 (Process Creation) events and isolates PowerShell executions.

Evidence Collected
Normal Process Creation Activity

Several standard applications were executed during testing to generate normal endpoint activity.

Examples include:

notepad.exe

calc.exe

powershell.exe

These events confirmed that Sysmon process creation logging was functioning correctly.

Suspicious PowerShell Command Execution

A PowerShell command was executed with flags often used in attacker scripts.

Command observed:

powershell -nop -c "Get-Process"

The command includes the -nop flag which disables PowerShell profiles. Attackers frequently use this parameter to avoid loading security monitoring scripts.

Splunk captured the event with the following details:

Field	Value
Host	Windows-10
Parent Process	explorer.exe
Image	powershell.exe
CommandLine	powershell -nop -c Get-Process
Encoded PowerShell Execution

An encoded PowerShell command was also executed to simulate attacker behavior.

Command executed on the endpoint:

powershell -EncodedCommand Z2V0LXByb2Nlc3M=

Encoded commands are commonly used to obfuscate malicious scripts and evade detection.

The following Splunk query was used to detect encoded commands:

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*powershell.exe"
(CommandLine="*-enc*" OR CommandLine="*EncodedCommand*")
| table _time host CommandLine ParentImage

The query successfully detected the encoded PowerShell execution.

Process Relationship Analysis

To understand the behavior of processes on the system, parent-child relationships were analyzed using the following query:

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| stats count by ParentImage Image
| sort -count

This analysis revealed common Windows process relationships including:

explorer.exe → powershell.exe

svchost.exe → rundll32.exe

services.exe → svchost.exe

These relationships are typically normal within Windows environments.

However, analysts often monitor unusual chains such as:

winword.exe → powershell.exe
excel.exe → cmd.exe

because they may indicate macro-based malware execution.

Timeline of Events
Time	Event
02:40:33	notepad.exe executed
02:40:44	calc.exe executed
02:40:55	powershell.exe executed
02:52:19	suspicious PowerShell command executed
02:55:56	encoded PowerShell command detected
Analysis

The PowerShell activity detected during this investigation was generated intentionally for laboratory testing purposes. The commands executed demonstrated how attackers may use PowerShell to run commands or obfuscate scripts using encoded payloads.

The encoded command detected in Splunk represents a typical technique used in real-world attacks. Monitoring PowerShell command-line arguments and encoded command usage is therefore an important detection strategy in Security Operations Centers.

Conclusion

The investigation determined that the PowerShell executions were part of controlled lab activity and do not represent malicious activity. However, the detection methods successfully identified behaviors that are commonly associated with attacker techniques.

This exercise demonstrates the effectiveness of Sysmon and Splunk in monitoring endpoint activity and detecting suspicious command execution.

Skills Demonstrated

SIEM log analysis using Splunk

Endpoint telemetry monitoring with Sysmon

PowerShell abuse detection

Command-line analysis

Process creation investigation

Parent-child process relationship analysis
