# Report-03: Suspicious Network Connections & C2 Detection

## Overview

This investigation focused on detecting suspicious outbound network connections and identifying potential command-and-control (C2) behavior using Sysmon telemetry and Splunk Enterprise.

Attackers often establish outbound connections to external or internal systems to receive commands, exfiltrate data, or maintain remote access. Monitoring these connections is critical in identifying compromised endpoints.

This lab simulated PowerShell-based network activity to validate detection techniques for abnormal connections.

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

This investigation focused on Sysmon Event ID 3:

| Sysmon Event ID | Description |
|---|---|
| 3 | Network Connection |

This event captures outbound network connections, including:

- Source IP
- Destination IP
- Destination Port
- Process responsible for the connection

---

## Simulated Activity

### PowerShell Network Connection Attempt

A PowerShell command was executed to simulate outbound communication:

```powershell
powershell -Command "Test-NetConnection 192.168.192.129 -Port 4444"

This was used to simulate communication with a potential attacker-controlled system.

Reverse Shell Simulation

A connection attempt was made to a listener running on a Kali Linux system:

nc -lvnp 4444

On the Windows endpoint, a connection attempt was initiated toward the listener.

This mimics how attackers establish reverse shells for remote control.

Detection Queries
Detect PowerShell Network Connections
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3
Image="*\\powershell.exe"
| table _time host Image DestinationIp DestinationPort
| sort - _time
Detect Suspicious Outbound Connections
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3
| table _time host Image DestinationIp DestinationPort
| sort - _time
Detect Non-Internal Connections
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3
| where NOT cidrmatch("192.168.0.0/16", DestinationIp)
| table _time host Image DestinationIp DestinationPort
| sort - _time
Evidence Collected
PowerShell Network Activity

Sysmon Event ID 3 captured outbound connections initiated by PowerShell:

Field	Value
Host	Windows-10
Image	powershell.exe
Destination IP	192.168.192.129
Destination Port	4444

This indicates attempted communication with a remote host.

External Network Connections

Additional outbound connections were observed:

Destination IP	Port
64.233.180.101	80
104.18.27.120	80

These represent normal web traffic but demonstrate visibility into outbound connections.

Reverse Shell Connection

A successful connection was observed from the Windows endpoint to the Kali system:

Source: Windows 10 endpoint
Destination: Kali Linux listener
Port: 4444

This confirms simulated attacker communication behavior.

Timeline of Events
Time	Event
03:33:42	PowerShell initiated outbound connection
03:42:43	Additional outbound connections observed
04:12:36	Connection attempt to port 4444 detected
04:31:44	Multiple outbound connections recorded
Analysis

The investigation successfully demonstrated how Sysmon Event ID 3 can be used to detect suspicious outbound network activity.

Key Observations
PowerShell was used to initiate outbound connections, which is a common attacker technique
Connections to internal lab IPs on uncommon ports (4444) indicate potential reverse shell behavior
External connections to known IP ranges were also observed, representing normal traffic
Differentiating between benign and suspicious traffic is critical in SOC analysis
Detection Insight

Outbound connections to non-standard ports (such as 4444) are strong indicators of potential malicious activity, especially when initiated by scripting engines like PowerShell.

Filtering internal vs external traffic improves visibility into potential threats.

MITRE ATT&CK Mapping
Technique ID	Technique Name
T1046	Network Service Discovery
T1071	Application Layer Protocol
T1105	Ingress Tool Transfer
T1095	Non-Application Layer Protocol
Risk Assessment
Activity	Risk Level	Reason
PowerShell outbound connection	High	Common attacker technique
Connection to port 4444	High	Non-standard port often used for reverse shells
External HTTP traffic	Low	Likely legitimate
Recommendations
Monitor outbound connections from scripting engines (PowerShell, cmd)
Alert on connections to uncommon ports (e.g., 4444, 1337, 8081)
Implement network segmentation to limit outbound communication
Correlate network activity with process creation events
Establish baseline traffic patterns for endpoints
Enable alerting for repeated connection attempts to a single IP
Conclusion

This investigation demonstrated how suspicious network activity can be detected using Sysmon and Splunk.

The simulated attack behavior closely mirrors real-world command-and-control communication patterns. The lab also emphasized the importance of distinguishing between legitimate traffic and suspicious connections based on context.

This phase strengthened practical SOC skills in:

network traffic analysis
SIEM-based detection
PowerShell activity monitoring
threat hunting
identifying command-and-control behavior
Skills Demonstrated
SIEM log analysis using Splunk
Network connection monitoring
Sysmon Event ID 3 analysis
Detection of suspicious outbound traffic
Threat hunting and investigation
SOC-style analysis and reporting
