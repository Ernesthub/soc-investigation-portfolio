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
