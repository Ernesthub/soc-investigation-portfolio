**SOC Lab Architecture**

**Overview**
This lab simulates a small Security Operations Center (SOC) environment used to detect, investigate, and respond to security events. The architecture focuses on centralized log collection, endpoint telemetry, and security analytics using a SIEM platform.
The environment collects telemetry from a Windows endpoint and forwards the data to a centralized Splunk SIEM for analysis and detection engineering.
The goal of the lab is to practice real-world SOC workflows including:
- Log ingestion and normalization
- Threat detection using SIEM queries
- Security investigation and timeline analysis
- Attack simulation and detection validation

**Architecture Diagram**
                +----------------------+
                |      Kali Linux      |
                |   (Attack Simulation)|
                +----------+-----------+
                           |
                           |
                           v
                +----------------------+
                |      Windows 10      |
                |   (Target Endpoint)  |
                |                      |
                |  - Windows Security  |
                |  - Sysmon Telemetry  |
                +----------+-----------+
                           |
                           | Splunk Universal Forwarder
                           | Port 9997
                           v
                +----------------------+
                |      Ubuntu Server   |
                |     Splunk SIEM      |
                |                      |
                |  Log Ingestion       |
                |  Search & Analytics  |
                |  Detection Queries   |
                +----------------------+

**Virtual Machine Environment**
The lab is deployed using VMware Workstation with three virtual machines.
Machine	Role	OS	Resources
- Windows VM	Endpoint / Log Source	Windows 10	8GB RAM, 2 CPU, 60GB disk
- Ubuntu VM	Splunk SIEM Server	Ubuntu Server	8GB RAM, 2 CPU, 60GB disk
- Kali Linux	Attack Simulation	Kali Linux	4GB RAM, 2 CPU, 30GB disk

All virtual machines are connected through the same NAT network to allow communication between systems.

**Logging Pipeline**
The log collection architecture is based on a standard enterprise model.
- Endpoint logs are generated on the Windows system.
- Sysmon provides enhanced telemetry for process activity, network connections, and file events.
- Splunk Universal Forwarder collects logs locally.
- Logs are forwarded securely to the Splunk SIEM server.

Splunk indexes and makes the events searchable for investigations.

Windows Logs
     |
     |  Security + Sysmon
     v
Splunk Universal Forwarder
     |
     | TCP 9997
     v
Splunk Enterprise
     |
     v
Detection Queries & Investigations

**Log Sources**
The following telemetry sources are collected and analyzed:

**Windows Security Logs**
Important authentication events including:
- Event ID 4624 – Successful logon
- Event ID 4625 – Failed logon
- Account authentication activity

**Sysmon Telemetry**
Sysmon provides enhanced endpoint visibility including:
Event ID	Description
- 1	Process creation
- 3	Network connections
- 7	Image loaded
- 11	File creation
- 22	DNS queries
This telemetry allows deeper detection of suspicious behavior.

**Splunk Configuration**
The Splunk Enterprise server acts as the SIEM platform for the lab.

Key configuration components include:
- Log receiving port: 9997
- Web interface: port 8000
- Management port: 8089
The Windows endpoint uses Splunk Universal Forwarder to send telemetry to the SIEM.

**Detection Workflow**
- Security investigations follow a typical SOC workflow.
- Event logs are ingested into Splunk.
- Detection queries identify suspicious activity.
- Analysts analyze event context and telemetry.
- A timeline of activity is constructed.

**A final verdict is documented.**
Example investigations include:
- Brute-force authentication attempts
- Suspicious PowerShell execution
- Encoded PowerShell detection
- Suspicious outbound network connections
- File creation events
- Security Monitoring Capabilities

**The SOC lab supports detection of multiple attack behaviors including:**
- Password guessing attacks
- Suspicious command execution
- Malware execution indicators
- Unauthorized network activity
- Suspicious file downloads
- PowerShell abuse
These scenarios simulate common incidents handled by real SOC teams.

**Purpose of the Lab**
This environment is designed to develop hands-on experience with:
- SIEM deployment and configuration
- Log analysis and investigation
- Detection engineering
- SOC workflow simulation
- Incident documentation
The investigation reports contained in this repository demonstrate practical blue-team skills using real telemetry.
  

**Disclaimer**
All activities in this environment are conducted in an isolated virtual lab for educational purposes only. No external systems or networks are targeted.
