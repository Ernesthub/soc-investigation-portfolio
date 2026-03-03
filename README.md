# SOC Investigation Portfolio

## Author
Ernest Gyimah Adu - Cybersecurity Graduate Student  
Security+ | AWS Cloud Practictioner | Azure Administrator | ISC2 Certified in Cybersecurity (CC)  
6+ Years IT Support / System Administration Experience  

---

## Purpose of This Portfolio

This repository documents hands-on security investigations performed in a controlled lab environment designed to simulate real-world SOC operations.

Each report follows a structured incident response workflow:

> Alert → Triage → Evidence Collection → Timeline Reconstruction → Verdict → Containment Recommendations

The objective is to demonstrate practical detection and investigation capability, not just theoretical knowledge.

---

## Skills Demonstrated

- Windows Security Log Analysis (Event IDs 4624, 4625, etc.)
- Sysmon Telemetry Investigation
- Authentication Failure Correlation
- Process Execution Analysis
- Suspicious PowerShell Detection
- Malware Download Investigation
- Timeline Reconstruction
- False Positive Determination
- Incident Documentation Standards
- Cloud Log Analysis (AWS CloudTrail / Azure Logs)
- Basic SIEM Querying (Splunk / Wazuh)

---

## Lab Environment

This lab simulates a small enterprise environment:

- **Hypervisor:** VMware Workstation
- **Attacker Machine:** Kali Linux
- **Victim Endpoint:** Windows 10
- **SIEM:** Splunk Enterprise
- **Telemetry Sources:**
  - Windows Security Logs
  - Sysmon Logs
  - AWS CloudTrail Logs

All attack simulations were performed in an isolated lab environment.

---

## Investigation Reports

### Brute Force / Password Guessing Investigation
- Correlated Event ID 4625 (failures) with 4624 (success)
- Analyzed logon type and source IP
- Determined false positive due to manual password entry error

[View Report #1](./Report-01-Brute-Force-Investigation.md)

---

###Encoded PowerShell Execution Investigation
- Investigated suspicious `-enc` PowerShell execution
- Analyzed parent-child process relationships
- Identified potential defense evasion behavior

[View Report #2](./Report-02-Encoded-PowerShell.md)

---

### Suspicious File Download Investigation
- Detected file creation via Sysmon
- Correlated process responsible
- Evaluated potential malware execution risk

[View Report #3](./Report-03-Suspicious-Download.md)

---

### Cloud IAM Privilege Escalation Investigation
- Analyzed AWS CloudTrail logs
- Identified suspicious `AttachUserPolicy` activity
- Reconstructed escalation timeline

[View Report #4](./Report-04-Cloud-IAM-Escalation.md)

---

## Detection Philosophy

The focus of this portfolio is accuracy over alarmism.

Not every alert is malicious.

Effective SOC analysts must:
- Correlate events across log sources
- Understand context
- Avoid false positives
- Recommend proportionate response actions

Each report reflects that investigative mindset.

---

## Career Direction

Primary Focus:
Cloud Security & Threat Detection

Secondary Focus:
Security Operations (SOC Analyst I)

This portfolio represents foundational blue-team capability with emphasis on:

- Cloud log analysis
- Authentication anomaly detection
- Endpoint telemetry investigation

---

## Disclaimer

All investigations were performed in a personal lab environment for educational purposes only.  
No real-world systems or unauthorized environments were accessed.

---

## Contact

LinkedIn: [Insert Your LinkedIn URL]  
Email: [Insert Professional Email]

---
