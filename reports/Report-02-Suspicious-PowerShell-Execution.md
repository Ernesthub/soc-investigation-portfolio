**Overview**

This investigation analyzes suspicious PowerShell activity detected through Sysmon logs and monitored using Splunk Enterprise SIEM. The goal of the investigation was to identify potentially malicious command execution and analyze process behavior on the monitored Windows endpoint.

PowerShell is frequently used by attackers because it allows command execution, scripting, and system interaction while often blending in with legitimate administrative activity. Monitoring PowerShell activity is therefore an important detection capability in Security Operations Centers (SOC).

**Lab Environment**

    **Component	              Description**
    SIEM Platform	            Splunk Enterprise
    Endpoint Monitoring	      Sysmon
    Endpoint System	          Windows 10
    Log Forwarding	          Splunk Universal Forwarder
    Virtualization	          VMware Workstation
    Log Source	              Microsoft-Windows-Sysmon/Operational

**Detection Strategy**

Sysmon Event ID 1 (Process Creation) was monitored to identify command execution activity on the endpoint.
The following Splunk query was used to identify PowerShell executions.

    **index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    Image="*powershell.exe"
    | table _time host User ParentImage CommandLine
    | sort -_time**

This query filters process creation events and isolates PowerShell execution activity.

**Evidence Collection**

  **Normal Endpoint Activity**
    
To generate baseline activity, several normal applications were opened on the Windows endpoint including:
- Notepad
- Calculator
- PowerShell
These actions generated Sysmon Event ID 1 events confirming that process creation logging was functioning correctly.
Example processes observed:

      **Process	      Parent Process**
  
      notepad.exe	    explorer.exe
      calc.exe	      explorer.exe
      powershell.exe	explorer.exe

**Suspicious PowerShell Execution**

A PowerShell command was executed using parameters commonly associated with attacker techniques.

    **_powershell -nop -c "Get-Process"_**

Explanation of Flags

    **Flag	  Description**
    
    -nop	    Disables PowerShell profiles
    -c	      Executes a command

Attackers often disable PowerShell profiles to bypass security scripts that may be loaded during normal PowerShell initialization.

Splunk captured the following information:

    **Field	        Value**
    
    Host	          Windows-10
    User	          Windows-10\Ernest
    Parent Process	explorer.exe
    Process	        powershell.exe
    Command Line	  powershell -nop -c Get-Process

**Encoded PowerShell Execution**

To simulate a common attacker technique, an encoded PowerShell command was executed.

    **_owershell -EncodedCommand Z2V0LXByb2Nlc3M=_**
    
Encoded PowerShell commands are frequently used by attackers to obfuscate malicious scripts and bypass detection systems.

The following Splunk detection query was used.

    **index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=1 Image="*powershell.exe"
    (CommandLine="*-enc*" OR CommandLine="*EncodedCommand*")
    | table _time host CommandLine ParentImage**

The encoded command execution was successfully detected within Splunk.

**Process Relationship Analysis**

Parent-child process relationships were analyzed to understand how processes were spawned on the system.

The following query was used.

    _index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=1
    | stats count by ParentImage Image
    | sort -count_

Common process relationships observed included:

    **Parent Process	   Child Process**
    
    explorer.exe	       powershell.exe
    svchost.exe	         rundll32.exe
    services.exe	       svchost.exe

While these relationships are typical in Windows environments, security analysts monitor for suspicious chains such as:

_winword.exe → powershell.exe
excel.exe → cmd.exe_

These patterns can indicate macro-based malware execution.

**Timeline of Events**

    Time	    Event
    
    02:40:33	notepad.exe executed
    02:40:44	calc.exe executed
    02:40:55	powershell.exe executed
    02:52:19	PowerShell command executed using -nop flag
    02:55:56	Encoded PowerShell command detected

**Analysis**

The detected PowerShell commands were generated intentionally during lab testing to simulate attacker behavior.
The investigation demonstrates how PowerShell execution and encoded commands can be identified through endpoint telemetry using Sysmon logs. Security analysts frequently monitor these events because PowerShell is commonly abused during post-exploitation stages of cyber attacks.

By monitoring command-line arguments and parent process relationships, analysts can identify suspicious behavior and investigate potential compromise.

**Conclusion**

The investigation determined that the PowerShell activity was part of controlled testing within the lab environment and did not represent malicious activity.
However, the detection methods used in this investigation successfully identified behaviors commonly associated with attacker techniques. This demonstrates the effectiveness of combining Sysmon endpoint monitoring with Splunk SIEM analysis.

**Skills Demonstrated**

  - SIEM log analysis using Splunk
  - Endpoint telemetry monitoring using Sysmon
  - PowerShell threat detection
  - Command-line investigation
  - Process creation analysis
  - Parent-child process relationship analysis
