# SOC-ALERT-02: Possible Encoded PowerShell Execution

## 1. Alert Information

- **Alert ID:** SOC-ALERT-02
- **Alert Name:** Possible Encoded PowerShell Execution
- **Category:** Endpoint Security 
- **Severity:** Medium 
- **Status:** Investigated
- **Affected Asset:** Windows Endpoint
- **Log Source:** Windows Sysmon
- **ndex** Main
- **Sourcetype** sysmon_xml_upload
- **Dataset:** windows-sysmon.log
- **Sysmon Event ID:** 1 – Process Creation
- **MITRE ATT&CK:** T1059.001 – PowerShell

## 2. Alert Description

This alert identifies PowerShell process executions involving encoded command arguments and execution policy bypass.

Encoded PowerShell commands can be used for legitimate administrative tasks, but they can also be used to conceal commands during suspicious or malicious activity.

The alert is intended to identify these executions for further investigation. The presence of encoded commands does not automatically indicate malicious activity.

## 3.Detection Query

SPL Query:
index=main source="windows-sysmon.log" sourcetype="sysmon_xml_upload"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "Name='Image'>(?<Image>[^<]*)</Data>"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "Name='ProcessId'>(?<ProcessId>[^<]*)</Data>"
| search EventID=1
| where match(CommandLine,"(?i)-enc") AND match(CommandLine,"(?i)-exec\s+bypass")
| table _time Image CommandLine ParentImage User ProcessId
| sort -_time


## 4. What the Query Does

-Searches the Windows Sysmon dataset in Splunk.
-Extracts the Sysmon Event ID from the raw event.
-Extracts the process image, command line, parent image, user and process ID.
-Filters for Sysmon Event ID 1, which records process creation.
-Identifies command lines containing encoded-command and execution-policy-bypass arguments.
-Displays the relevant process information for further investigation.


## 5. Simulation Note

This alert was investigated using a Windows Sysmon training dataset uploaded to Splunk Cloud.

The dataset contained 929 events. The investigation identified a PowerShell process using encoded command arguments and execution policy bypass.

The encoded command was decoded using Base64 UTF-16LE and found to contain:

Write-Host "Hello World"

A temporary file associated with PowerShell execution-policy testing was also identified during the investigation.

Based on the decoded command and the available supporting evidence, the activity was assessed as likely benign.

This project demonstrates alert investigation and analysis using training data. It does not represent a live production security alert.


## 6. Next

-Review the complete PowerShell command line.
-Decode and analyse encoded command content.
-Identify the parent process and executing user.
-Review available related process and file activity.
-Check whether relevant network telemetry is available.
-Document the evidence and determine the final verdict.


## 7. MITRE ATT&CK Reference

- **Tactic:** Execution
- **Technique:** T1059.001 – PowerShell
- **Reference:** https://attack.mitre.org/techniques/T1059/001/

## 8. Final Verdict

**Final Classification:** Likely Benign

The encoded PowerShell command was decoded and found to contain:
Write-Host "Hello World"

This command only prints text to the console. A temporary file consistent with PowerShell execution-policy testing was also identified.

No malicious behaviour was established from the available training dataset. Based on the evidence reviewed, the activity was assessed as likely benign.

