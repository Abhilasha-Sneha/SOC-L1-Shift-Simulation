# ALERT-002: Possible Encoded PowerShell Execution

## 1. Alert Information

- **Alert ID:** ALERT-002
- **Alert Name:** Possible Encoded PowerShell Execution
- **Category:** Endpoint Security / Suspicious Process Execution
- **Severity:** Medium (Initial Assessment)
- **Status:** New – Pending Investigation
- **Affected Asset:** Windows Endpoint
- **Log Source:** Windows Sysmon
- **Sysmon Event ID:** 1 – Process Creation
- **MITRE ATT&CK:** T1059.001 – PowerShell

## 2. Alert Description

A potentially suspicious PowerShell process execution has been flagged for investigation.

PowerShell supports encoded commands, which can allow commands to be passed in an encoded format rather than appearing as readable text in the command line. This functionality can be used by legitimate administrative scripts as well as attackers attempting to conceal their activity.

The SOC analyst must investigate the process execution and determine whether the activity is legitimate or potentially malicious.

## 3. Initial Indicators to Investigate

The following indicators should be examined:

- PowerShell executable (`powershell.exe` or `pwsh.exe`).
- Command-line arguments such as `-EncodedCommand` or `-enc`.
- Base64-encoded command content.
- Unusual parent-child process relationships.
- Unexpected user accounts or execution contexts.
- Related network connections, DNS queries, and file creation events.

**Note:** These are investigation indicators, not confirmed findings.

## 4. Investigation Objectives

1. Identify the PowerShell process execution event.
2. Examine the complete command line.
3. Determine whether an encoded command was used.
4. Decode and analyze the command, if applicable.
5. Identify the parent process and executing user.
6. Correlate related Sysmon events.
7. Determine whether the activity is malicious, benign, or inconclusive.

## 5. Initial Assessment

Encoded PowerShell execution can be associated with legitimate administration or malicious activity.

The alert requires further investigation before assigning a final verdict.

## 6. Expected SOC Actions

- Review relevant Sysmon process creation events in Splunk.
- Examine process relationships and command-line arguments.
- Investigate related network and file activity.
- Document supporting evidence.
- Escalate to L2 if suspicious activity is identified or the investigation remains inconclusive.

## 7. MITRE ATT&CK Reference

- **Tactic:** Execution
- **Technique:** T1059.001 – PowerShell
- **Reference:** https://attack.mitre.org/techniques/T1059/001/

## 8. Final Verdict

**Pending Investigation**

The final classification will be assigned after reviewing the available evidence.