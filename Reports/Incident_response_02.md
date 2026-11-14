# Incident Response Report 02: Possible Encoded PowerShell Execution

## 1. Incident Details

| Field | Details |
|---|---|
| Incident ID | ALERT-002 |
| Incident Name | Possible Encoded PowerShell Execution |
| Category | Endpoint Security |
| Investigation Date | 09 November 2026 |
| Affected Asset | Windows Endpoint |
| Log Source | Windows Sysmon |
| SIEM Platform | Splunk Cloud |
| Dataset | `windows-sysmon.log` |
| Index | `main` |
| Sourcetype | `sysmon_xml_upload` |
| Initial Severity | Medium |
| Final Severity Assessment | Low |
| Final Verdict | Likely Benign |
| Escalation Decision | No Immediate L2 Escalation Recommended |

## 2. Executive Summary

This report documents the investigation of a PowerShell process execution involving encoded command arguments and execution policy bypass.

The activity was identified in a Windows Sysmon training dataset and investigated using Splunk Cloud.

The investigation identified a PowerShell process launched by `cmd.exe` under the `ATTACKRANGE\Administrator` account.

The encoded command was decoded using Base64 UTF-16LE and found to contain:

```powershell
Write-Host "Hello World"
```

A temporary file consistent with PowerShell execution-policy testing was also identified.

No malicious behaviour was established from the available evidence. The activity was assessed as **Likely Benign**, and immediate L2 escalation was not recommended.

## 3. Key Findings

| Investigation Area | Finding |
|---|---|
| PowerShell Execution | Identified through Sysmon Event ID 1 |
| Process ID | 5948 |
| Parent Process | `cmd.exe`, PID 4936 |
| Executing User | `ATTACKRANGE\Administrator` |
| Integrity Level | High |
| Command-Line Indicators | `-Exec bypass` and `-enc` |
| Encoded Command | Successfully decoded |
| Decoded Command | `Write-Host "Hello World"` |
| Parent Process Event | Corresponding CMD creation event not found |
| Process Access | No matching Event ID 10 events for PID 5948 |
| File Creation | Temporary PowerShell policy-test file identified |
| Network Telemetry | Sysmon Event ID 3 events absent from the dataset |

## 4. Impact Assessment

The investigation identified PowerShell execution with encoded command arguments and execution policy bypass.

These indicators can be associated with suspicious activity and required further investigation.

However, the decoded command contained only a console output instruction. No malicious functionality was established from the available evidence.

The investigation did not establish unauthorised access, data theft, malware execution, or successful network communication.

The overall security state of the endpoint could not be independently verified because some supporting telemetry was unavailable.

**Assessed Impact:** No confirmed malicious impact identified from the available training dataset.

## 5. Actions Performed

The following investigation activities were completed:

1. Verified that the Windows Sysmon dataset was successfully indexed in Splunk Cloud.
2. Reviewed available Sysmon event types.
3. Identified the PowerShell process creation event.
4. Examined the command-line arguments and process details.
5. Decoded the Base64 command using UTF-16LE encoding.
6. Identified the parent process and executing user.
7. Reviewed available process-access events.
8. Identified a temporary PowerShell-related file creation event.
9. Checked the availability of network connection telemetry.
10. Documented the findings and assigned a final verdict.

No endpoint isolation, process termination, account disabling, or network blocking was performed as part of this simulation.

## 6. Recommendations

The following actions are recommended if additional evidence becomes available:

1. Review the parent `cmd.exe` process and its original command line.
2. Inspect the temporary PowerShell policy-test file if it can be recovered.
3. Collect additional endpoint process and network telemetry.
4. Validate the PowerShell executable hashes against a trusted reference.
5. Continue monitoring for unusual PowerShell executions involving encoded commands and execution policy bypass.
6. Reassess the alert if additional suspicious activity is identified.

## 7. Final Disposition

**Final Verdict: Likely Benign**

**Final Severity Assessment: Low**

**Escalation Decision: No Immediate L2 Escalation Recommended**

The investigation did not establish malicious behaviour from the available Windows Sysmon training dataset.

The decoded command showed a simple console output instruction, and the temporary file was consistent with PowerShell execution-policy testing.

The alert may be closed as likely benign, subject to organisational policy and any additional evidence that becomes available.

## 8. Investigation References

The following project documents contain the supporting alert and investigation details:

- [Alert 02 – Possible Encoded PowerShell Execution](../alerts/alert_02.md)
- [Investigation 02 – Possible Encoded PowerShell Execution](../investigations/investigation_02.md)
- [Escalation Assessment 02 – Possible Encoded PowerShell Execution](../escalation/escalation_02.md)

## 9. Limitations

This report is based on a static Windows Sysmon training dataset. The following limitations apply:

- The parent `cmd.exe` process creation event was not available.
- The temporary PowerShell policy-test file contents were not independently inspected.
- No matching Event ID 10 process-access events were found for PowerShell PID 5948.
- Sysmon Event ID 3 network connection events were absent from the dataset.
- The recorded PowerShell executable hashes were not independently validated.
- The complete process execution chain could not be established.
- The overall security state of the endpoint could not be independently verified.

The final assessment is based only on the evidence available in the training dataset. This report represents a simulated SOC investigation and does not describe a confirmed real-world security incident.