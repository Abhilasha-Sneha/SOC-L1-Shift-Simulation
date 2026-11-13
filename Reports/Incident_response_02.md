# Incident Report — ALERT-002

## Possible Encoded PowerShell Execution

### 1. Executive Summary

A PowerShell process was identified executing with encoded command arguments and execution policy bypass.

The activity was investigated using Windows Sysmon logs in Splunk Cloud. The encoded command was extracted and decoded, revealing a simple console output instruction:

`Write-Host "Hello World"`

A temporary file consistent with PowerShell execution-policy testing was also identified.

Based on the available evidence, the activity was assessed as likely benign. No malicious behaviour was substantiated during the investigation.

### 2. Alert Information

| Field | Details |
|---|---|
| Alert ID | ALERT-002 |
| Alert Name | Possible Encoded PowerShell Execution |
| Category | Endpoint Security |
| Severity | Medium (initial alert classification) |
| Status | Investigated |
| Final Assessment | Likely Benign |
| SIEM | Splunk Cloud |
| Log Source | Windows Sysmon |
| MITRE ATT&CK | T1059.001 – PowerShell |

### 3. Detection Details

A Windows PowerShell process was identified with the following command-line indicators:

- `-Exec bypass`
- `-enc`

**Process Information:**

| Field | Value |
|---|---|
| Process | powershell.exe |
| Parent Process | cmd.exe |
| Process ID | 5948 |
| Timestamp | 2026-11-09 10:17:41 |
| User | `ATTACKRANGE\Administrator` |
| Integrity Level | High |

The execution policy bypass and encoded command arguments triggered further investigation.

### 4. Key Investigation Findings

**Finding 1 — Encoded Command**

The Base64 command was decoded using UTF-16LE encoding.

Decoded command:

```powershell
Write-Host "Hello World"
```

The command only prints text to the console and does not show an apparent malicious payload.

**Finding 2 — Parent Process**

The immediate parent process was identified as `cmd.exe`.

However, the corresponding parent process creation event was not available in the uploaded dataset, preventing complete process-chain reconstruction.

**Finding 3 — File Creation**

A temporary file was identified:

```text
C:\Users\Administrator\AppData\Local\Temp\__PSScriptPolicyTest_1py4clft.gbo.ps1
```

The filename is consistent with PowerShell execution-policy testing. The file contents were not independently inspected.

**Finding 4 — Process and Network Activity**

No matching Sysmon Event ID 10 process-access events were identified for the investigated PowerShell PID.

The uploaded dataset did not contain Sysmon Event ID 3 network connection events, so network activity could not be fully assessed.

### 5. Evidence Summary

| Evidence | Observation |
|---|---|
| Encoded PowerShell execution | Confirmed |
| Execution policy bypass | Confirmed |
| Decoded command | `Write-Host "Hello World"` |
| Parent process | cmd.exe |
| Temporary file creation | Identified |
| User context | Administrator |
| Integrity level | High |
| Malicious payload | Not identified |
| Network telemetry | Not available for Event ID 3 |

### 6. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell was used to execute the command |

The technique mapping describes the observed execution method. It does not establish that the activity was malicious.

### 7. Final Assessment

<escape>**Classification: False Positive for malicious activity**</escape>

**Reasoning:**

- The encoded command was successfully decoded.
- The command contained only a console output instruction.
- A temporary file consistent with PowerShell execution-policy testing was identified.
- No additional malicious behaviour was established through the available evidence.

The initial alert indicators warranted investigation, but the evidence did not substantiate malicious execution.

### 8. Recommended Action

- Document the activity as likely benign.
- Retain the investigation evidence and Splunk queries.
- Reassess if additional suspicious telemetry becomes available.
- Review the original parent process and temporary file if more complete endpoint data becomes available.

### 9. Investigation Limitations

- The parent CMD process creation event was unavailable.
- The temporary file contents were not inspected.
- The PowerShell executable hashes were not independently validated.
- Sysmon Event ID 3 network connection telemetry was absent from the uploaded dataset.
- The conclusion is limited to the evidence available in the lab dataset.

### 10. Closure Summary

The alert was investigated through process creation analysis, command decoding, parent-process review, file creation analysis, and available endpoint telemetry.

The decoded command and temporary file provided evidence supporting a benign explanation. No malicious activity was substantiated.

**Final Disposition:** Likely benign — close as a false positive for malicious activity, based on the available lab evidence.
