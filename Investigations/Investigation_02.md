# Investigation 02 — Possible Encoded PowerShell Execution

## 1. Investigation Details

| Field | Details |
|---|---|
| Alert ID | ALERT-002 |
| Alert Name | Possible Encoded PowerShell Execution |
| Investigation Type | Endpoint Security |
| SIEM | Splunk Cloud |
| Log Source | Windows Sysmon |
| Dataset | windows-sysmon.log |
| Index | main |
| Sourcetype | sysmon_xml_upload |
| Investigation Date | 2026-11-09 |
| MITRE ATT&CK | T1059.001 – PowerShell |

## 2. Investigation Objective

Investigate a PowerShell process launched with encoded command arguments and execution policy bypass.

The investigation focused on identifying the process, decoding its command, examining its parent process, reviewing associated file activity, and checking available endpoint telemetry for additional suspicious behaviour.

## 3. Log Verification

**Objective:** Verify that the uploaded Sysmon dataset was available in Splunk.

**SPL Query:**

```spl
index=main source="windows-sysmon.log" sourcetype="sysmon_xml_upload"
| stats count by source sourcetype host
```

**Result:**
- Source: `windows-sysmon.log`
- Sourcetype: `sysmon_xml_upload`
- Index: `main`
- Total events: 929

The dataset was successfully indexed and available for investigation.

## 4. Sysmon Event Analysis

**Objective:** Identify the available Sysmon event types.

**SPL Query:**

```spl
index=main source="windows-sysmon.log" sourcetype="sysmon_xml_upload"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| stats count by EventID
| sort EventID
```

**Results:**

| Event ID | Event Type | Count |
|---|---|---:|
| 1 | Process Creation | 50 |
| 10 | Process Access | 800 |
| 11 | File Creation | 2 |
| 13 | Registry Value Set | 38 |
| 22 | DNS Query | 39 |

Event ID 1 was selected to identify suspicious process executions and extract command-line arguments.

## 5. PowerShell Process Identification

**Objective:** Identify PowerShell execution events.

**SPL Query:**

```spl
index=main source="windows-sysmon.log" sourcetype="sysmon_xml_upload"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "Name='Image'>(?<Image>[^<]*)</Data>"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "Name='User'>(?<User>[^<]*)</Data>"
| search EventID=1
| table _time Image CommandLine ParentImage User
| sort -_time
```

**Identified Process:**

- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Parent Image: `C:\Windows\System32\cmd.exe`
- Command-line indicators: `-Exec bypass` and `-enc`
- Timestamp: `2026-11-09 10:17:41`

**Analysis:**

The encoded command argument and execution policy bypass were considered suspicious indicators requiring further investigation. These indicators alone do not confirm malicious activity.

## 6. Base64 Command Extraction and Decoding

**Objective:** Extract and decode the PowerShell command.

**Extracted Base64:**

```text
VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAVwBvAHIAbABkACIA
```

The command was decoded using Base64 with UTF-16LE encoding.

**Decoded Command:**

```powershell
Write-Host "Hello World"
```

**Analysis:**

The decoded command prints `Hello World` to the console. It does not contain an apparent download or secondary script execution instruction.

This finding supported a potentially benign explanation for the PowerShell execution.

## 7. Parent Process Investigation

**Objective:** Examine the process that launched PowerShell.

**Parent Process:**

```text
C:\Windows\System32\cmd.exe
```

**Process Details:**

| Field | Value |
|---|---|
| PowerShell PID | 5948 |
| Parent PID | 4936 |
| PowerShell Process GUID | `{E983936C-DF28-6006-9809-00000000A301}` |
| Parent Process GUID | `{E983936C-D08E-6006-EB07-00000000A301}` |

A search for the corresponding CMD process creation event did not return a matching event.

**Analysis:**

The immediate parent process was identified, but its original creation event was not available in the uploaded dataset. The complete process execution chain could therefore not be established.

## 8. Process Access Investigation

**Objective:** Check for process-access activity associated with the PowerShell process.

Sysmon Event ID 10 was searched using PowerShell PID `5948`.

**Result:** No matching process-access events were identified.

**Analysis:**

No related process-access activity was found for the investigated PID in the available telemetry.

## 9. File Creation Investigation

**Objective:** Identify files created by the PowerShell process.

Sysmon Event ID 11 was searched using PID `5948`.

**Finding:**

```text
C:\Users\Administrator\AppData\Local\Temp\__PSScriptPolicyTest_1py4clft.gbo.ps1
```

| Field | Value |
|---|---|
| Process | powershell.exe |
| Process ID | 5948 |
| Event Type | Sysmon Event ID 11 |
| Timestamp | 2026-11-09 10:17:41 |

**Analysis:**

The temporary filename is consistent with a PowerShell execution-policy testing artifact. This supports a potentially benign explanation, although the file contents were not independently inspected.

## 10. Network Activity Investigation

**Objective:** Check for network connection events associated with the PowerShell process.

Sysmon Event ID 3 was searched using PID `5948`.

**Result:** No matching network connection events were identified.

**Analysis:**

The uploaded dataset contained no Event ID 3 network connection events. Therefore, network activity could not be assessed using this event type.

The absence of these events does not prove that the process performed no network activity.

## 11. User and Execution Context

**Objective:** Identify the account and privilege level used by the PowerShell process.

| Field | Value |
|---|---|
| User | `ATTACKRANGE\Administrator` |
| Integrity Level | High |
| Current Directory | `C:\Users\Administrator\` |
| Process ID | 5948 |

**Executable Hashes:**

```text
MD5:
097CE5761C89434367598B34FE32893B

SHA256:
BA4038FD20E474C047BE8AAD5BFACDB1BFC1DDBE12F803F473B7918D8D819436
```

These hashes belong to the PowerShell executable and were not independently validated.

**Analysis:**

The process executed under an Administrator account with a High integrity level. This indicates elevated execution privileges and was considered during the investigation.

## 12. Evidence Summary

| Investigation Area | Result |
|---|---|
| PowerShell execution | Identified |
| Encoded command | Identified |
| Execution policy bypass | Identified |
| Decoded command | `Write-Host "Hello World"` |
| Parent process | cmd.exe |
| Parent creation event | Not found |
| Process access events | No matching events |
| File creation | Temporary policy-test file identified |
| Network connection events | Not available in dataset |
| Executing user | Administrator |
| Integrity level | High |

## 13. Investigation Conclusion

The investigation identified PowerShell execution using encoded command arguments and execution policy bypass.

However, decoding revealed a simple console output command. A temporary file consistent with PowerShell execution-policy testing was also identified.

No matching process-access events were found, and the uploaded dataset did not contain Sysmon Event ID 3 network connection telemetry.

The available evidence did not establish malicious execution. The activity was assessed as likely benign, with limitations documented due to incomplete process and network telemetry.

**Final Assessment:** Likely benign activity; malicious behaviour not substantiated by the available evidence.