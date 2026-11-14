# Investigation 02: Possible Encoded PowerShell Execution

## 1. Summary

This investigation was conducted to analyse a PowerShell process execution identified in the Windows Sysmon training dataset.

The process was launched with encoded command arguments and execution policy bypass. These indicators can be associated with suspicious PowerShell activity and required further investigation.

The investigation focused on identifying the PowerShell process, decoding the command, examining its parent process, reviewing related file and process activity, and checking the available network telemetry.

The encoded command was successfully decoded and found to contain:

```powershell
Write-Host "Hello World"
```

A temporary file consistent with PowerShell execution-policy testing was also identified.

No malicious behaviour was established from the available evidence. The activity was assessed as **Likely Benign**.

## 2. Scope

| Field | Details |
|---|---|
| Alert ID | SOC-ALERT-002 |
| Alert Name | Possible Encoded PowerShell Execution |
| Investigation Date | 09 November 2026 |
| Investigation Type | Endpoint Security |
| SIEM Platform | Splunk Cloud |
| Log Source | Windows Sysmon |
| Dataset | `windows-sysmon.log` |
| Index | `main` |
| Sourcetype | `sysmon_xml_upload` |
| Total Events | 929 |
| Affected Asset | Windows Endpoint |
| Process | `powershell.exe` |
| Process ID | 5948 |
| Parent Process | `cmd.exe` |
| Parent Process ID | 4936 |
| Executing User | `ATTACKRANGE\Administrator` |
| Initial Severity | Medium |
| Final Verdict | Likely Benign |

## 3. Investigation Steps

### Step 1: Verify the Uploaded Dataset

The first step was to verify that the Windows Sysmon dataset was successfully uploaded and indexed in Splunk.

**SPL Query:**

```spl
index=main source="windows-sysmon.log" sourcetype="sysmon_xml_upload"
| stats count by source sourcetype host
```

**Result:**

The dataset was successfully indexed and contained 929 events.

| Field | Result |
|---|---|
| Source | `windows-sysmon.log` |
| Sourcetype | `sysmon_xml_upload` |
| Index | `main` |
| Total Events | 929 |

### Step 2: Identify Available Sysmon Event Types

The next step was to identify the Sysmon event types available in the uploaded dataset.

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
| | **Total** | **929** |

Event ID 1 was selected to identify process executions and examine command-line arguments.

No Sysmon Event ID 3 (Network Connection) events were present in the uploaded dataset.

### Step 3: Identify the PowerShell Process

Process creation events were reviewed to identify PowerShell executions and their command-line arguments.

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

| Field | Observed Value |
|---|---|
| Timestamp | 09 November 2026, 10:17:41 |
| Process Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Process ID | 5948 |
| Parent Image | `C:\Windows\System32\cmd.exe` |
| Parent Process ID | 4936 |
| Executing User | `ATTACKRANGE\Administrator` |
| Integrity Level | High |
| Current Directory | `C:\Users\Administrator\` |
| Command-Line Indicators | `-Exec bypass` and `-enc` |

**Analysis:**

The PowerShell process contained encoded command arguments and an execution policy bypass indicator.

These indicators can be associated with suspicious activity, but they do not independently confirm malicious execution.

### Step 4: Decode the Encoded PowerShell Command

The PowerShell command line contained a Base64-encoded value.

**Extracted Base64:**

```text
VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAVwBvAHIAbABkACIA
```

The encoded value was decoded using Base64 with UTF-16LE encoding.

**Decoded Command:**

```powershell
Write-Host "Hello World"
```

**Analysis:**

The decoded command prints `Hello World` to the console.

No apparent download or secondary script execution instruction was identified in the decoded command. This finding supported a potentially benign explanation for the PowerShell execution.

### Step 5: Examine the Parent Process

The identified PowerShell process was launched by `cmd.exe`.

**Process Details:**

| Field | Value |
|---|---|
| PowerShell Process ID | 5948 |
| Parent Process | `cmd.exe` |
| Parent Process ID | 4936 |
| PowerShell Process GUID | `{E983936C-DF28-6006-9809-00000000A301}` |
| Parent Process GUID | `{E983936C-D08E-6006-EB07-00000000A301}` |

A search for the corresponding CMD process creation event did not return a matching event.

**Analysis:**

The immediate parent process was identified, but its original creation event was not available in the uploaded dataset.

Therefore, the complete process execution chain and the activity that originally launched CMD could not be established.

### Step 6: Review Process Access Events

Sysmon Event ID 10 records process access activity.

The available Event ID 10 records were searched for activity associated with PowerShell Process ID `5948`.

**Result:**

No matching process-access events were identified for PID `5948`.

**Analysis:**

No related process-access activity was found for the investigated process in the available telemetry.

### Step 7: Review File Creation Events

Sysmon Event ID 11 records file creation activity.

A temporary PowerShell-related file was identified during the investigation.

**Identified File:**

```text
C:\Users\Administrator\AppData\Local\Temp\__PSScriptPolicyTest_1py4clft.gbo.ps1
```

| Field | Value |
|---|---|
| Process | `powershell.exe` |
| Process ID | 5948 |
| Event Type | Sysmon Event ID 11 |
| Timestamp | 09 November 2026, 10:17:41 |

**Analysis:**

The temporary filename is consistent with a PowerShell execution-policy testing artifact.

This supports a potentially benign explanation. However, the file contents were not independently inspected, so its exact purpose could not be confirmed.

### Step 8: Review Network Activity

The investigation checked whether network connection activity could be reviewed for the PowerShell process.

**Result:**

No Sysmon Event ID 3 (Network Connection) events were present in the uploaded dataset.

**Analysis:**

Network connection activity associated with PowerShell PID `5948` could not be assessed because the required Event ID 3 telemetry was unavailable.

The absence of these events does not prove that the process performed no network activity.

### Step 9: Review User and Execution Context

The executing account and privilege level were reviewed to understand the context in which PowerShell was launched.

| Field | Observed Value |
|---|---|
| User | `ATTACKRANGE\Administrator` |
| Integrity Level | High |
| Current Directory | `C:\Users\Administrator\` |
| Process ID | 5948 |

**PowerShell Executable Hashes:**

MD5:

```text
097CE5761C89434367598B34FE32893B
```

SHA256:

```text
BA4038FD20E474C047BE8AAD5BFACDB1BFC1DDBE12F803F473B7918D8D819436
```

These hashes were recorded during the investigation but were not independently validated against a trusted reference.

**Analysis:**

The PowerShell process executed under an Administrator account with High integrity.

This indicates elevated execution privileges and was considered during the investigation. However, the account context alone does not establish malicious activity.

## 4. Evidence

The following evidence was collected during the investigation:

| Evidence | Observation |
|---|---|
| Dataset | 929 Windows Sysmon events |
| Process Execution | PowerShell process identified through Event ID 1 |
| Process ID | 5948 |
| Parent Process | `cmd.exe`, PID 4936 |
| Executing User | `ATTACKRANGE\Administrator` |
| Integrity Level | High |
| Command-Line Indicators | `-Exec bypass` and `-enc` |
| Encoded Command | Successfully decoded using Base64 UTF-16LE |
| Decoded Command | `Write-Host "Hello World"` |
| Parent Process Event | Not found in the available dataset |
| Event ID 10 | No matching process-access events for PID 5948 |
| Event ID 11 | Temporary PowerShell policy-test file identified |
| Event ID 3 | Network connection telemetry absent from dataset |
| Executable Hashes | Recorded but not independently validated |

## 5. Analysis

The investigation identified PowerShell execution involving encoded command arguments and execution policy bypass.

These indicators required further investigation because encoded PowerShell commands can be used to conceal malicious instructions.

However, decoding the command revealed a simple console output instruction:

```powershell
Write-Host "Hello World"
```

The command did not show apparent malicious functionality. A temporary file consistent with PowerShell execution-policy testing was also identified.

The investigation did not identify matching process-access events for the PowerShell process. Additionally, the parent CMD process creation event was unavailable, and network connection activity could not be assessed because the dataset did not contain Sysmon Event ID 3 events.

Based on the available evidence, the activity appeared consistent with benign PowerShell execution. However, the incomplete telemetry did not allow the entire execution context or overall endpoint security state to be verified.

## 6. Verdict

**Final Verdict: Likely Benign**

The encoded PowerShell command was successfully decoded and contained a simple console output instruction.

The temporary file identified during the investigation was consistent with PowerShell execution-policy testing.

No malicious behaviour was established from the available training dataset. The activity was therefore assessed as likely benign based on the evidence reviewed.

This verdict does not establish that the entire endpoint or all related activity was harmless.

## 7. Severity

**Initial Severity: Medium**

**Final Severity Assessment: Low**

The alert was initially assigned Medium severity because encoded PowerShell execution and execution policy bypass can be associated with suspicious activity.

Following investigation, the decoded command showed no apparent malicious functionality, and the available supporting evidence was consistent with a potentially benign explanation.

Based on the evidence reviewed, a Low severity assessment was considered appropriate.

## 8. Escalation Decision

**Decision: No Immediate L2 Escalation Recommended**

The investigation did not establish malicious activity requiring immediate escalation.

The decoded command appeared benign, and the temporary file was consistent with PowerShell execution-policy testing.

However, further validation may be appropriate if additional endpoint telemetry becomes available, particularly to establish the parent process context and inspect the temporary file contents.

## 9. Recommendations

1. Review the parent `cmd.exe` process if additional process creation logs become available.
2. Inspect the temporary PowerShell policy-test file if the original file can be recovered.
3. Review additional endpoint telemetry for related suspicious process activity.
4. Collect network connection logs if further investigation is required.
5. Continue monitoring for unusual PowerShell executions involving encoded commands and execution policy bypass.
6. Document similar events and compare their decoded commands and process relationships.

## 10. MITRE ATT&CK

| Field | Details |
|---|---|
| Tactic | Execution |
| Technique | T1059.001 – PowerShell |
| Reference | [MITRE ATT&CK – PowerShell](https://attack.mitre.org/techniques/T1059/001/) |

The technique was mapped because the investigated activity involved PowerShell execution. This mapping does not establish that the activity was malicious.

## 11. Limitations

The investigation was conducted using a static Windows Sysmon training dataset. The following limitations apply:

- The parent `cmd.exe` process creation event was not available.
- The contents of the temporary PowerShell policy-test file were not independently inspected.
- No matching Event ID 10 process-access events were found for PowerShell PID `5948`.
- Sysmon Event ID 3 network connection events were absent from the uploaded dataset, so network connection activity could not be assessed through those events.
- The recorded PowerShell executable hashes were not independently validated.
- The investigation could not establish the complete process execution chain.
- The overall security state of the endpoint could not be independently verified.

The final verdict is therefore based only on the evidence available in the training dataset.