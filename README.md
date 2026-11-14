# SOC Level 1 Shift Simulation

## Project Overview

This project simulates the workflow of a Tier 1 Security Operations Center (SOC) analyst investigating security alerts using SIEM data and basic threat intelligence tools.

The objective is to demonstrate how an L1 analyst monitors alerts, performs initial triage, investigates suspicious activity, evaluates evidence, documents findings, and escalates incidents when necessary.

This is a hands-on lab project using simulated security datasets, Splunk Cloud, and VirusTotal.

## Tools Used

- **Splunk Cloud:** Log ingestion, searching, event correlation, and alert investigation.
- **VirusTotal:** Basic reputation checks for suspicious IP addresses, domains, and file hashes.
- **Windows Sysmon:** Endpoint telemetry, process creation, and DNS activity.
- **PowerShell:** Dataset preparation and basic log inspection.
- **MITRE ATT&CK:** Mapping observed behaviour to known adversary techniques.

## Project Workflow

The simulated SOC workflow follows:

1. Monitor – Identify incoming security alerts.
2. Triage – Review alert details and determine investigation priority.
3. Investigate – Examine logs, processes, users, IP addresses, and other indicators.
4. Decide – Determine whether the activity is malicious, benign, or inconclusive.
5. Escalate – Forward suspicious or unresolved activity to L2.
6. Document – Record findings, evidence, and recommended actions.

## Investigated Alerts

| Alert | Category | Status |
|---|---|---|
| SSH Brute Force Activity | Authentication Security | Investigated |
| Encoded PowerShell Execution | Endpoint Security | Investigated |
| Possible DNS Data Exfiltration | Network Security | Pending investigation |

## Alert 01 – SSH Brute Force Activity

Investigated repeated SSH authentication failures involving the source IP `194.8.74.23`.

Findings included:
- 132 failed password events associated with the primary IP.
- Multiple targeted usernames, including root.
- No successful authentication observed from the primary IP in the logs reviewed.
- Further correlation recommended due to activity involving additional IPs and services.

## Alert 02 – Encoded PowerShell Execution

Investigated a PowerShell process launched through `cmd.exe` with an encoded command.

Findings included:
- PowerShell executed with `-ExecutionPolicy Bypass` and `-EncodedCommand` style arguments.
- The Base64 command decoded to `Write-Host "Hello World"`.
- A PowerShell temporary script-policy test file was created.
- No matching network connection event was available in the uploaded dataset.
- Malicious behaviour was not substantiated by the evidence reviewed.

## Alert 03 – Possible DNS Data Exfiltration

The investigation uses a simulated Sysmon dataset containing repeated `nslookup.exe` executions and Base64-encoded strings in DNS query arguments.

The dataset is intended to demonstrate investigation of possible DNS-based data transfer.

Status: Pending Splunk ingestion and full investigation.

## Important Note

This is a simulated SOC lab project. The findings are based on provided sample datasets and should not be interpreted as investigations of real-world production incidents.

## Repository Structure

- `Alerts/` – Initial alert descriptions and investigation objectives.
- `Investigations/` – Detailed investigation notes and Splunk queries.
- `Reports/` – Final incident summaries and conclusions.
- `Escalation/` – Escalation criteria and handover checklist.
- `Screenshots/` – Supporting screenshots from Splunk investigations.