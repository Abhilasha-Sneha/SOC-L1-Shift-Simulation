# Incident Report: Suspicious SSH Authentication Activity

## Incident Details

| Field | Details |
|---|---|
| Report Type | Simulated SOC L1 Incident Report |
| Alert ID | SOC-ALERT-01 |
| Incident Date | 06 November 2026 |
| Investigation Date | 09 November 2026 |
| Affected Servers | mailsv, www1, www2, www3 |
| Primary Source IP | 194.8.74.23 |
| Platform | Splunk Cloud |
| Classification | Suspicious Authentication Activity |
| Compromise Status | Not Confirmed |
| Disposition | Recommended for SOC L2 Escalation |

## 1. Executive Summary

During the investigation of a simulated security alert, repeated failed SSH authentication attempts were identified from source IP `194.8.74.23`.

The investigation identified 132 failed authentication events across four servers. Multiple usernames, including root, were targeted.

No successful SSH authentication from the primary source IP was observed in the investigated logs. VirusTotal reported no security vendor detections for the IP at the time of checking.

The activity was classified as suspicious and recommended for SOC L2 escalation to investigate the wider authentication and service-related activity.

## 2. Key Findings

- 132 failed SSH authentication events associated with the primary IP.
- Four servers recorded failed authentication events.
- Multiple usernames were targeted, including root.
- Additional source IP addresses generated failed authentication attempts against mailsv.
- No successful authentication from the primary source IP was observed.
- No VirusTotal security vendor detections were reported at the time of lookup.
- Additional service-related activity requires investigation.

## 3. Impact Assessment

The investigation confirmed repeated unsuccessful SSH authentication attempts.

No successful authentication or account compromise was established from the available evidence.

The potential impact of the wider activity remains undetermined and requires further investigation.

## 4. Actions Performed

- Reviewed SSH authentication logs in Splunk.
- Identified and analysed the suspicious source IP.
- Investigated failed and successful authentication events.
- Identified targeted usernames and affected servers.
- Examined additional source IP addresses and service-related logs.
- Checked IP reputation using VirusTotal.
- Prepared recommendations and an SOC L2 escalation request.

## 5. Recommendations

- Restrict SSH access to trusted networks.
- Disable direct root SSH login.
- Implement SSH key-based authentication.
- Configure Fail2ban or equivalent protection.
- Monitor repeated authentication failures.
- Investigate additional source IP addresses and service-related events.

## 6. Final Disposition

**Final assessment:** Suspicious SSH authentication activity.

**Compromise status:** Not confirmed.

**Escalation:** Recommended for SOC L2 investigation.

## 7. Investigation Reference

Detailed evidence, queries and analysis:

[Investigation 01 – Multiple Failed SSH Logins](../investigations/investigation_01.md)

SOC L1 to L2 handover:

[Escalation Request 01](../escalation/escalation_request_01.md)

## 8. Limitations

This report is based on a simulated training dataset and the events available during the investigation. The absence of successful authentication from the primary IP does not establish that the wider environment was free from compromise.