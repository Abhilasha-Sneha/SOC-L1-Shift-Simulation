# Incident Report: Suspicious SSH Authentication Activity

## Incident Details

| Field | Details |
|---|---|
| Report Type | Simulated SOC L1 Incident Report |
| Alert ID | SOC-ALERT-01 |
| Incident Date | 06 November 2026 |
| Activity Period | 30 October–6 November 2026 (training dataset) |
| Investigation Date | 09 November 2026 |
| Affected Servers | mailsv, www1, www2, www3 |
| Primary Source IP | 194[.]8[.]74[.]23 |
| Platform | Splunk Cloud |
| Classification | Suspicious Authentication Activity |
| Compromise Status | Not Confirmed |
| Disposition | Recommended for SOC L2 Escalation |

## 1. Executive Summary

During the investigation of a simulated security alert, repeated failed SSH authentication attempts were identified from source IP 194[.]8[.]74[.]23.

The investigation identified 132 failed SSH authentication events across four servers. The attempts targeted 74 distinct usernames, including root.

No successful SSH authentication from the primary source IP was identified in the investigated logs. A VirusTotal lookup performed on 10 November 2026 returned zero security-vendor detections for the IP.

A broader search also identified 181 related web access events associated with the same IP. These events have not yet been individually investigated.

The activity was classified as suspicious and recommended for SOC L2 escalation. No successful compromise was confirmed from the available evidence.

## 2. Key Findings

- 132 failed SSH authentication events associated with the primary IP.
- Four servers recorded failed authentication events.
- 74 distinct usernames were targeted, including root.
- Additional source IP addresses generated failed authentication attempts against mailsv.
- No successful authentication from the primary source IP was observed.
-Three additional internal IP addresses were identified with both failed and successful SSH login events; their activity requires validation.
- VirusTotal returned zero security-vendor detections on 10 November 2026.
- The broader search returned 181 related web access events that require further investigation.

## 3. Impact Assessment

The investigation confirmed repeated unsuccessful SSH authentication attempts acress four servers.

No successful authentication or account compromise from the primary source IP was established from the available evidence.

The potential impact of the wider activity remains undetermined and requires further investigation.

## 4. Actions Performed

- Reviewed SSH authentication logs in Splunk.
- Identified the primary source IP and affected servers.
- Investigated failed and successful authentication events.
- Identified targeted usernames and affected servers.
- Examined additional source IP addresses and service-related logs.
- Checked IP reputation using VirusTotal.
-Identified related web access events requiring further investigation.
- Prepared recommendations and an SOC L2 escalation request.

## 5. Recommendations

-Review the SSH authentication activity across all affected servers.
-Validate whether successful SSH sessions from the additional internal IP addresses were legitimate and authorised.
-Investigate the 181 related web access events, including requested paths, HTTP methods, status codes and user agents.
-Restrict SSH access to trusted networks where appropriate.
-Disable direct root SSH login where operationally appropriate.
-Implement SSH key-based authentication.
-Configure Fail2ban or equivalent protection against repeated authentication attempts.
-Continue monitoring repeated authentication failures and suspicious login patterns.
-Assess whether the primary source IP should be blocked through the appropriate security change process.

## 6. Final Disposition

**Final assessment:** Suspicious SSH authentication activity.

**Compromise status:** Not confirmed from the available logs.

**Severity**: Medium.

**Escalation:** Recommended for SOC L2 investigation.
The investigation identified repeated failed SSH authentication attempts across multiple servers. Further investigation is required before determining whether the wider activity resulted in unauthorised access or compromise.

## 7. Investigation Reference

Detailed evidence, queries and analysis:

[Investigation 01 – Multiple Failed SSH Logins](../investigations/investigation_01.md)

SOC L1 to L2 handover:

[Escalation Request 01](../escalation/escalation_request_01.md)

## 8. Limitations

This report is based on a simulated training dataset and the events available during the investigation. The absence of successful authentication from the primary IP does not establish that the wider environment was free from compromise.