# SOC-ALERT-01: Escalation to SOC L2

## 1. Escalation Details

| Field | Details |
|---|---|
| Alert ID | SOC-ALERT-01 |
| Alert Name | Multiple Failed SSH Login Attempts |
| Latest Observed Activity | 6 November 2026 |
| Activity Period | 30 October–6 November 2026 (training dataset)|
| Affected Hosts | `www1`, `mailsv`, `www2`, `www3` |
| Primary Source IP | `194[.]8[.]74[.]23` |
| Failed Login Attempts | 132 |
| Severity | Medium |
| Initial Assessment | Suspicious SSH authentication activity |
| Escalation | Recommended to SOC L2 |

## 2. Incident Summary

During the investigation, I identified repeated failed SSH login attempts from the source IP `194[.]8[.]74[.]23`.

The activity affected four hosts and generated 132 failed authentication events. The attempts involved multiple usernames, including `root`.

This pattern raised concern because the same source IP repeatedly attempted to access different servers.

## 3. Investigation Findings

| Finding | Result |
|---|---|
| Failed SSH attempts | 132 |
| Source IP | `194[.]8[.]74[.]23` |
| Hosts affected | 4 |
| Root account targeted | Yes |
| Successful login from the primary IP | No successful authentication observed in the investigated logs |
| Other source IPs | Three internal IPs were identified with both failed and successful SSH login events; their activity requires validation |
| VirusTotal lookup | 0 security vendor detections on 10 November 2026 |

The initial broad search returned 313 matching events. After filtering for failed SSH password attempts, 132 events were identified.

## 4. Escalation Checklist

| Check | Result |
|---|---|
| Alert activity investigated | Yes |
| Source IP identified | Yes |
| Affected hosts identified | Yes |
| Targeted usernames reviewed | Yes |
| Successful authentication checked | Yes |
| External IP reputation checked | Yes |
| Evidence documented | Yes |
| Further investigation required | Yes |

## 5. Actions Taken by SOC L1

- Reviewed the SSH authentication events in Splunk.
- Identified the source IP responsible for the repeated failures.
- Checked which hosts and usernames were targeted.
- Searched for successful SSH authentication from the primary IP.
- Checked the IP address using VirusTotal.
- Documented the findings and supporting evidence.

## 6. Reason for Escalation

I recommend escalating this alert to SOC L2 because the repeated login attempts affected multiple servers and included attempts against the `root` account.

Although no successful authentication from the primary IP was observed in the investigated logs, the activity still requires further review.

The VirusTotal lookup returned no vendor detections, but this alone does not establish that the IP is safe.

## 7. Requested SOC L2 Actions

I recommend that SOC L2:

1. Review the SSH authentication activity across all affected hosts.
2. Check whether any successful login or suspicious session was missed.
3. Investigate the additional source IP addresses.
4. Review related events for possible follow-up activity.
5. Determine whether the source IP should be blocked, based on the wider investigation.
6. Review the 181 related web access events, including requested paths, HTTP methods, status codes and user agents.

## 8. Final Escalation Decision

**Decision: Recommend escalation to SOC L2.**

Based on the repeated failed SSH attempts across four hosts, I consider the activity suspicious and worthy of further investigation.

There is currently no confirmed evidence of a successful compromise from the primary IP in the logs reviewed. The final incident classification should be determined after further investigation.

## 9. Supporting Evidence

- [Alert Configuration](../alerts/alert_01.md)
- [Investigation Notes](../investigations/investigation_01.md)
- [Incident Report](../reports/incident_report.md)

Screenshots and Splunk search results are available in the `screenshots/` folder.