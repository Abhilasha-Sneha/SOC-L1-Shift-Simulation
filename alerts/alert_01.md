# SOC-ALERT-01: Multiple Failed SSH Logins

## 1. Alert Summary

| Field | Value |
|---|---|
| Alert ID | SOC-ALERT-01 |
| Alert Name | Multiple Failed SSH Logins from One Source IP |
| Platform | Splunk Cloud (free trial) |
| Data Source | Linux SSH authentication logs (`index=main`, `sourcetype=secure-2`) |
| Hosts in Scope | mailsv, www1, www2, www3 |
| Detection Condition | 10 or more failed SSH logins from a single source IP, counted across all hosts in scope |
| Alert Type | Scheduled, hourly |
| Initial Severity | Medium |
| Status | Investigated. See Section 6 |

## 2. What Fired

The detection query flagged source IPs with 10 or more failed SSH logins. The investigation focused on `194[.]8[.]74[.]23`, which had 132 failed logins against `mailsv`. Other IPs also generated failures against the same server. Their counts are in the investigation file.

## 3. Detection Query

```spl
index=main sourcetype=secure-2 "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3}) port"
| stats count by src_ip
| where count >= 10
```

## 4. What the Query Does

- Finds failed SSH password events in the authentication logs.
- Extracts the source IP address from each event with `rex`.
- Counts failed attempts per source IP with `stats count by src_ip`.
- Keeps only IPs with 10 or more failures with `where count >= 10`.

The threshold of 10 is a simple starting value for this simulation. A real deployment would tune it against the environment's normal failure rate.

## 5. Simulation Note

The data is a static training dataset, so no new events arrive over time. A scheduled alert was configured in Splunk but did not trigger. I validated the detection logic by running the query manually against the full dataset. In a live SOC, this alert would run on streaming logs.

## 6. Outcome

| Question | Answer |
|---|---|
| What I checked | Failed SSH login counts per source IP, targeted usernames, whether any login from the source IP succeeded, and other activity associated with the IP |
| Verdict | True Positive (TP) |
| Why | The source IP 194[.]8[.]74[.]23 generated 132 failed SSH login attempts against mailsv. Multiple usernames, including root, were targeted. No successful login from this IP was observed in the logs reviewed |
| Escalation | Escalate to L2 – repeated authentication failures against multiple accounts indicate suspicious activity that requires further investigation. |

Full evidence, queries and reasoning: [Investigation 01](../Investigations/Investigation_01.md)