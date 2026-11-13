# Investigation 01: Multiple Failed SSH Logins (SOC-ALERT-01)

## 1. At a Glance

| Question | Answer |
|---|---|
| **What fired** | SOC-ALERT-01 detected source IPs with 10 or more failed SSH logins. I investigated 194[.]8[.]74[.]23, which generated 132 failed SSH login events across four servers: mailsv, www1, www2 and www3. |

| **What I checked** | Failed logins per source IP and host, targeted usernames, successful SSH logins, other activity associated with the IP, and its VirusTotal reputation. |

| **Verdict** | True Positive (TP). The alert detected repeated failed SSH authentication activity from the investigated IP |

| **Why** | The IP generated 132 failed SSH login events across four servers, targeting 74 distinct usernames, including `root`. No successful SSH login from this IP was found in the searched dataset. |

| **Severity** | Medium. Repeated attempts across four servers, including attempts against root, warrant further investigation. |

| **Decision** | **Escalate to L2** for review of the repeated SSH failures and to check whether any other high-failure source IPs had successful logins. |

## 2. Scope

| Field | Details |
|---|---|
| Alert | SOC-ALERT-01 |
| Platform | Splunk Cloud, `index=main`, `sourcetype=secure-2`, time range: All time |
| Primary source IP | `194[.]8[.]74[.]23` |
| Hosts | mailsv, www1, www2, www3 |
| Investigation date | 09 November 2026 |
| Event time | Timestamps are taken from the training dataset. They do not represent a verified real-world incident date. |

## 3. Investigation Steps

### Step 1: What does a failed login look like?
**Question:** What fields does a failed SSH event contain?
**Query:** `index=main sourcetype=secure-2 "Failed password" | head 5`
**Result:**
```text
Thu Nov 06 2026 06:16:56 mailsv1 sshd[1039]: Failed password for root from 194.8.74.23 port 3768 ssh2
```
**Meaning:** The event shows a failed SSH password attempt against root from 194.8.74.23. The raw message identifies the hostname as mailsv1, while Splunk's indexed host field identifies it as mailsv. I use the indexed host field for host-based investigation.

### Step 2: What does a successful login look like?
**Question:** How do accepted logins differ from failures?
**Query:** `index=main sourcetype=secure-2 "Accepted password" | head 5`
**Result:**
```text
Thu Nov 06 2026 06:16:56 mailsv1 sshd[74181]: Accepted password for nsharpe from 10[.]2[.]10[.]163 port 4245 ssh2
```
**Meaning:** This event demonstrates the format of a successful SSH login. It is from a different source IP (10[.]2[.]10[.]163), so it is only a reference example and does not indicate successful access by the investigated IP.

### Step 3: How far does this IP reach?
**Question:** Which hosts did `194[.]8[.]74[.]23` fail against?
**Queries:**
```
index=main "194.8.74.23" | stats count by host, source, sourcetype
index=main "194.8.74.23" "Failed password" | stats count by host | sort -count
```
**Result:** 313 events mention the IP in total; 132 are failed logins.

| Host | Failed logins |
|---|---:|
| www1 | 62 |
| mailsv | 45 |
| www3 | 19 |
| www2 | 6 |
| **Total** | **132** |

**Meaning:** The investigated IP generated failed SSH login events against four servers. The activity was not limited to a single host, making it more suspicious than an isolated failed login.

### Step 4: Which usernames did it try?
**Query:**
```
index=main "194.8.74.23" "Failed password"
| rex "Failed password for (invalid user )?(?<username>\S+)"
| stats count by username
| sort -count
```
**Result:** The query returned 74 distinct usernames across 132 failed SSH login events. The visible results included local (6 attempts), system (6), irc (5), games (4), nagios (4) and root (4).

**Meaning:** The source IP attempted multiple account names, including root. This pattern is consistent with automated username and password guessing.

### Step 5: Were the usernames real accounts?
**Query:** Same extraction, with `eval account_type=if(match(_raw,"Failed password for invalid user"),"Invalid username","Potentially valid username")`.
**Result:** 16 usernames were not marked "invalid user" (for example `root`, `nagios`, `games`, `mail`). TODO: list the full set from your Splunk table.
**Meaning:** The IP tried names that look like real system accounts. The log wording alone doesn't prove those accounts exist.

### Step 6: Did this IP ever succeed?
**Query:** `index=main sourcetype=secure-2 "194.8.74.23"
("Accepted password" OR "Accepted publickey")
| table _time host _raw`

**Result:** 0 successful SSH login events found for 194.8.74.23 in the searched dataset.

**Meaning:** No successful SSH login from this IP was identified in the logs reviewed. This does not rule out other access methods or activity outside the dataset.

### Step 7: Who else is failing, and did anyone succeed?

**Query:** index=main sourcetype=secure-2
| eval failed=if(searchmatch("Failed password"),1,0)
| eval accepted=if(searchmatch("Accepted password") OR searchmatch("Accepted publickey"),1,0)
| rex field=_raw "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3}) port"
| stats sum(failed) as failed_logins sum(accepted) as successful_logins by src_ip
| where failed_logins >= 10
| sort -failed_logins

**Result:** Three source IPs had at least 10 failed SSH login attempts and also recorded successful SSH logins:
| Source IP | Failed logins | Successful logins |
| ---|---|--- |
| 10.3.10.46 | 121 | 955 |
| 10.2.10.163 | 47 | 478 |
| 10.1.10.172 | 16 | 166 |

**Meaning:** These three internal IP addresses had both failed and successful SSH authentication events. Their activity requires further review to determine whether the logins were legitimate. The presence of successful logins alone does not establish malicious activity.

### Step 8: What else does this IP do?
**Query:** `index=main "194.8.74.23" | stats count by sourcetype source host | sort -count`
**Result:** TODO: breakdown of the 313 events by sourcetype.
**Meaning:** TODO: after reading the raw non-SSH events (for example the web logs), say whether they look like normal browsing or probing.

### Step 9: Timing
**Query:** `index=main "194.8.74.23" "Failed password" | timechart span=5m count`
**Result:** TODO: first and last timestamp, and the shape of the chart.
**Meaning:** TODO: if all events share nearly one timestamp, I cannot state a rate or duration.

### Step 10: Did targeted accounts log in successfully?
**Query:** index=main sourcetype=secure-2 ("Accepted password" OR "Accepted publickey")
| rex field=_raw "Accepted (?:password|publickey) for (?<username>\S+)"
| search [
    search index=main sourcetype=secure-2 "194.8.74.23" "Failed password"
    | rex field=_raw "Failed password for (?:invalid user )?(?<username>\S+)"
    | dedup username
    | fields username
]
| table _time host username _raw

**Result:** 0 successful SSH login events were found for the usernames targeted by 194.8.74.23 in the searched dataset.

**Meaning:** No successful SSH authentication was identified for the targeted usernames in the searched logs. This does not rule out other access methods or activity outside the dataset.

### Step 11: Threat intelligence
**Indicator:** `194[.]8[.]74[.]23` in VirusTotal.

**Result:** No vendor flagged it as malicious on TODO: [date].

**Meaning:** This does not clear the IP. Many attacker IPs have no detections. I kept the IP as suspicious based on its behaviour in the logs.

## 4. Analysis

- **Observation:** 132 failed SSH logins from one IP across four servers; TODO: [N] usernames, including `root`; no successful login from this IP.
- **Interpretation:** This fits automated credential guessing from an external source.
- **Alternatives considered:** A scanner or a security test could produce the same pattern. I can't rule that out from logs alone, but it doesn't change the response, because unauthorised guessing against a root account still warrants a block.
- **What I cannot tell:** Whether the successful SSH logins from the three internal IPs were legitimate or authorised.


## 5. Verdict

**True Positive (TP).** The detection rule identified repeated failed SSH login activity from `194[.]8[.]74[.]23` across four servers. The activity is consistent with automated credential guessing. No successful login from this IP was observed in the logs reviewed. This does not establish that a server was compromised.

## 6. Severity

**Medium.** The source IP generated repeated failed SSH login attempts across four servers and targeted usernames including `root`. No successful login from this IP was observed in the logs reviewed. Further investigation is recommended.

## 7. Escalation Decision

**Escalate to L2.** The investigated IP generated repeated failed SSH attempts across four servers. Additionally, three other internal IPs with repeated failed attempts also recorded successful logins. L2 should review those successful sessions and determine whether the activity was authorised.

## 8. Recommendations

**Immediate:** review all successful logins on the affected servers; consider blocking the source IP through the organisation's change process; keep the authentication logs.
**Longer term:** restrict SSH to trusted networks; disable direct root login; use key-based authentication; add rate limiting such as Fail2ban; alert on repeated failures.

## 9. MITRE ATT&CK

**Tactic:** Credential Access. **Technique:** T1110 Brute Force. The sub-technique can't be confirmed, because the logs don't show the passwords used. Reference: https://attack.mitre.org/techniques/T1110/

## 10. Limitations

- Static, fictional training data, so results don't represent a live environment.
- A missing successful login from this IP doesn't rule out other compromise paths.
- Account existence wasn't verified.
- TODO: timestamp limitation, if check C of the earlier checks confirms it.
- VirusTotal results reflect the lookup date only.