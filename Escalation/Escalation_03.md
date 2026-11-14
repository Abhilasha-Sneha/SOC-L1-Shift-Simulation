# Escalation Request – ALERT-003

## 1. Escalation Details

| Field | Details |
|---|---|
| Alert ID | ALERT-003 |
| Alert Name | Suspicious PayPal Account Verification Email |
| Escalation From | SOC L1 Analyst – Simulation |
| Escalation To | SOC L2 Analyst |
| Category | Phishing / Email Security |
| Priority | Medium – recommended for a comparable real-world incident |
| Status | Escalation recommended – simulated handoff |
| Final L1 Assessment | Suspicious – phishing indicators present |

## 2. Incident Summary

A suspicious email impersonating PayPal Security was identified during a simulated SOC L1 investigation.

The email claimed that the recipient's account had been limited due to unusual activity. It instructed the recipient to verify the account within 24 hours to avoid permanent suspension.

The investigation identified multiple phishing indicators, including a mismatched sender domain, a different Reply-To address, failed SPF/DKIM/DMARC authentication results, urgency-based wording and a suspicious account-verification URL.

The email also contained a PDF attachment named `Invoice_Statement.pdf`. The supplied structural inspection information identified a JavaScript action displaying a training message.

## 3. Key Investigation Findings

### Sender Information

- Display Name: PayPal Security
- From: `security@yznphish.com`
- Reply-To: `recovery-support@paypal-account-help.ru`
- Return-Path: `bounce@mkt7.yznphish.com`

### Email Authentication

| Check | Result |
|---|---|
| SPF | Fail |
| DKIM | Fail |
| DMARC | Fail |

### URL and Attachment Findings

- The plain-text URL uses the hostname `yznphish.com`.
- The HTML URL uses the reserved `.invalid` domain.
- The two URL versions contain different hostnames.
- The PDF attachment contains placeholder invoice content and a JavaScript action displaying a training message.
- The attachment was not opened or executed.

### Additional Findings

- The email uses urgency and account-suspension threats to pressure the recipient.
- The IP addresses in the sample belong to documentation/test ranges.
- The sample explicitly identifies itself as a controlled training exercise.
- No evidence establishes recipient interaction or account compromise.

## 4. Actions Completed by SOC L1

- Preserved the original `.eml` sample for analysis.
- Reviewed the sender, Reply-To and Return-Path fields.
- Inspected the supplied Received headers.
- Reviewed SPF, DKIM and DMARC authentication results.
- Identified suspicious wording and URL indicators.
- Recorded the plain-text and HTML URL differences.
- Reviewed the supplied attachment information without executing the attachment.
- Documented the evidence, findings and investigation limitations.

No links were visited, no attachment was executed and no credentials were submitted.

No production email quarantine, sender blocking or account remediation was performed.

## 5. Reason for Escalation

The email contains multiple indicators associated with phishing and brand impersonation.

The sender and Reply-To domains do not match the claimed PayPal identity. All three email authentication checks failed, and the message uses urgency and account-suspension threats to pressure the recipient.

In a real SOC environment, these findings would justify further review to determine whether similar emails reached other users and whether any recipient interacted with the message.

The escalation is recommended for a comparable real-world incident. The current sample is a controlled training exercise, and no actual SOC L2 handoff was performed.

## 6. Requested SOC L2 Actions

The following actions are recommended for a comparable real-world incident:

1. Search the email gateway for other messages with matching sender details, subject or URL indicators.
2. Identify all recipients of matching emails.
3. Check whether any recipient clicked the link or submitted account credentials.
4. Review proxy, endpoint and authentication logs for related activity.
5. Examine the attachment using approved malware-analysis tools in an isolated environment.
6. Determine whether email quarantine or removal is required.
7. Recommend credential resets and session revocation if credential exposure is confirmed.
8. Follow organisational procedures for blocking confirmed malicious indicators.

## 7. Investigation Limitations

- The email is explicitly identified as a controlled training sample.
- The IP addresses belong to documentation/test ranges.
- The HTML URL uses the reserved `.invalid` domain.
- No live URL was visited.
- The attachment was not opened or executed.
- No recipient mailbox, endpoint or authentication logs were supplied.
- No evidence establishes successful credential theft or account compromise.

## 8. Evidence Provided

- `phishing_sample.eml`
- `../alerts/alert_03.md`
- `../investigations/investigation_03.md`

Supporting screenshots can be stored in the `screenshots/` directory.

## 9. SOC L1 Recommendation

**Recommended Decision:** Escalate for SOC L2 review in a comparable real-world environment.

**Reason:** Multiple phishing indicators are present, and further investigation would be required to establish recipient exposure or possible compromise.

**Current Assessment:** Suspicious – phishing indicators present.

**Confirmed Compromise:** Not established by the available evidence.

**Handoff Status:** Simulated escalation recommendation only. No actual SOC L2 handoff was performed.