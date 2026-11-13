# Escalation Request – SOC-ALERT-01

## 1. Escalation Details

| Field | Details |
|---|---|
| Alert ID | SOC-ALERT-01 |
| Alert Name | Suspicious PayPal Account Verification Email |
| Escalation From | SOC L1 Analyst – Simulation |
| Escalation To | SOC L2 Analyst |
| Category | Phishing / Email Security |
| Priority | To be determined according to organisational policy |
| Status | Escalation recommended – simulated handoff |

## 2. Incident Summary

A suspicious email impersonating PayPal Security was identified during a simulated SOC L1 investigation.

The email claimed that the recipient's account had been limited due to unusual activity. It instructed the recipient to verify their account within 24 hours to avoid permanent suspension.

The investigation identified multiple phishing indicators, including a mismatched sender domain, a different Reply-To address, failed email authentication checks and a suspicious account-verification URL.

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

### Other Findings

- The email uses urgency and account-suspension threats to pressure the recipient.
- The plain-text and HTML bodies contain different URL hostnames.
- The PDF attachment contains minimal placeholder content and a JavaScript action displaying a training message.
- The IP addresses in the sample belong to documentation/test ranges.
- The sample explicitly identifies itself as a controlled training exercise.

## 4. Actions Completed by SOC L1

- Preserved the original `.eml` file.
- Reviewed the sender, Reply-To and Return-Path fields.
- Inspected the Received headers.
- Reviewed SPF, DKIM and DMARC results.
- Identified suspicious wording and URL indicators.
- Inspected the attachment's available structure without executing it.
- Documented the findings and limitations.

No links were clicked, no attachment was executed and no credentials were submitted.

## 5. Reason for Escalation

The email contains several indicators associated with phishing and brand impersonation.

The sender and Reply-To domains do not match the claimed PayPal identity. All three email authentication checks failed, and the message attempts to create urgency through a threat of account suspension.

In a real SOC environment, these findings would justify further review to determine whether similar emails reached other users and whether any recipient interacted with the message.

## 6. Requested SOC L2 Actions

The following actions are recommended for a comparable real-world incident:

1. Search the email gateway for other messages with matching sender details, subject or URL indicators.
2. Identify all recipients of matching emails.
3. Check whether any recipient clicked the link or submitted account credentials.
4. Review proxy, endpoint and authentication logs for related activity.
5. Examine the attachment using approved malware-analysis tools in an isolated environment.
6. Determine whether email quarantine or removal is required.
7. Recommend credential resets and session revocation if credential exposure is confirmed.

## 7. Evidence Provided

- `phishing_sample.eml`
- `alerts/alert_01.md`
- `investigations/investigation_01.md`
- `reports/incident_report.md`

Supporting screenshots are stored in the `screenshots/` directory.

## 8. SOC L1 Recommendation

**Recommended Decision:** Escalate for SOC L2 review in a real-world environment.

**Reason:** Multiple phishing indicators are present and further investigation would be required to establish recipient exposure or possible compromise.

**Current Assessment:** Suspicious phishing-style email.

**Confirmed Compromise:** Not established.

