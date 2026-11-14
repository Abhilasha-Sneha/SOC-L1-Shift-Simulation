# Incident Response Report – ALERT-003

## 1. Incident Details

| Field | Details |
|---|---|
| Incident ID | ALERT-003 |
| Incident Name | Suspicious PayPal Account Verification Email |
| Category | Phishing / Email Security |
| Analyst Role | SOC L1 Analyst – Simulation |
| Evidence Source | `phishing_sample.eml` |
| Investigation Date | 13 November 2026 |
| Sample Timestamp | 19 July 2026, 18:20:05 |
| Environment | Controlled phishing training sample |
| Initial Assessment | Suspicious phishing indicators identified |
| Final Assessment | Suspicious – phishing indicators present |
| Recommended Priority | Medium for a comparable real-world incident |
| Escalation | SOC L2 review recommended for a comparable real-world incident |

## 2. Executive Summary

A PayPal-themed email was examined as part of a simulated SOC L1 phishing investigation.

The message claimed that unusual activity had been detected on the recipient's PayPal account and requested account verification within 24 hours. The investigation identified multiple suspicious indicators, including a mismatched sender domain, a separate Reply-To domain, failed SPF/DKIM/DMARC authentication results, urgency-based wording and a suspicious account-verification URL.

The email also contained a PDF attachment named `Invoice_Statement.pdf`. The supplied structural inspection information identified a JavaScript action displaying a training message.

The sample is explicitly identified as a controlled training exercise. The investigation did not establish recipient interaction, credential theft or account compromise.

## 3. Key Findings

1. The display name claimed to be PayPal Security, but the sender domain was `yznphish.com`.
2. The Reply-To address used the separate domain `paypal-account-help.ru`.
3. SPF, DKIM and DMARC all reported failure.
4. The email used urgency and threatened account suspension to pressure the recipient.
5. The plain-text and HTML bodies contained different URL hostnames.
6. The HTML URL used the reserved `.invalid` domain.
7. The attached PDF contained placeholder text and a JavaScript action displaying a training message.
8. The IP addresses in the sample belonged to documentation/test ranges.
9. No evidence established that a recipient clicked the link, submitted credentials or experienced account compromise.

## 4. Impact Assessment

The available evidence does not show that a recipient clicked the link, submitted credentials, opened or executed the attachment, or experienced account compromise.

The sample is explicitly labelled as a controlled training exercise. Therefore, no real-world victim impact can be established.

The investigation did not include recipient mailbox, endpoint, proxy or authentication logs. As a result, it cannot determine whether similar messages reached other users or whether any recipient interacted with a comparable email.

## 5. Indicators of Compromise / Investigation Indicators

The following indicators were recorded from the supplied training sample. They should not be treated as confirmed indicators of a real-world attack.

| Type | Value |
|---|---|
| Display Name | PayPal Security |
| Sender | `security@yznphish.com` |
| Reply-To | `recovery-support@paypal-account-help.ru` |
| Return-Path | `bounce@mkt7.yznphish.com` |
| Plain-text URL | `hxxps://yznphish[.]com/secure/login?ref=8834211` |
| HTML URL | `https://yznphish.example.invalid/secure/login?ref=8834211` |
| Attachment | `Invoice_Statement.pdf` |
| IP addresses | `192.0.2.201`, `203.0.113.77`, `198.51.100.12` |
| SPF | Fail |
| DKIM | Fail |
| DMARC | Fail |

**Indicator note:** The listed IP addresses belong to documentation/test ranges. The HTML hostname uses the reserved `.invalid` domain. These values are included to document the sample, not to identify real attacker infrastructure.

## 6. Actions Performed by SOC L1

- Preserved the original email sample.
- Reviewed the sender, Reply-To and Return-Path fields.
- Inspected the supplied Received headers.
- Reviewed SPF, DKIM and DMARC authentication results.
- Examined the email wording for social-engineering indicators.
- Recorded the plain-text and HTML URL differences.
- Reviewed the supplied attachment information.
- Documented the evidence, assessment and limitations.

No links were visited, no attachment was executed and no credentials were submitted.

No production containment or remediation action was performed. No email quarantine, sender blocking, account disabling, credential reset or session revocation was carried out.

## 7. Recommended SOC Actions

For a comparable real-world email:

- Search the email gateway for other messages with matching sender details, subject lines and URL indicators.
- Identify all recipients of matching messages.
- Check whether recipients clicked the link or submitted credentials.
- Review relevant proxy, endpoint and authentication logs.
- Examine the attachment using approved malware-analysis tools in an isolated environment.
- Quarantine or remove matching messages where appropriate.
- Block confirmed malicious sender domains and URLs according to organisational policy.
- Recommend credential resets and session revocation if credential exposure is confirmed.
- Escalate for further investigation if additional evidence indicates compromise.

## 8. Final Verdict

**Assessment:** Suspicious – phishing indicators present.

**Environment:** Controlled training sample.

**Confirmed Compromise:** Not established by the available evidence.

**Recommended Priority:** Medium for a comparable real-world incident, subject to organisational alert rules.

**Escalation Recommendation:** SOC L2 review is recommended for a comparable real-world incident to investigate possible recipient exposure and related activity.

**Final Disposition:** The sample is documented as a suspicious phishing-style email in a controlled training environment. The available evidence does not establish a real-world attack or recipient compromise.

## 9. Investigation References

- Alert details: [`alert_03.md`](../alerts/alert_03.md)
- Investigation findings: [`investigation_03.md`](../investigations/investigation_03.md)
- Escalation request: [`escalation_03.md`](../escalation/escalation_03.md)
- Original email: `phishing_sample.eml`

Supporting screenshots can be stored in the `screenshots/` directory.

## 10. Limitations

- The email is explicitly identified as a controlled training sample.
- The IP addresses belong to documentation/test ranges.
- The HTML URL uses the reserved `.invalid` domain.
- No live URL was visited, and no redirect chain was verified.
- The attachment was not opened or executed.
- Attachment findings are based on the supplied structural inspection information.
- No recipient mailbox, endpoint, proxy or authentication logs were supplied.
- No evidence establishes successful credential theft or account compromise.
- The investigation does not establish whether any real recipient received or interacted with a similar email.

**Report Conclusion:** The supplied email contains multiple phishing indicators and is appropriately classified as suspicious. This report documents a controlled training investigation and does not claim a confirmed real-world incident or successful compromise.