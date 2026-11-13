# Incident Report – SOC-ALERT-01

## 1. Executive Summary

A PayPal-themed email was examined as part of a simulated SOC L1 phishing investigation.

The message claimed that the recipient's PayPal account had been limited and requested account verification within 24 hours. The investigation identified multiple suspicious indicators, including a mismatched sender domain, a separate Reply-To domain, failed SPF/DKIM/DMARC checks and an account-verification link.

The email also contained a PDF attachment. Its visible content was minimal, and its internal structure included a JavaScript action displaying a training message.

## 2. Key Findings

1. The display name claimed to be PayPal Security, but the sender domain was `yznphish.com`.
2. The Reply-To address used `paypal-account-help.ru`.
3. SPF, DKIM and DMARC all reported failure.
4. The email used urgency and threatened account suspension.
5. The plain-text and HTML bodies contained different URL hostnames.
6. The attached PDF contained placeholder text and a training JavaScript action.

## 3. Impact Assessment

The available evidence does not show that a recipient clicked the link, opened the attachment, submitted credentials or experienced account compromise.

The sample is explicitly labelled as a controlled training exercise. Therefore, no real-world victim impact can be established.

## 4. Indicators of Compromise / Investigation Indicators

| Type | Value |
|---|---|
| Sender | security@yznphish.com |
| Reply-To | recovery-support@paypal-account-help.ru |
| Return-Path | bounce@mkt7.yznphish.com |
| Plain-text URL | hxxps://yznphish[.]com/secure/login?ref=8834211 |
| HTML URL | https://yznphish.example.invalid/secure/login?ref=8834211 |
| Attachment | Invoice_Statement.pdf |
| IP addresses | 192.0.2.201, 203.0.113.77, 198.51.100.12 |



## 5. Recommended SOC Actions

For a comparable real-world email:

- Preserve the original email and headers.
- Search for other recipients who received the same message.
- Check whether anyone clicked the link or submitted credentials.
- Review relevant email gateway, proxy and endpoint logs.
- Block confirmed malicious sender domains and URLs according to organisational policy.
- Quarantine or remove matching messages where appropriate.
- Reset credentials and revoke sessions if credential exposure is confirmed.
- Escalate for further investigation if additional evidence indicates compromise.

## 6. Final Verdict

**Assessment:** Suspicious – phishing indicators present.

**Environment:** Controlled training sample.

**Confirmed Compromise:** No evidence available.

**Escalation Recommendation:** Suitable for SOC L2 review in a real-world scenario if the same indicators are found in production.

## 7. Evidence Files

- `phishing_sample.eml`
- `alerts/alert_01.md`
- `investigations/investigation_01.md`

Screenshots can be added to the `screenshots/` folder as the investigation progresses.