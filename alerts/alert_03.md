# ALERT-003: Suspicious PayPal Account Verification Email

## Alert Summary

| Field | Details |
|---|---|
| Alert ID | SOC-ALERT-003 |
| Alert Name | Suspicious PayPal Account Verification Email |
| Category | Phishing / Email Security |
| Source | Controlled phishing training sample |
| Priority | To be determined according to organisational alert rules |
| Status | Investigation completed |
| Initial Assessment | Suspicious phishing indicators identified |
| Dataset / Evidence | `phishing_sample.eml` |

## Alert Description

An email claiming to be from PayPal Security was identified with the subject:

**Urgent: Your Account Has Been Limited - Verify Now**

The email claims that unusual activity has been detected and that the recipient's account access has been limited. It asks the recipient to verify their account within 24 hours to avoid permanent suspension.

The message contains several suspicious indicators, including a sender domain that does not match the claimed brand, a different Reply-To domain, failed SPF/DKIM/DMARC authentication results, a suspicious verification URL and a PDF attachment.

The sample is explicitly identified as a controlled phishing training email.

## Key Indicators

| Indicator | Observed Value |
|---|---|
| Display Name | PayPal Security |
| From | `security@yznphish.com` |
| Reply-To | `recovery-support@paypal-account-help.ru` |
| Return-Path | `bounce@mkt7.yznphish.com` |
| Subject | Urgent: Your Account Has Been Limited - Verify Now |
| Sending IP in Authentication Results | `203.0.113.77` |
| X-Originating-IP | `192.0.2.201` |
| Plain-text URL | `hxxps://yznphish[.]com/secure/login?ref=8834211` |
| HTML URL | `https://yznphish.example.invalid/secure/login?ref=8834211` |
| Attachment | `Invoice_Statement.pdf` |

## Detection Logic

This alert is based on manual inspection of the supplied `.eml` training sample.

The following indicators support the suspicious classification:

- The display name claims to represent PayPal, but the sender domain does not match the brand.
- The Reply-To address uses a different domain from the sender address.
- SPF, DKIM and DMARC authentication results report failure.
- The email uses urgency and threatens account suspension.
- The message contains a verification URL with a hostname that does not match the claimed PayPal identity.
- A PDF attachment is included.

No automated email-gateway detection rule or live alert trigger was configured as part of this simulation.

## What the Detection Logic Identifies

The indicators above help an L1 analyst identify a potentially deceptive email that may be attempting to impersonate a trusted service.

The sender details, authentication results, message content, URL information and attachment characteristics should be reviewed together. No single indicator should be treated as conclusive proof of phishing.

## Alert Assessment

**Initial Classification:** Suspicious – phishing indicators present.

The sample contains multiple indicators associated with phishing and brand impersonation. However, it is explicitly labelled as a controlled training sample.

The available evidence does not establish that a recipient clicked the link, submitted credentials, opened or executed the attachment, or