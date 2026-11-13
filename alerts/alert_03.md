# SOC-ALERT-03: Suspicious PayPal Account Verification Email

## 1. Alert Overview

| Field | Details |
|---|---|
| Alert ID | SOC-ALERT-03 |
| Alert Name | Suspicious PayPal Account Verification Email |
| Category | Phishing / Email Security |
| Source | Controlled phishing training sample |
| Priority | To be determined by the organisation's alert rules |
| Status | Under investigation |
| Initial Assessment | Suspicious phishing indicators identified |

## 2. Alert Description

An email claiming to be from PayPal Security was received with the subject:

**Urgent: Your Account Has Been Limited - Verify Now**

The email tells the recipient that unusual activity has been detected and that their account access has been limited. It asks the recipient to verify their account within 24 hours to avoid permanent suspension.

The message contains a suspicious sender domain, a different Reply-To domain, failed email authentication checks, and a defanged verification link.

## 3. Key Indicators

| Indicator | Observed Value |
|---|---|
| Display Name | PayPal Security |
| From | security@yznphish.com |
| Reply-To | recovery-support@paypal-account-help.ru |
| Return-Path | bounce@mkt7.yznphish.com |
| Subject | Urgent: Your Account Has Been Limited - Verify Now |
| Sending IP in Authentication Results | 203.0.113.77 |
| X-Originating-IP | 192.0.2.201 |
| Suspicious URL in plain-text body | hxxps://yznphish[.]com/secure/login?ref=8834211 |
| Attachment | Invoice_Statement.pdf |

## 4. Initial Observations

- The sender uses a domain that does not match the PayPal brand.
- The Reply-To address uses a separate domain.
- SPF, DKIM and DMARC authentication results all show failure.
- The email uses urgency and a threat of account suspension to pressure the recipient.
- The message includes a suspicious account-verification link.
- A PDF attachment is included.

## 5. Initial Assessment

The email contains several indicators commonly associated with phishing, including brand impersonation, sender inconsistencies, failed authentication checks and urgency-based language.

The sample is explicitly labelled as a controlled lab/training email. Its indicators should therefore be treated as training evidence, not proof of a real-world attack.

## 6. Initial L1 Action

- Preserve the original email for analysis.
- Do not click the link.
- Do not open the attachment.
- Inspect the email headers and authentication results.
- Record the sender, Reply-To, Return-Path and URL as indicators.
- Continue investigation before assigning a final verdict.

## 7. Initial Verdict

**Suspicious – phishing indicators present.**

No evidence in this sample establishes successful credential theft, account compromise or execution on a recipient's device.

## 8. Evidence

- `../phishing_sample.eml`
- Screenshots to be added in `../screenshots/`