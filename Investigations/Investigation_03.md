# Investigation 03 – PayPal-Themed Phishing Email

## 1. Summary

A suspicious email claiming to be from PayPal Security was investigated using a controlled phishing training sample.

The email stated that unusual activity had been detected on the recipient's account and requested account verification within 24 hours. The investigation identified multiple suspicious indicators, including a mismatched sender domain, a separate Reply-To domain, failed SPF/DKIM/DMARC authentication results, urgency-based wording and a suspicious verification URL.

The email also contained a PDF attachment named `Invoice_Statement.pdf`. The supplied structural inspection information identified a JavaScript action displaying a training message.

The investigation was limited to the supplied email sample. No live links were visited, and the attachment was not executed.

## 2. Scope

| Field | Details |
|---|---|
| Investigation ID | ALERT-003 |
| Alert Name | Suspicious PayPal Account Verification Email |
| Investigation Type | Phishing Email Analysis |
| Analyst Role | SOC L1 Analyst – Simulation |
| Sample | `phishing_sample.eml` |
| Investigation Date | 13 November 2026 |
| Sample Timestamp | 19 July 2026, 18:20:05 |
| Environment | Controlled training sample |
| Status | Analysis completed; findings documented |

## 3. Investigation Steps

### Step 1 – Review the Email

The email was reviewed to identify its claimed sender, subject, message content and suspicious characteristics.

| Field | Value |
|---|---|
| Display Name | PayPal Security |
| From | `security@yznphish.com` |
| Reply-To | `recovery-support@paypal-account-help.ru` |
| Return-Path | `bounce@mkt7.yznphish.com` |
| To | `victim@example-corp.com` |
| Subject | Urgent: Your Account Has Been Limited - Verify Now |
| Date | 19 July 2026, 18:20:05 |

**Observation:** The display name claims to represent PayPal, but the actual sender address uses `yznphish.com`. The Reply-To address uses a separate domain, `paypal-account-help.ru`.

**Analysis:** These inconsistencies are suspicious. They may be intended to make the recipient trust the message while directing replies to a different address.

### Step 2 – Inspect the Received Headers

The sample contains three `Received` entries.

| IP Address | Where It Appears | Observation |
|---|---|---|
| `192.0.2.201` | First Received entry and X-Originating-IP | Documented as the originating host address |
| `203.0.113.77` | Second Received entry and Authentication-Results | Identified as the sender IP for SPF evaluation |
| `198.51.100.12` | Third Received entry | Appears in the receiving mail-server chain |

**Important:** These addresses belong to documentation/test IP ranges. They are reserved for examples and documentation and should not be treated as real attacker infrastructure.

The supplied headers do not establish a trustworthy real-world mail route.

### Step 3 – Review Email Authentication

The `Authentication-Results` header reports the following:

| Authentication Check | Result | Meaning |
|---|---|---|
| SPF | Fail | The sending IP was not authorised by the sender domain's SPF policy |
| DKIM | Fail | The DKIM signature did not verify |
| DMARC | Fail | The message failed the domain's DMARC evaluation |

**Analysis:** All three authentication checks failed in the supplied sample. This supports the suspicious assessment, although authentication failures alone do not prove that an email is malicious.

### Step 4 – Analyse the Email Content

The plain-text body contains statements including:

- "We have detected unusual activity on your PayPal account."
- "Your account access has been LIMITED."
- The recipient must verify within 24 hours.
- Failure to verify may result in permanent loss of funds.

**Observations:**

- The email creates urgency.
- It threatens account suspension and loss of funds.
- It asks the recipient to verify account information through a link.
- It claims to represent PayPal without using a matching sender domain.

**Analysis:** These are common social-engineering techniques used to pressure recipients into acting quickly without carefully checking the message.

### Step 5 – Inspect the URLs

**Plain-text URL:**

`hxxps://yznphish[.]com/secure/login?ref=8834211`

**HTML URL:**

`https://yznphish.example.invalid/secure/login?ref=8834211`

**Observations:**

- The plain-text and HTML versions contain different hostnames.
- The plain-text URL uses `yznphish.com`, which does not match the claimed PayPal identity.
- The HTML URL uses the reserved `.invalid` domain.

**Analysis:** The hostname mismatch is suspicious and should be documented. The `.invalid` hostname is reserved for invalid example use and is not a live destination.

No live website, redirect chain or credential-harvesting page was verified. Neither URL was visited.

### Step 6 – Review the Attachment Information

| Field | Details |
|---|---|
| File Name | `Invoice_Statement.pdf` |
| File Type | PDF |
| Content | Placeholder invoice text |
| Visible Information | "INVOICE - Statement of Account" and a harmless training message |
| JavaScript Action | Contains an `app.alert()` message identifying it as a safe training file |

**Observation:** The supplied structural inspection information indicates that the PDF contains minimal placeholder content and a JavaScript action that displays a training message.

**Analysis:** The JavaScript action is worth documenting, but the supplied information does not demonstrate credential theft or malicious execution. The attachment is identified as a harmless training sample.

The attachment was not opened or executed during this investigation.

### Step 7 – Record the Evidence

The following indicators were documented:

| Evidence | Observation | Significance |
|---|---|---|
| Sender domain | Does not match PayPal | Suspicious |
| Reply-To domain | Different from sender domain | Suspicious |
| SPF | Fail | Suspicious |
| DKIM | Fail | Suspicious |
| DMARC | Fail | Suspicious |
| Email wording | Urgency and account suspension threat | Phishing indicator |
| Plain-text URL | Uses a domain unrelated to PayPal | Suspicious |
| HTML URL | Uses reserved `.invalid` domain | Training/sample indicator |
| PDF attachment | Placeholder content and training JavaScript action | Limited attachment evidence |
| IP addresses | Documentation/test ranges | Not usable as real attacker infrastructure |

### Step 8 – Assess the Findings

The sender and Reply-To inconsistencies, failed authentication results, urgency-based wording and suspicious URL pattern collectively support a phishing-style classification.

However, the sample is explicitly identified as a controlled training email. The documentation/test IP addresses and reserved HTML hostname also limit the ability to draw conclusions about real-world infrastructure.

The attachment information provides limited additional evidence and does not establish malicious execution.

### Step 9 – Determine the Final Verdict

Based on the available evidence, the email should be classified as suspicious and treated as a phishing-style training sample.

The evidence does not establish that a recipient interacted with the email or experienced account compromise.

## 4. Evidence

| Evidence Item | Finding |
|---|---|
| Original email | `phishing_sample.eml` |
| Display name | PayPal Security |
| Sender | `security@yznphish.com` |
| Reply-To | `recovery-support@paypal-account-help.ru` |
| Return-Path | `bounce@mkt7.yznphish.com` |
| Authentication | SPF Fail, DKIM Fail, DMARC Fail |
| Plain-text URL | `hxxps://yznphish[.]com/secure/login?ref=8834211` |
| HTML URL | `https://yznphish.example.invalid/secure/login?ref=8834211` |
| Attachment | `Invoice_Statement.pdf` |
| IP addresses | `192.0.2.201`, `203.0.113.77`, `198.51.100.12` |

## 5. Analysis

The email uses PayPal branding to create trust while using sender and Reply-To domains that do not match the claimed organisation.

The failed SPF, DKIM and DMARC results provide additional reasons to treat the message cautiously. Its urgency-based language and account-suspension threat are consistent with common phishing techniques.

The plain-text and HTML URLs contain different hostnames. The attachment's supplied structural information identifies a JavaScript action that displays a training message, but does not establish malicious execution.

The sample is explicitly labelled as a controlled training exercise. Therefore, the findings support a suspicious phishing-style classification, not a confirmed real-world attack or account compromise.

## 6. Verdict

**Final Verdict:** Suspicious – phishing indicators present.

**Reason:** Multiple indicators support the suspicious classification, including brand impersonation, sender inconsistencies, failed email authentication, urgency-based wording and a suspicious verification URL.

**Compromise Status:** Not established by the available evidence.

## 7. Severity

| Severity | Assessment |
|---|---|
| Initial Priority | To be determined by organisational alert rules |
| Final Assessment | Medium – analyst recommendation for a comparable real-world email |

**Reason:** The email contains multiple phishing indicators and could expose recipients to credential theft if it were a real malicious message. However, no recipient interaction or compromise is established in this training sample.

The severity is an analyst recommendation, not a priority value supplied by the sample.

## 8. Escalation Decision

**Recommended Decision:** Escalate for SOC L2 review in a comparable real-world environment.

**Reason:** Further investigation would be required to determine whether similar messages reached other users, whether any recipient interacted with the email and whether related activity appears in email gateway, proxy, endpoint or authentication logs.

This is a simulated escalation recommendation. No actual SOC L2 handoff or production response action was performed.

## 9. Recommendations

For a comparable real-world incident:

- Search the email gateway for matching sender details, subject lines and URL indicators.
- Identify all recipients of matching messages.
- Check whether recipients clicked the link or submitted credentials.
- Review proxy, endpoint and authentication logs for related activity.
- Analyse the attachment using approved tools in an isolated environment.
- Quarantine or remove matching emails where appropriate.
- Recommend credential resets and session revocation if credential exposure is confirmed.
- Follow organisational procedures for blocking confirmed malicious indicators.

## 10. MITRE ATT&CK

Potential technique mapping for the behaviour represented by the sample:

| Technique | Name | Relevance |
|---|---|---|
| T1566.002 | Spearphishing Link | The email attempts to direct the recipient to an account-verification URL |
| T1566.001 | Spearphishing Attachment | The email includes a PDF attachment |

These are potential technique references for the simulated scenario, not confirmation that an actual attack occurred.

## 11. Limitations

- The email is explicitly identified as a controlled training sample.
- The IP addresses belong to documentation/test ranges.
- The HTML URL uses the reserved `.invalid` domain.
- The URLs were not visited.
- No live website or redirect chain was verified.
- The attachment was not opened or executed.
- The attachment findings are based on the supplied structural inspection information.
- No recipient mailbox, endpoint or authentication logs were supplied.
- No evidence establishes successful credential theft or account compromise.
- The investigation does not establish whether any real recipient received or interacted with a similar email.

**Final Investigation Conclusion:** The supplied email contains multiple phishing indicators and should be treated as suspicious. The evidence supports documenting the sample as a phishing-style training case, but does not establish a real-world attack or recipient compromise.