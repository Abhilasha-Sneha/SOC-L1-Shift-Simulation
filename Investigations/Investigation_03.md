# Investigation 03 – PayPal-Themed Phishing Email

## 1. Investigation Details

| Field | Details |
|---|---|
| Investigation ID | ALERT-003 |
| Investigation Type | Phishing Email Analysis |
| Analyst Role | SOC L1 Analyst – Simulation |
| Sample | phishing_sample.eml |
| Status | Analysis completed; findings documented |

## 2. Objective

The objective is to inspect the suspicious email, identify phishing indicators, review the email headers, examine the URL and attachment information, and determine whether the message should be treated as suspicious.

The investigation is limited to the supplied training sample. No live links or attachments were opened.

## 3. Email Header Analysis

### 3.1 Sender Information

| Header | Value | Observation |
|---|---|---|
| From | PayPal Security <security@yznphish.com> | Display name claims to be PayPal, but sender domain is different |
| Reply-To | recovery-support@paypal-account-help.ru | Uses a different domain from the From address |
| Return-Path | bounce@mkt7.yznphish.com | Uses a subdomain of yznphish.com |
| To | victim@example-corp.com | Example recipient address |
| Subject | Urgent: Your Account Has Been Limited - Verify Now | Creates urgency |
| Date | 19 July 2026, 18:20:05 | Timestamp recorded in the sample |

**Observation:** The display name impersonates PayPal, while the actual sender address uses `yznphish.com`. The Reply-To address uses another domain, `paypal-account-help.ru`.

**Interpretation:** These inconsistencies are suspicious and may be intended to make the recipient trust the message while directing replies elsewhere.

### 3.2 Received Headers and IP Addresses

The email contains three `Received` entries.

| IP Address | Where It Appears | Observation |
|---|---|---|
| 192.0.2.201 | First Received entry and X-Originating-IP | Documented as the originating host address |
| 203.0.113.77 | Second Received entry and Authentication-Results | Identified as the sender IP for SPF evaluation |
| 198.51.100.12 | Third Received entry | Appears in the receiving mail-server chain |

**Important:** These IP addresses belong to documentation/test ranges. They are not ordinary public Internet addresses that can be used to identify a real sender.

The sample contains multiple Received entries, but the supplied headers alone do not establish a trustworthy real-world mail route.

### 3.3 Email Authentication

The `Authentication-Results` header reports:

| Authentication | Result | Meaning |
|---|---|---|
| SPF | Fail | The sending IP was not authorised by the sender domain's SPF policy |
| DKIM | Fail | The DKIM signature did not verify |
| DMARC | Fail | The message failed the domain's DMARC evaluation |

**Interpretation:** All three authentication checks failed in the supplied sample. This supports the suspicious assessment, although authentication failures alone do not prove phishing.

## 4. Email Content Analysis

The plain-text body contains these statements:

- "We have detected unusual activity on your PayPal account."
- "Your account access has been LIMITED."
- The recipient must verify within 24 hours.
- Failure to verify may result in permanent loss of funds.

**Observations:**

- The email uses fear and urgency.
- It threatens account suspension and loss of funds.
- It asks the recipient to verify account information through a link.
- It claims to represent PayPal without using a matching sender domain.

**Interpretation:** These are common social-engineering techniques used to pressure recipients into taking action without carefully checking the message.

## 5. URL Analysis

### URL found in the plain-text body

`hxxps://yznphish[.]com/secure/login?ref=8834211`

This URL is defanged in the sample. Do not convert it into a clickable link or visit it.

### URL found in the HTML body

`https://yznphish.example.invalid/secure/login?ref=8834211`

**Observation:** The plain-text and HTML versions contain different hostnames.

**Interpretation:** This inconsistency should be recorded. The `.invalid` hostname is reserved for invalid example use and is not a live destination.

No live website, redirect chain or credential-harvesting page was verified.

## 6. Attachment Analysis

| Field | Details |
|---|---|
| File Name | Invoice_Statement.pdf |
| File Type | PDF |
| Content | Placeholder invoice text |
| Visible Information | "INVOICE - Statement of Account" and a harmless training message |
| JavaScript Action | Contains an `app.alert()` message identifying it as a safe training file |

**Observation:** The PDF contains very little visible information. Its internal structure includes a JavaScript action that displays a training message.

**Interpretation:** The JavaScript action is worth documenting, but the supplied code does not demonstrate credential theft or malicious execution. The PDF is explicitly labelled as a harmless training sample.

The attachment was not opened or executed during this investigation.

## 7. Evidence Assessment

| Evidence | Observation | Significance |
|---|---|---|
| Sender domain | Does not match PayPal | Suspicious |
| Reply-To domain | Different from sender domain | Suspicious |
| SPF | Fail | Suspicious |
| DKIM | Fail | Suspicious |
| DMARC | Fail | Suspicious |
| Email wording | Urgency and account suspension threat | Phishing indicator |
| URL | Defanged training URL | Suspicious link pattern |
| PDF | Minimal placeholder content with a training JavaScript action | Limited attachment evidence |

## 8. MITRE ATT&CK Reference

Potential technique mapping for the behaviour represented by the sample:

- **T1566.002 – Spearphishing Link:** The email attempts to direct the recipient to an account-verification URL.
- **T1566.001 – Spearphishing Attachment:** The email includes a PDF attachment.

These are potential technique references for the simulated scenario, not confirmation that an actual attack occurred.

## 9. Investigation Limitations

- The email is explicitly identified as a controlled training sample.
- The IP addresses are documentation/test addresses.
- The URLs are defanged or use a reserved `.invalid` domain.
- No live URL was visited.
- The attachment was not executed.
- No recipient mailbox, endpoint or authentication logs were supplied.
- No evidence establishes successful credential theft or account compromise.

## 10. Investigation Conclusion

The email contains multiple phishing indicators, including PayPal brand impersonation, sender and Reply-To inconsistencies, failed SPF/DKIM/DMARC checks, urgency-based wording and a suspicious verification-link pattern.

The attachment provides limited additional evidence and is explicitly presented as a training file.

**Final Assessment:** Suspicious phishing-style email in a controlled training environment.

**Compromise Status:** Not established by the available evidence.

**Recommended Action:** Document the indicators and escalate for further review in a real SOC environment, following the organisation's email-security procedures.