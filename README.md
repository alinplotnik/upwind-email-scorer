# 🏄 Upwind Email Scorer

A Gmail Add-on powered by AI and multiple security APIs that analyzes incoming emails for phishing, scams, and malware — in real time.

---

## 🌟 Overview

Upwind Email Scorer is a defense-in-depth email security tool that runs directly inside Gmail. When you open an email, it automatically scores it from **0 (Safe)** to **100 (Highly Suspicious)** using a combination of:

- **Local heuristic analysis** (keyword matching, domain checks, link analysis)
- **Google Safe Browsing API** (real-time threat database for links and domains)
- **VirusTotal API** (malware hash matching for email attachments)
- **RDAP domain age check** (flags newly registered phishing domains)
- **SPF / DKIM / DMARC header validation** (detects domain spoofing)
- **Gemini AI deep scan** (independent AI investigator for linguistic analysis)

---

## 🏗️ Architecture

```
Gmail Add-on (Google Apps Script)
        │
        │  POST (JSON payload)
        ▼
AWS Lambda (Python backend)
        │
        ├── Heuristic Engine
        ├── Google Safe Browsing API
        ├── VirusTotal API (attachment hashes)
        ├── RDAP Domain Age Check
        ├── SPF/DKIM/DMARC Header Analysis
        └── Gemini 2.5 Flash (optional AI deep scan)
```

### Key Files

| File | Purpose |
|------|---------|
| `addon/Code.gs` | Gmail Add-on UI, email data extraction, attachment hashing |
| `addon/appsscript.json` | Add-on manifest and OAuth scopes |
| `backend/lambda_function.py` | All scoring logic, API integrations, AI prompt |
| `backend/tests/` | Lambda test event JSON files |

---

## 🔍 Detection Engine

### 1. Sender Analysis
- **Brand impersonation detection** using a general domain-segment algorithm: checks if the brand name appears as a clean, standalone segment in the sender's domain (between dots). For example:
  - `mail.amazon.jobs` → `['mail', 'amazon', 'jobs']` → ✅ `amazon` is a clean segment → **Legit**
  - `paypal-security-update.com` → `['paypal-security-update', 'com']` → ❌ `paypal` is inside a hyphenated segment → **Flagged**
  - Covered brands: PayPal, Apple, Microsoft, Google, Amazon, Netflix, Facebook, Instagram, WhatsApp, LinkedIn, Twitter, Dropbox, DocuSign
  - **Penalty: +40 points**
- Flags free email providers (Gmail, Yahoo, etc.) used for official-sounding roles (e.g. "IT Support" sending from `@gmail.com`)
- Detects mismatches between display name and actual email domain

### 2. Security Header Analysis (SPF / DKIM / DMARC)
Reads the raw `Authentication-Results` email header to detect domain spoofing:
- `SPF fail` → sender IP not authorized to send for this domain
- `DKIM fail` → email signature is invalid or tampered
- `DMARC fail` → email fails the domain owner's own policy
- **Penalty: +40 points**

### 3. Domain Reputation (RDAP Age Check)
Queries the global RDAP registry to find when the sender's domain was registered:
- Domains less than 30 days old are flagged as likely phishing domains
- **Penalty: +60 points**
- No API key required (uses the public `rdap.org` endpoint)

### 4. Google Safe Browsing
All links and domains in the email are checked against Google's global threat database:
- Detects Malware and Social Engineering URLs
- **Penalty: +100 points**
- Requires: `SAFE_BROWSING_API_KEY`

### 5. Attachment Analysis

#### 5a. Dangerous File Extension Heuristics
Flags executable and script file types often used to distribute malware:
`.exe`, `.scr`, `.vbs`, `.bat`, `.cmd`, `.js`, `.wsf`, `.msi`, `.ps1`, `.jar`, `.lnk`, `.iso`, `.img`
- **Penalty: +50 points**

#### 5b. ZIP Extraction
ZIP files are **unpacked in memory** in the Google Apps Script layer (no files are uploaded):
- Inner files are inspected for dangerous extensions
- Password-protected ZIPs are flagged (**+40 points**) since they are a common malware delivery technique

#### 5c. VirusTotal Hash Check
SHA-256 hashes of attachments (and inner ZIP contents) are checked against VirusTotal's database:
- Only the cryptographic fingerprint is sent — the actual file never leaves your Gmail
- **Penalty: +100 points** if flagged as malicious
- Requires: `VIRUSTOTAL_API_KEY`

### 6. Deceptive Link Analysis
Parses the raw HTML of the email to detect link tricks:
- **URL mismatch**: link text shows `www.microsoft.com` but `href` points elsewhere → **+50 points**
- **Brand mismatch**: link text contains "Apple" but the URL is unrelated → **+40 points**
- **URL shorteners**: detects `t.co`, `bit.ly`, `tinyurl.com`, etc. → **+20 points**
- **Raw IP address links**: `href` pointing to `http://192.168.1.1/...` → **+45 points**

### 7. Multilingual Keyword Heuristics
Scans the email subject and body for suspicious patterns in **English and Hebrew**:

| Category | Examples | Penalty |
|----------|---------|---------|
| Urgency | "URGENT", "24 hours", "immediately", "דחוף", "מיידי" | +10 pts |
| Financial requests | "wire transfer", "bitcoin", "gift card", "העברה בנקאית" | +20–30 pts |
| Credential harvesting | "verify your account", "reset password", "אמת את החשבון" | +20 pts |
| Generic greetings | "Dear customer", "Dear user", "Dear member" | +10 pts |

### 8. AI Deep Scan (Gemini 2.5 Flash)
An optional on-demand scan triggered by the "Deep Scan with AI" button:
- The email is **scrubbed of PII** (phone numbers, credit card numbers, ID numbers) before sending
- The AI acts as an **independent investigator** — it receives only raw metadata and content, with no heuristic verdicts
- The AI provides its own risk score (out of 100) to cross-reference with the heuristic score
- The email's exact timestamp is included so the AI can assess dates accurately
- Requires: `GEMINI_API_KEY`

---

## 🔐 Privacy

- **No file uploads**: attachments are hashed locally using `Utilities.computeDigest()` in Google Apps Script. Only the SHA-256 fingerprints are sent.
- **PII scrubbing**: before sending content to the Gemini AI, all personal identifiers (phone numbers, credit card numbers, ID numbers, long numeric sequences) are automatically redacted and replaced with `[REDACTED]` placeholders.
- **Self-sent bypass**: emails sent to yourself are automatically marked as Safe and no external API calls are made.

---

## 📊 Scoring & Verdicts

| Score Range | Verdict |
|-------------|---------|
| 0–14 | ✅ Safe |
| 15–39 | 🟡 Slightly Suspicious |
| 40–69 | 🟠 Suspicious |
| 70–100 | 🔴 Highly Suspicious |

---

## ⚙️ Environment Variables (AWS Lambda)

| Variable | Required | Purpose |
|----------|----------|---------|
| `GEMINI_API_KEY` | ✅ Yes | Gemini AI deep scan |
| `SAFE_BROWSING_API_KEY` | Recommended | Google Safe Browsing (falls back to `GEMINI_API_KEY`) |
| `VIRUSTOTAL_API_KEY` | Recommended | Attachment malware hash lookup |

---

## 🧪 Testing

The `backend/tests/` directory contains ready-to-use Lambda test event JSON files.
Paste them directly into the **AWS Lambda → Test** tab.

| File | Tests |
|------|-------|
| `test_malicious_attachment.json` | `.exe` extension detection, urgency & financial keywords, generic greeting |
| `test_deceptive_link.json` | Deceptive link (display vs. href mismatch), raw IP address, free provider impersonation |
| `test_brand_impersonation.json` | PayPal brand impersonation, domain spoofing, login/credential keywords |

---

## 🚀 Deployment

### Backend (AWS Lambda)
1. Upload `backend/lambda_function.py` to your AWS Lambda function
2. Set the required environment variables in Lambda → Configuration → Environment Variables
3. Ensure the Lambda Function URL is enabled and accessible

### Gmail Add-on (Google Apps Script)
1. Open [script.google.com](https://script.google.com)
2. Copy the contents of `addon/Code.gs` and `addon/appsscript.json` into your project
3. Update the `awsLambdaUrl` constant in `Code.gs` with your Lambda Function URL
4. Deploy as a Gmail Add-on (Deploy → New Deployment → Gmail Add-on)
5. Install the add-on from your Gmail settings

---

## 🏄 Easter Egg

Emails from **Upwind** or sent via the **Comeet** HR platform receive a special `🏄‍♂️ UPWIND VIP 🏄‍♀️` verdict that bypasses all security checks. Clicking "Deep Scan with AI" on such an email reveals a surprise 😉
