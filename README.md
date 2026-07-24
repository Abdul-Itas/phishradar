# 🛡️ PhishRadar — Africa Threat Intelligence Platform

> **AI-Powered Phishing Detection & SOC Platform** | Built with Python, Flask, Gmail API & Groq AI

![Status](https://img.shields.io/badge/Status-Live-00ff88?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-00a8ff?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-00e5ff?style=for-the-badge&logo=flask)
![AI Powered](https://img.shields.io/badge/AI-Groq%20LLaMA-a78bfa?style=for-the-badge)
![Africa](https://img.shields.io/badge/Focus-Africa%20Threat%20Intel-ff2d55?style=for-the-badge)

---

## 🎯 What is PhishRadar?

PhishRadar is a **real-time phishing detection and threat intelligence platform** purpose-built for African users. It automatically scans Gmail inboxes, analyzes emails using AI, detects African-specific phishing patterns (BVN fraud, CBN impersonation, Nigerian bank scams), and provides a public threat intelligence API — just like tools used by enterprise Security Operations Centers (SOCs).

🔗 **Live Demo:** https://phishradar.onrender.com
💻 **Africa IOC Repository:** https://github.com/Abdul-Itas/Africa-Phishing-IOCs
📖 **API Documentation:** https://phishradar.onrender.com/api/docs

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔍 **Live Inbox Scanning** | Connects to Gmail via OAuth and scans latest emails automatically |
| 🤖 **AI Threat Analysis** | Groq LLaMA acts as a SOC analyst — explains *why* an email is dangerous |
| 🌍 **Africa Threat Intelligence** | Dedicated detection for Nigerian banks, fintechs, BVN/NIN fraud, CBN/EFCC impersonation |
| 📊 **SOC Dashboard** | Real-time threat overview with risk scores, DEFCON level, and doughnut chart |
| 🚨 **Community Submission Portal** | Anyone can report suspicious URLs — submissions feed the public IOC database |
| 🔌 **Public Threat Intelligence API** | Free API for querying phishing IOCs — no authentication required |
| 📈 **Weekly African Phishing Report** | Auto-generated summary of threats detected each week |
| 📧 **Auto Alert Emails** | Sends HTML warning email the moment phishing is detected |
| 🔐 **Google OAuth** | Users connect Gmail securely — no passwords stored |
| 📎 **Manual Upload** | Paste raw email text or upload `.eml` files for instant analysis |
| 🎓 **Simulation Lab** | 4 interactive phishing scenarios to train cyber awareness |

---

## 🌍 Africa Threat Intelligence

PhishRadar includes dedicated detection for threats targeting African users:

- 🏦 **30+ Nigerian & African Banks** — GTBank, Zenith, Access, First Bank, UBA, FCMB, Ecobank
- 💳 **African Fintechs** — OPay, PalmPay, Kuda, Flutterwave, Paystack, Moniepoint
- 🏛️ **Government Impersonation** — CBN, EFCC, FIRS, NIMC, NCC
- 📱 **Telco Scams** — MTN, Airtel, Glo, 9mobile prize fraud
- 🆔 **BVN/NIN Fraud** — Bank Verification Number and NIN update scams
- 💰 **419 Advance Fee Fraud** — Inheritance, next-of-kin, lottery scams

### Africa Phishing IOC Repository
Community-driven database of confirmed African phishing indicators:
👉 https://github.com/Abdul-Itas/Africa-Phishing-IOCs

---

## 🔌 Public Threat Intelligence API

Free, no authentication required:

```bash
# Check a URL or domain
curl "https://phishradar.onrender.com/api/check?url=cbn-nigeria-verify.com"

# Get community IOC feed
curl "https://phishradar.onrender.com/api/iocs"

# Get threat feed metadata
curl "https://phishradar.onrender.com/api/feed"
```

**Example Response:**
```json
{
  "query": "cbn-nigeria-verify.com",
  "threat_detected": true,
  "risk_score": 100,
  "verdict": "PHISHING",
  "flags": [
    "African brand impersonation: Central Bank of Nigeria (cbn.gov.ng)",
    "Known African phishing domain pattern",
    "Credential-harvesting keywords: verify, bvn"
  ],
  "powered_by": "PhishRadar Africa Threat Intelligence"
}
```

Full API docs: https://phishradar.onrender.com/api/docs

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    PhishRadar SOC                       │
├─────────────────┬───────────────────────────────────────┤
│   Frontend      │   Flask Templates (Jinja2)            │
│                 │   Tailwind CSS + Chart.js             │
├─────────────────┼───────────────────────────────────────┤
│   Backend       │   Flask (Python)                      │
│                 │   Google OAuth 2.0 + Gmail API        │
│                 │   IMAP fallback                       │
├─────────────────┼───────────────────────────────────────┤
│   AI Engine     │   Stage 1: Africa Threat Signatures   │
│  (2-stage)      │   Stage 2: Groq LLaMA deep analysis  │
├─────────────────┼───────────────────────────────────────┤
│   Threat Intel  │   Public API (/api/check, /api/iocs)  │
│                 │   Community submission portal          │
│                 │   Weekly phishing report               │
├─────────────────┼───────────────────────────────────────┤
│   Alerts        │   Gmail SMTP — HTML email alerts      │
└─────────────────┴───────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Clone and install

```bash
git clone https://github.com/Abdul-Itas/phishradar
cd phishradar
pip install -r requirements.txt
```

### 2. Set up environment variables

```bash
cp .env.example .env
```

```env
EMAIL_USER=your_gmail@gmail.com
EMAIL_PASS=your_16_char_app_password
GROQ_API_KEY=your_groq_api_key
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret
FLASK_SECRET=any-random-string
BASE_URL=https://your-deployed-url.com
```

### 3. Run

```bash
python app.py
```

Open `http://127.0.0.1:5000` 🚀

---

## 📁 Project Structure

```
phishradar/
├── app.py                        # Flask routes, OAuth flow, API endpoints
├── email_scanner.py              # AI engine + Gmail/IMAP fetcher + alerts
├── africa_threat_signatures.py   # Africa-specific phishing signatures
├── report_generator.py           # PDF threat report generator
├── ioc_submissions.json          # Community IOC database
├── requirements.txt
└── templates/
    ├── dashboard.html            # Main SOC dashboard
    ├── upload.html               # Manual email upload/paste
    ├── connect_google.html       # OAuth consent page
    ├── simulation.html           # Phishing simulation lab
    ├── report_threat.html        # Community threat submission portal
    ├── weekly_report.html        # Weekly African phishing report
    └── api_docs.html             # API documentation
```

---

## 🧠 How the AI Engine Works

```
Email Input
    │
    ▼
┌─────────────────────────────────┐
│  Stage 1: Africa Threat Engine  │  ← Always runs first
│  • BVN/NIN fraud patterns       │
│  • Nigerian bank signatures     │
│  • CBN/EFCC impersonation       │
│  • Fintech & telco detection    │
│  • 419 advance fee patterns     │
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│  Stage 2: Groq AI Engine        │  ← Deep contextual analysis
│  • LLaMA 3.1 SOC-level reasoning│
│  • Natural language verdict     │
│  • Specific red flags list      │
│  • Africa-aware prompt system   │
└─────────────┬───────────────────┘
              │
              ▼
        Risk Score (0-100)
        Verdict + Explanation
        Auto-alert if score ≥ 70
        IOC logged if submitted
```

---

## 🔒 Security & Privacy

- OAuth tokens are **session-only** and never written to disk
- Emails are analyzed in memory and **never stored**
- PhishRadar requests **read-only** Gmail access
- Community IOC submissions are anonymized before storage

---

## 🤝 Contributing

Found a phishing domain targeting African users?

1. Submit via the portal: https://phishradar.onrender.com/report-threat
2. Or contribute to the IOC repo: https://github.com/Abdul-Itas/Africa-Phishing-IOCs

---

## 👤 Author

Built by **Abdulmajid Imam**
- GitHub: https://github.com/Abdul-Itas
- LinkedIn: https://linkedin.com/in/abdulmajid-imam
- Live: https://phishradar.onrender.com

---

## 📄 License

MIT License — free to use, share, and build upon with attribution.

⭐ Star this repo to support Africa-focused cybersecurity research!