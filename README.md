# 🛡️ PhishGuard SOC — AI-Powered Email Security Platform

> **Hackathon Project** | Cybersecurity Track | Built with Python, Flask, Gmail API & Claude AI

![PhishGuard](https://img.shields.io/badge/Status-Live-00ff88?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-00a8ff?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-00e5ff?style=for-the-badge&logo=flask)
![AI Powered](https://img.shields.io/badge/AI-Claude%20Sonnet-a78bfa?style=for-the-badge)

---

## 🎯 What is PhishGuard?

PhishGuard is a **real-time phishing detection system** that automatically scans your Gmail inbox, analyzes every email using an AI engine, and alerts you instantly when a threat is detected — just like the tools used by enterprise Security Operations Centers (SOCs).

Built for the hackathon in under 5 days, PhishGuard demonstrates how AI can make professional-grade cybersecurity tools accessible to everyday users.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔍 **Live Inbox Scanning** | Connects to Gmail and scans your latest emails automatically |
| 🤖 **AI Threat Analysis** | Claude AI acts as a SOC analyst — explains *why* an email is dangerous |
| 📊 **SOC Dashboard** | Real-time threat overview with risk scores, DEFCON level, and doughnut chart |
| 📧 **Auto Alert Emails** | Sends an HTML warning email the moment phishing is detected |
| 🔐 **Google OAuth** | Users connect Gmail securely — no passwords stored |
| 📎 **Manual Upload** | Paste raw email text or upload `.eml` files for instant analysis |
| 🎓 **Simulation Lab** | 4 interactive phishing scenarios to train cyber awareness |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  PhishGuard SOC                     │
├─────────────────┬───────────────────────────────────┤
│   Frontend      │   Flask Templates (Jinja2)        │
│   (HTML/CSS/JS) │   Tailwind CSS + Chart.js         │
├─────────────────┼───────────────────────────────────┤
│   Backend       │   Flask (Python)                  │
│                 │   Google OAuth 2.0 + Gmail API    │
│                 │   IMAP fallback                   │
├─────────────────┼───────────────────────────────────┤
│   AI Engine     │   Stage 1: Rule-based pre-filter  │
│  (2-stage)      │   Stage 2: Claude AI deep analysis│
├─────────────────┼───────────────────────────────────┤
│   Alerts        │   Gmail SMTP — HTML email alerts  │
└─────────────────┴───────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Clone and install

```bash
git clone https://github.com/yourusername/phishguard
cd phishguard
pip install -r requirements.txt
```

### 2. Set up environment variables

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

```env
# Gmail IMAP (for fallback scanning)
EMAIL_USER=your_gmail@gmail.com
EMAIL_PASS=your_16_char_app_password    # From myaccount.google.com/apppasswords

# Claude AI Engine (optional — falls back to rule-based if empty)
ANTHROPIC_API_KEY=sk-ant-...            # From console.anthropic.com

# Google OAuth (for Connect Gmail feature)
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret

# Flask
FLASK_SECRET=any-random-string
```

### 3. Run

```bash
python app.py
```

Open `http://127.0.0.1:5000` 🚀

---

## 📁 Project Structure

```
phishguard/
├── app.py                  # Flask routes & OAuth flow
├── email_scanner.py        # AI engine + Gmail/IMAP fetcher + alerts
├── requirements.txt
├── .env.example
└── templates/
    ├── dashboard.html      # Main SOC dashboard
    ├── upload.html         # Manual email upload/paste
    ├── connect_google.html # OAuth consent page
    └── simulation.html     # Phishing simulation lab
```

---

## 🧠 How the AI Engine Works

PhishGuard uses a **2-stage pipeline** for every email:

```
Email Input
    │
    ▼
┌─────────────────────────────┐
│  Stage 1: Rule-Based Filter │  ← Fast, free, always runs
│  • Keyword detection        │
│  • Domain reputation check  │
│  • Lookalike domain scanner │
│  • URL analysis             │
│  • Brand mismatch detection │
└─────────────┬───────────────┘
              │ Pre-score + reasons
              ▼
┌─────────────────────────────┐
│  Stage 2: Claude AI Engine  │  ← Deep analysis, SOC-level reasoning
│  • Contextual understanding │
│  • Natural language verdict │
│  • Specific indicators list │
│  • Actionable recommendation│
└─────────────┬───────────────┘
              │
              ▼
        Risk Score (0-100)
        Verdict + Explanation
        Auto-alert if score ≥ 70
```

---

## 🎓 Phishing Simulation Lab

4 interactive training scenarios modeled after real-world attacks:

- 🏦 **Bank Account Alert** — Classic suspension scam (Easy)
- 💻 **Microsoft Security Alert** — Typosquatted domain attack (Medium)
- 📦 **Package Delivery Failed** — Fake courier fee harvest (Medium)
- 💼 **Dream Job Offer** — Employment scam (Hard)

Users hover over red-highlighted text to reveal hidden attack indicators — teaching them to recognize phishing patterns before real attackers exploit them.

---

## 🔒 Security & Privacy

- OAuth tokens are **session-only** and never written to disk
- Emails are analyzed in memory and **never stored**
- PhishGuard requests **read-only** Gmail access — cannot send, delete, or modify
- IMAP app passwords are used instead of real account passwords

---

## 🏆 Why PhishGuard Stands Out

1. **Real AI** — Not just keyword matching. Claude understands context like a human analyst
2. **Real inbox integration** — Actually connects to Gmail via OAuth, not a demo with fake data
3. **Full alert pipeline** — Detects threat → sends warning email → user is protected
4. **Education layer** — Simulation mode teaches users, not just protects them
5. **Production-ready architecture** — 2-stage AI pipeline mirrors real enterprise SOC tools (Proofpoint, Darktrace)

---

## 👥 Team

Built with ❤️ for Cybernation Hackathon — March 2025

---

## 📄 License

MIT License — free to use and modify