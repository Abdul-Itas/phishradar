import imaplib
import email
import json
import os
import re
from email.header import decode_header

from groq import Groq
from dotenv import load_dotenv

load_dotenv()

USERNAME    = os.getenv("EMAIL_USER")
PASSWORD    = os.getenv("EMAIL_PASS")
IMAP_SERVER = "imap.gmail.com"

# Instantiate the Groq client once (reads GROQ_API_KEY from env)
_groq_client = None

def get_groq_client():
    global _groq_client
    if _groq_client is None:
        api_key = os.getenv("GROQ_API_KEY")
        if api_key:
            _groq_client = Groq(api_key=api_key)
    return _groq_client


# ══════════════════════════════════════════════════════════════════
#  TRUSTED DOMAINS & FREE PROVIDERS  (used by keyword fallback)
# ══════════════════════════════════════════════════════════════════

TRUSTED_DOMAINS = [
    "google.com", "gmail.com", "microsoft.com", "outlook.com",
    "apple.com", "amazon.com", "paypal.com", "github.com",
    "linkedin.com", "twitter.com", "facebook.com", "instagram.com",
    "netflix.com", "spotify.com", "dropbox.com", "slack.com",
    "zoom.us", "stripe.com", "shopify.com",
]

FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "icloud.com", "live.com",
    "ymail.com", "mail.com", "gmx.com",
]


# ══════════════════════════════════════════════════════════════════
#  SHARED HELPERS
# ══════════════════════════════════════════════════════════════════

def extract_domain(sender: str) -> str:
    match = re.search(r'@([\w.\-]+)', sender)
    return match.group(1).lower() if match else ""


def is_trusted_domain(domain: str) -> bool:
    return any(domain == t or domain.endswith("." + t) for t in TRUSTED_DOMAINS)


def check_lookalike_domain(domain: str) -> str | None:
    BRAND_PATTERNS = {
        "paypal": "PayPal", "google": "Google", "amazon": "Amazon",
        "microsoft": "Microsoft", "apple": "Apple", "netflix": "Netflix",
        "facebook": "Facebook", "instagram": "Instagram",
        "linkedin": "LinkedIn", "twitter": "Twitter", "github": "GitHub",
    }
    normalised = (domain
        .replace("0","o").replace("1","l").replace("3","e")
        .replace("4","a").replace("5","s")
    )
    domain_name = normalised.split(".")[0]
    for key, name in BRAND_PATTERNS.items():
        if domain_name == key and not is_trusted_domain(domain):
            return name
        if key in domain_name and not is_trusted_domain(domain):
            return name
    return None


# ══════════════════════════════════════════════════════════════════
#  ENGINE 1 — GROQ AI ANALYSIS
# ══════════════════════════════════════════════════════════════════

AI_SYSTEM_PROMPT = """You are phishradar, an expert cybersecurity AI specializing in
phishing email detection. You analyze emails with the precision of a senior SOC analyst.

When given an email's subject, sender, and body, you must respond with ONLY a valid
JSON object — no preamble, no markdown fences, no explanation outside the JSON.

The JSON must have exactly these fields:
{
  "risk_score": <integer 0-100>,
  "status": <"SAFE" | "SUSPICIOUS" | "PHISHING DETECTED">,
  "explanation": <one clear sentence summarizing the verdict>,
  "red_flags": [<list of short strings, each a specific red flag found, empty list if none>],
  "engine": "groq-ai"
}

Scoring guide:
- 0-39:  SAFE — no meaningful indicators of phishing
- 40-69: SUSPICIOUS — some indicators but not conclusive
- 70-100: PHISHING DETECTED — strong evidence of phishing attempt

CRITICAL RULES — read carefully before scoring:
1. Personal emails between individuals (friend-to-friend, family, colleagues) sent from
   Gmail, Yahoo, Outlook etc. are NORMAL and should score 0-20 (SAFE). Using a free
   email provider is NOT a red flag for personal communication.
2. Only flag free providers as suspicious when they are IMPERSONATING a company or
   brand (e.g. paypal-support@gmail.com claiming to be PayPal).
3. A plain conversation email with no urgency, no links, no credential requests = SAFE.
4. Do NOT penalise emails just because they come from Gmail or similar providers.

Key signals to look for (only flag when clearly present):
- Sender impersonating a brand from a non-brand domain (e.g. amazon-security@gmail.com)
- Urgency / fear / threat language: "account suspended", "verify within 24 hours"
- Generic greetings combined with financial requests: "Dear Customer, click here to pay"
- Shortened or obfuscated URLs (bit.ly, tinyurl, suspicious redirects)
- Requests for passwords, PINs, card numbers, or personal data via email
- Typosquatted domains: micros0ft.com, paypa1.com, arnazon.com

Be conservative. When in doubt, score lower. A false positive (flagging a safe email)
is worse than a false negative for user trust. Only output PHISHING DETECTED when
there is strong, clear evidence of an attack."""


def analyze_with_groq(subject: str, sender: str, body: str) -> tuple[int, str, str, str]:
    """
    Calls the Groq API to analyze the email.
    Returns (risk_score, status, explanation, engine_label).
    Raises an exception if the API call fails so caller can fallback.
    """
    client = get_groq_client()
    if client is None:
        raise ValueError("GROQ_API_KEY not set")

    # Truncate body to keep token usage reasonable
    body_preview = body[:1500] if body else "(empty body)"

    user_message = f"""Analyze this email for phishing:

SENDER: {sender}
SUBJECT: {subject}
BODY:
{body_preview}"""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[
            {"role": "system", "content": AI_SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
        temperature=0.1,
        max_tokens=512,
    )

    raw = response.choices[0].message.content.strip()

    # Strip markdown fences if the model included them
    raw = re.sub(r'^```(?:json)?\s*', '', raw)
    raw = re.sub(r'\s*```$', '', raw)

    data = json.loads(raw)

    score       = max(0, min(100, int(data.get("risk_score", 0))))
    status      = data.get("status", "SAFE")
    explanation = data.get("explanation", "No explanation provided.")
    red_flags   = data.get("red_flags", [])

    # Append red flags to explanation so dashboard shows them
    if red_flags:
        flags_str = " | ".join(red_flags)
        explanation = f"{explanation} — Red flags: {flags_str}"

    return score, status, explanation, "groq-ai"


# ══════════════════════════════════════════════════════════════════
#  ENGINE 2 — KEYWORD FALLBACK
# ══════════════════════════════════════════════════════════════════

def analyze_with_keywords(subject: str, sender: str, body: str) -> tuple[int, str, str, str]:
    subject_lower = str(subject).lower()
    sender_lower  = str(sender).lower()
    body_lower    = str(body).lower()

    risk_score = 0
    reasons    = []

    sender_domain = extract_domain(sender_lower)
    trusted       = is_trusted_domain(sender_domain)

    PHISHING_KEYWORDS = [
        "urgent","verify","suspended","password","invoice",
        "action required","important update","account locked",
        "confirm your","limited time","unusual sign",
        "unauthorized access","your account has been",
    ]
    matched = [w for w in PHISHING_KEYWORDS if w in subject_lower]
    if matched:
        penalty = 20 if trusted else 40
        risk_score += penalty
        reasons.append(f"Subject keyword(s): {', '.join(repr(k) for k in matched[:3])}")

    IMPERSONATION_WORDS = ["support","security","admin","noreply","alert","helpdesk"]
    if any(w in sender_lower for w in IMPERSONATION_WORDS) and not trusted:
        # Only penalise if the body also mentions a brand — pure impersonation signal
        body_mentions_brand = any(b in body_lower for b in ["paypal","amazon","microsoft","apple","google","bank","account"])
        if any(fp in sender_domain for fp in FREE_EMAIL_PROVIDERS) and body_mentions_brand:
            risk_score += 45
            reasons.append(f"Authority name + free email provider impersonating a brand ({sender_domain})")
        elif not any(fp in sender_domain for fp in FREE_EMAIL_PROVIDERS):
            risk_score += 25
            reasons.append(f"Authority-implying sender from unverified domain: {sender_domain}")

    brand = check_lookalike_domain(sender_domain)
    if brand:
        risk_score += 60
        reasons.append(f"Lookalike domain impersonating {brand}")

    if any(g in body_lower for g in ["dear customer","dear user","dear account holder"]):
        risk_score += 20
        reasons.append("Generic greeting instead of real name")

    THREAT_PHRASES = ["will be suspended","will be terminated","immediately",
                      "within 24 hours","within 48 hours","failure to"]
    if any(p in body_lower for p in THREAT_PHRASES):
        risk_score += 25
        reasons.append("Urgency / threat language in body")

    links = re.findall(r'https?://\S+', body_lower)
    if links:
        if any(s in body_lower for s in ["bit.ly","tinyurl.com","goo.gl","ow.ly"]):
            risk_score += 45
            reasons.append("Shortened/hidden URLs detected")
        elif len(links) >= 3:
            risk_score += 20
            reasons.append(f"{len(links)} links found in body")
        else:
            risk_score += 8
            reasons.append(f"{len(links)} link(s) found")

    for bk in ["paypal","google","amazon","microsoft","apple","netflix"]:
        if bk in body_lower and bk not in sender_domain and not trusted:
            risk_score += 15
            reasons.append(f"Body mentions '{bk.capitalize()}' but sender domain doesn't match")
            break

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        status = "PHISHING DETECTED"
    elif risk_score >= 40:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"
        if not reasons:
            reasons.append("No suspicious indicators found.")

    return risk_score, status, " | ".join(reasons), "keyword-engine"


# ══════════════════════════════════════════════════════════════════
#  PUBLIC API — single entry point for app.py
# ══════════════════════════════════════════════════════════════════

# Module-level flag — set to True after first API failure to skip future calls
_groq_disabled = False

def analyze_email(subject: str, sender: str, body: str) -> tuple[int, str, str, str]:
    """
    Tries Groq AI first; falls back to keyword engine if unavailable.
    Once an auth/quota error occurs, skips Groq for the rest of the session.
    Returns (risk_score, status, explanation, engine_used).
    """
    global _groq_disabled

    # Skip Groq entirely if no key or already failed this session
    if _groq_disabled or not os.getenv("GROQ_API_KEY"):
        return analyze_with_keywords(subject, sender, body)

    try:
        return analyze_with_groq(subject, sender, body)
    except Exception as e:
        err_str = str(e)
        # Rate limit (429) — wait briefly and fall back for this call only
        if '429' in err_str or 'rate_limit' in err_str.lower():
            print(f"[phishradar] Groq rate limit — using keyword engine for this email.")
            return analyze_with_keywords(subject, sender, body)
        # Auth/key errors — permanently disable for session (no point retrying)
        elif any(x in err_str.lower() for x in ['401', '403', 'api_key', 'invalid']):
            _groq_disabled = True
            print(f"[phishradar] Groq disabled for this session ({e}) — using keyword engine.")
        else:
            print(f"[phishradar] Groq API error ({e}), using keyword engine.")
        return analyze_with_keywords(subject, sender, body)


# ══════════════════════════════════════════════════════════════════
#  EMAIL ALERT NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════

def send_phishing_alert(threat_email: dict, alert_recipient: str = None) -> bool:
    """
    Sends a warning email when a phishing threat is detected.
    Uses Gmail SMTP with the same credentials as IMAP.
    Returns True if sent successfully.
    """
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    smtp_user = os.getenv("EMAIL_USER")
    smtp_pass = os.getenv("EMAIL_PASS")
    recipient  = alert_recipient or smtp_user

    if not smtp_user or not smtp_pass:
        print("[phishradar] Alert skipped — EMAIL_USER/EMAIL_PASS not set")
        return False

    try:
        subject_line = f"⚠ phishradar Alert: Phishing Detected — {threat_email.get('subject', 'Unknown')[:50]}"

        html_body = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0a0f1e;color:#e8f0fe;margin:0;padding:0;}}
  .wrapper{{max-width:600px;margin:0 auto;padding:32px 16px;}}
  .card{{background:#0d1b2e;border:1px solid #1a3a6e;border-radius:12px;overflow:hidden;}}
  .hdr{{background:linear-gradient(135deg,#1a0a0a,#2d0f0f);padding:28px 32px;border-bottom:2px solid #ff2d55;}}
  .hdr h1{{margin:0;font-size:22px;color:#ff2d55;letter-spacing:1px;}}
  .hdr p{{margin:6px 0 0;font-size:13px;color:#7a8fad;}}
  .body{{padding:28px 32px;}}
  .score{{display:inline-block;background:rgba(255,45,85,.15);border:2px solid #ff2d55;border-radius:50px;padding:8px 20px;font-size:28px;font-weight:bold;color:#ff2d55;margin-bottom:20px;}}
  .row{{padding:10px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:14px;}}
  .lbl{{color:#7a8fad;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:3px;}}
  .box{{background:rgba(255,45,85,.06);border-left:3px solid #ff2d55;border-radius:6px;padding:14px 16px;margin:20px 0;font-size:13px;color:#7a8fad;line-height:1.7;}}
  .btn{{display:block;text-align:center;background:#ff2d55;color:white;text-decoration:none;padding:14px 24px;border-radius:8px;font-weight:bold;font-size:14px;letter-spacing:1px;margin-top:24px;}}
  .foot{{padding:20px 32px;background:rgba(0,0,0,.2);font-size:11px;color:#4a5568;text-align:center;}}
</style></head><body>
<div class="wrapper"><div class="card">
  <div class="hdr"><h1>⚠ PHISHING THREAT DETECTED</h1><p>phishradar Security Operations Center — Automated Alert</p></div>
  <div class="body">
    <div class="score">Risk Score: {threat_email.get('risk_score', 0)}%</div>
    <div class="row"><div class="lbl">Malicious Sender</div>{threat_email.get('sender','Unknown')}</div>
    <div class="row"><div class="lbl">Email Subject</div>{threat_email.get('subject','Unknown')}</div>
    <div class="row"><div class="lbl">Threat Status</div><span style="color:#ff2d55;font-weight:bold;">{threat_email.get('status','PHISHING DETECTED')}</span></div>
    <div class="box"><strong style="color:#ff2d55;">Analysis:</strong><br>{threat_email.get('explanation','Suspicious indicators detected.').replace(' | ','<br>› ')}</div>
    <p style="font-size:13px;color:#7a8fad;line-height:1.7;">
      <strong style="color:#e8f0fe;">Recommended Actions:</strong><br>
      → Do NOT click any links in this email<br>
      → Do NOT download any attachments<br>
      → Do NOT reply or provide any personal information<br>
      → Mark the email as spam and delete it immediately
    </p>
    <a href="http://127.0.0.1:5000" class="btn">VIEW FULL SOC DASHBOARD</a>
  </div>
  <div class="foot">Automated security alert from phishradar SOC</div>
</div></div></body></html>"""

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject_line
        msg['From']    = f"phishradar SOC <{smtp_user}>"
        msg['To']      = recipient
        msg.attach(MIMEText(html_body, 'html'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, recipient, msg.as_string())

        print(f"[phishradar] Alert sent to {recipient} for: {threat_email.get('subject','')[:40]}")
        return True

    except Exception as e:
        print(f"[phishradar] Alert send failed: {e}")
        return False


# ══════════════════════════════════════════════════════════════════
#  IMAP FETCHER
# ══════════════════════════════════════════════════════════════════

def fetch_latest_emails(limit: int = 5) -> list[dict] | None:
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(USERNAME, PASSWORD)
        mail.select("inbox")

        status, messages = mail.search(None, "ALL")
        email_ids = messages[0].split()
        latest_ids = list(reversed(email_ids[-limit:]))

        email_data_list = []

        for e_id in latest_ids:
            res, msg_data = mail.fetch(e_id, "(RFC822)")
            for response_part in msg_data:
                if not isinstance(response_part, tuple):
                    continue

                msg = email.message_from_bytes(response_part[1])

                raw_subject, encoding = decode_header(msg["Subject"])[0]
                subject = (
                    raw_subject.decode(encoding or "utf-8", errors="replace")
                    if isinstance(raw_subject, bytes) else (raw_subject or "(No Subject)")
                )
                sender = msg.get("From", "Unknown Sender")

                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            try:
                                body = part.get_payload(decode=True).decode(errors="replace")
                                break
                            except Exception:
                                pass
                else:
                    try:
                        body = msg.get_payload(decode=True).decode(errors="replace")
                    except Exception:
                        pass

                score, threat_status, explanation, engine = analyze_email(subject, sender, body)

                email_entry = {
                    "msg_id":      str(e_id.decode()),
                    "subject":     subject,
                    "sender":      sender,
                    "status":      threat_status,
                    "risk_score":  score,
                    "explanation": explanation,
                    "engine":      engine,
                }
                email_data_list.append(email_entry)

        mail.logout()
        return email_data_list

    except Exception as e:
        print(f"[phishradar] IMAP error: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  GMAIL API — fetch emails using OAuth token (no IMAP / no .env password)
# ══════════════════════════════════════════════════════════════════════════════

def fetch_emails_with_token(token_info: dict, limit: int = 5):
    """
    Fetches emails using a Google OAuth token stored in the Flask session.
    Uses the Gmail API instead of IMAP — no EMAIL_USER / EMAIL_PASS needed.
    Returns same list-of-dicts format as fetch_latest_emails().
    """
    try:
        import google.oauth2.credentials
        import googleapiclient.discovery
        import base64

        credentials = google.oauth2.credentials.Credentials(
            token=token_info['token'],
            refresh_token=token_info.get('refresh_token'),
            token_uri=token_info.get('token_uri', 'https://oauth2.googleapis.com/token'),
            client_id=token_info.get('client_id'),
            client_secret=token_info.get('client_secret'),
            scopes=token_info.get('scopes', []),
        )

        service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)

        result = service.users().messages().list(
            userId='me',
            labelIds=['INBOX'],
            maxResults=limit,
        ).execute()

        messages = result.get('messages', [])
        print(f"[phishradar] Gmail API found {len(messages)} messages in inbox")
        email_data_list = []

        for msg_ref in messages:
            msg = service.users().messages().get(
                userId='me',
                id=msg_ref['id'],
                format='full',
            ).execute()

            headers = {h['name']: h['value'] for h in msg['payload'].get('headers', [])}
            subject = headers.get('Subject', '(No Subject)')
            sender  = headers.get('From', 'Unknown Sender')

            # Recursively extract plain text body
            def extract_body(part):
                if part.get('mimeType') == 'text/plain':
                    data = part.get('body', {}).get('data', '')
                    if data:
                        return base64.urlsafe_b64decode(data + '==').decode('utf-8', errors='replace')
                if 'parts' in part:
                    for subpart in part['parts']:
                        found = extract_body(subpart)
                        if found:
                            return found
                return ""

            body = extract_body(msg.get('payload', {}))

            score, threat_status, explanation, engine = analyze_email(subject, sender, body)

            email_entry = {
                "msg_id":      msg_ref['id'],
                "subject":     subject,
                "sender":      sender,
                "status":      threat_status,
                "risk_score":  score,
                "explanation": explanation,
                "engine":      engine,
                "ai_powered":  bool(os.getenv("ANTHROPIC_API_KEY")),
            }
            email_data_list.append(email_entry)

        return email_data_list

    except Exception as e:
        import traceback
        print(f"[phishradar] Gmail API error: {e}")
        traceback.print_exc()
        return None