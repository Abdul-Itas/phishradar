import os
import email as email_lib
from email.header import decode_header

from flask import Flask, render_template, request, redirect, url_for, session
from email_scanner import fetch_latest_emails, analyze_email, fetch_emails_with_token

app = Flask(__name__)

# OAuth environment flags — must be set before any OAuth flow runs
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allow HTTP in dev
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'  # Allow scope differences
app.secret_key = os.getenv("FLASK_SECRET", "phishguard-dev-secret")


# ─── Helper: parse raw email string into subject/sender/body ──────────────────
def parse_raw_email(raw: str) -> dict:
    msg = email_lib.message_from_string(raw)

    raw_subject, enc = decode_header(msg.get("Subject", "(No Subject)"))[0]
    if isinstance(raw_subject, bytes):
        subject = raw_subject.decode(enc or "utf-8", errors="replace")
    else:
        subject = raw_subject or "(No Subject)"

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
            body = msg.get_payload() or ""

    if not body:
        body = raw

    return {"subject": subject, "sender": sender, "body": body}


# ─── HOME — SOC Dashboard ─────────────────────────────────────────────────────
@app.route('/')
def dashboard():
    import time
    from flask import make_response
    from email_scanner import send_phishing_alert
    emails = []
    now = time.time()
    cache_ttl = 120  # 2 minutes

    cached = session.get('cached_emails')
    cached_time = session.get('cached_emails_time', 0)
    fresh = bool(cached and (now - cached_time) < cache_ttl)

    if fresh:
        print("[PhishGuard] Serving emails from cache")
        emails = cached
    elif 'google_token' in session:
        token_info = session['google_token']
        print(f"[PhishGuard] Token scopes: {token_info.get('scopes', 'NONE')}")
        print("[PhishGuard] Fetching emails via Google OAuth token...")
        emails = fetch_emails_with_token(token_info, limit=5) or []
        session['cached_emails'] = emails
        session['cached_emails_time'] = now
    else:
        print("[PhishGuard] Fetching emails via IMAP...")
        emails = fetch_latest_emails(limit=5) or []
        session['cached_emails'] = emails
        session['cached_emails_time'] = now

    # Send alerts only for new phishing emails not previously alerted
    if not fresh:
        alerted = set(session.get('alerted_ids', []))
        for em in emails:
            msg_id = em.get('msg_id') or em.get('subject', '')
            if em.get('risk_score', 0) >= 70 and msg_id not in alerted:
                send_phishing_alert(em)
                alerted.add(msg_id)
        session['alerted_ids'] = list(alerted)

    connected_email = session.get('user_email', None)
    resp = make_response(render_template('dashboard.html', emails=emails, connected_email=connected_email))
    resp.headers['Cache-Control'] = 'private, max-age=120'
    return resp


# ─── UPLOAD ───────────────────────────────────────────────────────────────────
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    result = None
    error = None

    if request.method == 'POST':
        raw_text = ""

        pasted = request.form.get('email_text', '').strip()
        if pasted:
            raw_text = pasted

        uploaded_file = request.files.get('eml_file')
        if uploaded_file and uploaded_file.filename:
            try:
                raw_text = uploaded_file.read().decode('utf-8', errors='replace')
            except Exception as e:
                error = f"Could not read uploaded file: {e}"

        if not raw_text and not error:
            error = "Please paste an email or upload a .eml file."

        if raw_text and not error:
            try:
                parsed = parse_raw_email(raw_text)
                score, status, explanation, engine = analyze_email(
                    parsed["subject"], parsed["sender"], parsed["body"]
                )
                result = {
                    "subject": parsed["subject"],
                    "sender": parsed["sender"],
                    "risk_score": score,
                    "status": status,
                    "explanation": explanation,
                    "engine": engine,
                }
            except Exception as e:
                error = f"Analysis failed: {e}"

    return render_template('upload.html', result=result, error=error)


# ─── CONNECT GOOGLE — Info / Consent page ────────────────────────────────────
@app.route('/connect-google')
def connect_google():
    status = request.args.get('status', None)
    return render_template('connect_google.html', status=status)


# ─── GOOGLE LOGIN — Start OAuth flow ─────────────────────────────────────────
@app.route('/google-login')
def google_login():
    from google_auth_oauthlib.flow import Flow

    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")

    if not client_id or not client_secret:
        return redirect(url_for('connect_google') + '?status=not_configured')

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=[
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid",
        ],
        redirect_uri='http://127.0.0.1:5000/google-callback',
    )

    # Generate PKCE code verifier and store in session
    import hashlib, base64, secrets
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode()

    auth_url, state = flow.authorization_url(
        prompt='consent',
        access_type='offline',
        include_granted_scopes='true',
        code_challenge=code_challenge,
        code_challenge_method='S256',
    )
    session['oauth_state'] = state
    session['code_verifier'] = code_verifier
    return redirect(auth_url)


# ─── GOOGLE CALLBACK — Handle return from Google ─────────────────────────────
@app.route('/google-callback')
def google_callback():
    from google_auth_oauthlib.flow import Flow
    import googleapiclient.discovery

    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=[
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid",
        ],
        redirect_uri='http://127.0.0.1:5000/google-callback',
        state=session.get('oauth_state'),
    )

    try:
        # Force http in the authorization response URL (fixes https mismatch in dev)
        auth_response = request.url.replace('https://', 'http://')
        # Pass code_verifier to satisfy PKCE check
        code_verifier = session.pop('code_verifier', None)
        flow.fetch_token(
            authorization_response=auth_response,
            code_verifier=code_verifier,
        )
        credentials = flow.credentials

        # Store token in session
        session['google_token'] = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": list(credentials.scopes) if credentials.scopes else [],
        }

        # Get user's Gmail address to show in dashboard
        service = googleapiclient.discovery.build(
            'oauth2', 'v2',
            credentials=credentials,
        )
        user_info = service.userinfo().get().execute()
        session['user_email'] = user_info.get('email', '')

        print(f"[PhishGuard] OAuth success for {session['user_email']}")

    except Exception as e:
        print(f"[PhishGuard] OAuth callback error: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('connect_google') + '?status=error')

    return redirect(url_for('dashboard'))


# ─── LOGOUT — Disconnect Google account ──────────────────────────────────────
@app.route('/logout')
def logout():
    session.pop('google_token', None)
    session.pop('user_email', None)
    session.pop('cached_emails', None)
    session.pop('cached_emails_time', None)
    session.pop('alerted_ids', None)
    return redirect(url_for('dashboard'))


# ─── PDF REPORT ──────────────────────────────────────────────────────────────
@app.route('/report')
def download_report():
    from flask import Response
    from report_generator import generate_report

    # Fetch latest emails same way dashboard does
    if 'google_token' in session:
        emails = fetch_emails_with_token(session['google_token'], limit=10) or []
    else:
        emails = fetch_latest_emails(limit=10) or []

    connected_email = session.get('user_email', None)
    pdf_bytes = generate_report(emails, connected_email)

    filename = f"phishguard_report_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        pdf_bytes,
        mimetype='application/pdf',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


# ─── URL SCANNER ──────────────────────────────────────────────────────────────
@app.route('/scan-url', methods=['POST'])
def scan_url():
    from flask import jsonify
    import urllib.request, urllib.parse, json, re

    # Handle both JSON body and form data
    try:
        data = request.get_json(force=True, silent=True) or {}
        url = data.get('url', '').strip()
    except Exception:
        url = request.form.get('url', '').strip()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Add http:// if missing so urlparse works
    if not url.startswith('http'):
        url = 'http://' + url

    results = {
        'url': url,
        'risk_score': 0,
        'flags': [],
        'final_url': url,
        'domain': '',
        'safe': True,
    }

    try:
        # 1. Parse domain
        parsed = urllib.parse.urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed.netloc.lower().replace('www.', '')
        results['domain'] = domain

        # 2. Check for URL shorteners — resolve real destination
        SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'rb.gy', 'short.link']
        if any(s in domain for s in SHORTENERS):
            results['flags'].append({
                'severity': 'HIGH',
                'message': f'URL shortener detected ({domain}) — real destination is hidden'
            })
            results['risk_score'] += 45
            # Try to resolve
            try:
                req = urllib.request.Request(url, method='HEAD', headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    results['final_url'] = resp.geturl()
                    results['flags'].append({
                        'severity': 'INFO',
                        'message': f'Resolved to: {results["final_url"]}'
                    })
            except Exception:
                results['flags'].append({
                    'severity': 'HIGH',
                    'message': 'Could not resolve shortened URL destination'
                })
                results['risk_score'] += 20

        # 3. Check Google Safe Browsing API (if key configured)
        gsb_key = os.getenv('GOOGLE_SAFE_BROWSING_KEY')
        if gsb_key:
            try:
                gsb_payload = json.dumps({
                    "client": {"clientId": "phishguard", "clientVersion": "2.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }).encode()
                req = urllib.request.Request(
                    f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}',
                    data=gsb_payload,
                    headers={'Content-Type': 'application/json'},
                    method='POST'
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    gsb_data = json.loads(resp.read())
                    if gsb_data.get('matches'):
                        results['risk_score'] += 80
                        results['flags'].append({
                            'severity': 'CRITICAL',
                            'message': 'CONFIRMED MALICIOUS by Google Safe Browsing database'
                        })
            except Exception as e:
                print(f'[PhishGuard] GSB check failed: {e}')

        # 4. Lookalike brand domain check
        BRANDS = ['paypal', 'google', 'amazon', 'microsoft', 'apple',
                  'netflix', 'facebook', 'instagram', 'linkedin', 'bankofamerica']
        normalised_domain = domain.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('4', 'a')
        domain_name = normalised_domain.split('.')[0]
        for brand in BRANDS:
            if brand in domain_name:
                LEGIT = {
                    'paypal': 'paypal.com', 'google': 'google.com',
                    'amazon': 'amazon.com', 'microsoft': 'microsoft.com',
                    'apple': 'apple.com', 'netflix': 'netflix.com',
                    'facebook': 'facebook.com', 'instagram': 'instagram.com',
                    'linkedin': 'linkedin.com', 'bankofamerica': 'bankofamerica.com',
                }
                if domain != LEGIT.get(brand, ''):
                    results['risk_score'] += 60
                    results['flags'].append({
                        'severity': 'HIGH',
                        'message': f'Domain impersonates {brand.capitalize()} (legitimate: {LEGIT.get(brand)})'
                    })
                break

        # 5. IP address instead of domain name
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ip_pattern.match(domain):
            results['risk_score'] += 40
            results['flags'].append({
                'severity': 'HIGH',
                'message': 'URL uses raw IP address instead of domain name — common phishing tactic'
            })

        # 6. Suspicious keywords in URL path
        BAD_KEYWORDS = ['login', 'verify', 'secure', 'account', 'update',
                        'confirm', 'banking', 'signin', 'password', 'credential']
        path_lower = (parsed.path + '?' + parsed.query).lower()
        found_kw = [k for k in BAD_KEYWORDS if k in path_lower]
        if len(found_kw) >= 2:
            results['risk_score'] += 25
            results['flags'].append({
                'severity': 'MEDIUM',
                'message': f'URL path contains credential-harvesting keywords: {", ".join(found_kw[:3])}'
            })

        # 7. Excessive subdomains (e.g. paypal.com.login.evil.ru)
        parts = domain.split('.')
        if len(parts) > 4:
            results['risk_score'] += 30
            results['flags'].append({
                'severity': 'MEDIUM',
                'message': f'Excessive subdomains ({len(parts) - 2}) — may be spoofing a legitimate domain'
            })

        # 8. HTTP (no SSL)
        if url.startswith('http://') and not url.startswith('https://'):
            results['risk_score'] += 15
            results['flags'].append({
                'severity': 'LOW',
                'message': 'No HTTPS — connection is unencrypted'
            })

        # If no flags found
        if not results['flags']:
            results['flags'].append({
                'severity': 'INFO',
                'message': 'No obvious threat indicators found in URL structure'
            })

    except Exception as e:
        results['flags'].append({'severity': 'ERROR', 'message': str(e)})

    results['risk_score'] = min(results['risk_score'], 100)
    results['safe'] = results['risk_score'] < 40

    if results['risk_score'] >= 70:
        results['verdict'] = 'MALICIOUS'
    elif results['risk_score'] >= 40:
        results['verdict'] = 'SUSPICIOUS'
    else:
        results['verdict'] = 'SAFE'

    return jsonify(results)


# ─── SIMULATION MODE ─────────────────────────────────────────────────────────
@app.route('/simulation')
def simulation():
    return render_template('simulation.html')


# ─── RUN ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    # Allows OAuth over HTTP in local development (never use in production)
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    # Don't raise errors when Google returns a slightly different scope set
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
    # Force Flask to use 127.0.0.1 so it always matches the redirect URI in Google Console
    app.run(debug=True, host='127.0.0.1', port=5000)