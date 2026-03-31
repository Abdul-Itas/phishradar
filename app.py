import os
import time
import email as email_lib
from email.header import decode_header
from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
from email_scanner import fetch_latest_emails, analyze_email, fetch_emails_with_token
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
if os.environ.get('RAILWAY_ENVIRONMENT') is None:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
app.secret_key = os.getenv("FLASK_SECRET", "phishradar-dev-secret")
_pkce_store = {}
import threading
_cache_lock = threading.Lock()
_cached_emails = {}
_cached_time = {}
_fetch_active = set()
CACHE_TTL = 300
def get_redirect_uri():
    railway_url = os.getenv("RAILWAY_PUBLIC_DOMAIN")
    if railway_url:
        return f"https://{railway_url}/google-callback"
    return "http://127.0.0.1:5000/google-callback"
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
@app.route('/')
def dashboard():
    from email_scanner import send_phishing_alert
    emails = []
    now = time.time()
    user_key = session.get('user_email', '')
    token_info = session.get('google_token')
    if not token_info or not user_key:
        emails = []
    else:
        with _cache_lock:
            age = now - _cached_time.get(user_key, 0)
            fresh = (user_key in _cached_emails) and (age < CACHE_TTL)
            busy = user_key in _fetch_active
        if fresh:
            print("[PhishRadar] Serving emails from global cache")
            emails = _cached_emails[user_key]
        elif busy:
            print("[PhishRadar] Fetch in progress — waiting...")
            for _ in range(16):
                time.sleep(0.5)
            with _cache_lock:
                if user_key not in _fetch_active:
                    pass
            emails = _cached_emails.get(user_key, [])
        else:
            with _cache_lock:
                _fetch_active.add(user_key)
            try:
                print(f"[PhishRadar] Token scopes: {token_info.get('scopes', 'NONE')}")
                print("[PhishRadar] Fetching emails via Google OAuth token...")
                fetched = fetch_emails_with_token(token_info, limit=5) or []
                with _cache_lock:
                    _cached_emails[user_key] = fetched
                    _cached_time[user_key] = now
                emails = fetched
            except Exception as e:
                print(f"[PhishRadar] Fetch error: {e}")
                emails = _cached_emails.get(user_key, [])
            finally:
                with _cache_lock:
                    _fetch_active.discard(user_key)
    if emails:
        alerted = set(session.get('alerted_ids', []))
        new_alerted = False
        for em in emails:
            msg_id = em.get('msg_id') or em.get('subject', '')
            if em.get('risk_score', 0) >= 70 and msg_id not in alerted:
                send_phishing_alert(em)
                alerted.add(msg_id)
                new_alerted = True
        if new_alerted:
            session['alerted_ids'] = list(alerted)
    connected_email = session.get('user_email', None)
    resp = make_response(render_template('dashboard.html', emails=emails, connected_email=connected_email))
    if connected_email:
        resp.headers['Cache-Control'] = 'private, max-age=300'
    else:
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return resp
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
                score, status, explanation, engine = analyze_email(parsed["subject"], parsed["sender"], parsed["body"])
                result = {"subject": parsed["subject"], "sender": parsed["sender"], "risk_score": score, "status": status, "explanation": explanation, "engine": engine}
            except Exception as e:
                error = f"Analysis failed: {e}"
    return render_template('upload.html', result=result, error=error)
@app.route('/connect-google')
def connect_google():
    status = request.args.get('status', None)
    redirect_uri = get_redirect_uri()
    return render_template('connect_google.html', status=status, redirect_uri=redirect_uri)
@app.route('/google-login')
def google_login():
    from google_auth_oauthlib.flow import Flow
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        return redirect(url_for('connect_google') + '?status=not_configured')
    redirect_uri = get_redirect_uri()
    flow = Flow.from_client_config({"web": {"client_id": client_id, "client_secret": client_secret, "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token"}}, scopes=["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/userinfo.email", "openid"], redirect_uri=redirect_uri)
    import hashlib, base64, secrets
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b'=').decode()
    auth_url, state = flow.authorization_url(prompt='consent', access_type='offline', include_granted_scopes='true', code_challenge=code_challenge, code_challenge_method='S256')
    _pkce_store[state] = code_verifier
    session['oauth_state'] = state
    session['code_verifier'] = code_verifier
    return redirect(auth_url)
@app.route('/google-callback')
def google_callback():
    from google_auth_oauthlib.flow import Flow
    import googleapiclient.discovery
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = get_redirect_uri()
    flow = Flow.from_client_config({"web": {"client_id": client_id, "client_secret": client_secret, "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token"}}, scopes=["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/userinfo.email", "openid"], redirect_uri=redirect_uri, state=session.get('oauth_state'))
    try:
        auth_response = request.url
        if os.environ.get('RAILWAY_ENVIRONMENT') is None:
            auth_response = request.url.replace('https://', 'http://')
        state_key = request.args.get('state', '')
        code_verifier = _pkce_store.pop(state_key, None) or session.pop('code_verifier', None)
        flow.fetch_token(authorization_response=auth_response, code_verifier=code_verifier)
        credentials = flow.credentials
        session['google_token'] = {"token": credentials.token, "refresh_token": credentials.refresh_token, "token_uri": credentials.token_uri, "client_id": credentials.client_id, "client_secret": credentials.client_secret, "scopes": list(credentials.scopes) if credentials.scopes else []}
        service = googleapiclient.discovery.build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        session['user_email'] = user_info.get('email', '')
        print(f"[PhishRadar] OAuth success for {session['user_email']}")
    except Exception as e:
        print(f"[PhishRadar] OAuth callback error: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('connect_google') + '?status=error')
    return redirect(url_for('dashboard'))
@app.route('/logout')
def logout():
    user_email = session.get('user_email', '')
    if user_email:
        with _cache_lock:
            _cached_emails.pop(user_email, None)
            _cached_time.pop(user_email, None)
            _fetch_active.discard(user_email)
    session.clear()
    resp = make_response(redirect(url_for('dashboard')))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    return resp
@app.route('/report')
def download_report():
    from flask import Response
    from report_generator import generate_report
    if 'google_token' in session:
        emails = fetch_emails_with_token(session['google_token'], limit=10) or []
    else:
        emails = fetch_latest_emails(limit=10) or []
    connected_email = session.get('user_email', None)
    pdf_bytes = generate_report(emails, connected_email)
    filename = f"phishradar_report_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(pdf_bytes, mimetype='application/pdf', headers={'Content-Disposition': f'attachment; filename={filename}'})
@app.route('/scan-url', methods=['POST'])
def scan_url():
    from flask import jsonify
    import urllib.request, urllib.parse, json, re
    try:
        data = request.get_json(force=True, silent=True) or {}
        url = data.get('url', '').strip()
    except Exception:
        url = request.form.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    if not url.startswith('http'):
        url = 'http://' + url
    results = {'url': url, 'risk_score': 0, 'flags': [], 'final_url': url, 'domain': '', 'safe': True}
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        results['domain'] = domain
        SHORTENERS = ['bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','rb.gy','short.link']
        if any(s in domain for s in SHORTENERS):
            results['flags'].append({'severity':'HIGH','message':f'URL shortener detected ({domain}) — real destination is hidden'})
            results['risk_score'] += 45
        try:
            req = urllib.request.Request(url, method='HEAD', headers={'User-Agent':'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                results['final_url'] = resp.geturl()
                results['flags'].append({'severity':'INFO','message':f'Resolved to: {results["final_url"]}'})
        except Exception:
            results['flags'].append({'severity':'HIGH','message':'Could not resolve shortened URL destination'})
            results['risk_score'] += 20
        gsb_key = os.getenv('GOOGLE_SAFE_BROWSING_KEY')
        if gsb_key:
            try:
                gsb_payload = json.dumps({"client":{"clientId":"phishradar","clientVersion":"2.0"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":url}]}}).encode()
                req = urllib.request.Request(f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}',data=gsb_payload,headers={'Content-Type':'application/json'},method='POST')
                with urllib.request.urlopen(req, timeout=8) as resp:
                    gsb_data = json.loads(resp.read())
                    if gsb_data.get('matches'):
                        results['risk_score'] += 80
                        results['flags'].append({'severity':'CRITICAL','message':'CONFIRMED MALICIOUS by Google Safe Browsing database'})
            except Exception as e:
                print(f'[PhishRadar] GSB check failed: {e}')
        BRANDS = ['paypal','google','amazon','microsoft','apple','netflix','facebook','instagram','linkedin','bankofamerica']
        normalised = domain.replace('0','o').replace('1','l').replace('3','e').replace('4','a')
        domain_name = normalised.split('.')[0]
        LEGIT = {'paypal':'paypal.com','google':'google.com','amazon':'amazon.com','microsoft':'microsoft.com','apple':'apple.com','netflix':'netflix.com','facebook':'facebook.com','instagram':'instagram.com','linkedin':'linkedin.com','bankofamerica':'bankofamerica.com'}
        for brand in BRANDS:
            if brand in domain_name and domain != LEGIT.get(brand,''):
                results['risk_score'] += 60
                results['flags'].append({'severity':'HIGH','message':f'Domain impersonates {brand.capitalize()} (legitimate: {LEGIT.get(brand)})'})
                break
        if re.compile(r'^(\d{1,3}\.){3}\d{1,3}$').match(domain):
            results['risk_score'] += 40
            results['flags'].append({'severity':'HIGH','message':'URL uses raw IP address instead of domain name'})
        path_lower = (parsed.path + '?' + parsed.query).lower()
        BAD_KW = ['login','verify','secure','account','update','confirm','banking','signin','password','credential']
        found_kw = [k for k in BAD_KW if k in path_lower]
        if len(found_kw) >= 2:
            results['risk_score'] += 25
            results['flags'].append({'severity':'MEDIUM','message':f'Credential-harvesting keywords in URL: {", ".join(found_kw[:3])}'})
        if len(domain.split('.')) > 4:
            results['risk_score'] += 30
            results['flags'].append({'severity':'MEDIUM','message':f'Excessive subdomains — may be spoofing a legitimate domain'})
        if url.startswith('http://'):
            results['risk_score'] += 15
            results['flags'].append({'severity':'LOW','message':'No HTTPS — connection is unencrypted'})
        if not results['flags']:
            results['flags'].append({'severity':'INFO','message':'No obvious threat indicators found in URL structure'})
    except Exception as e:
        results['flags'].append({'severity':'ERROR','message':str(e)})
    results['risk_score'] = min(results['risk_score'], 100)
    results['safe'] = results['risk_score'] < 40
    results['verdict'] = 'MALICIOUS' if results['risk_score'] >= 70 else ('SUSPICIOUS' if results['risk_score'] >= 40 else 'SAFE')
    return jsonify(results)
@app.route('/simulation')
def simulation():
    return render_template('simulation.html')
if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)