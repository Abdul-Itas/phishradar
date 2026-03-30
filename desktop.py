"""
phishradar SOC — Desktop Launcher
Starts Flask in a background thread then opens a native pywebview window.
"""
import sys
import os
import threading
import time
import socket

# ── Ensure project root is on path ───────────────────────────────────────────
BASE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# ── Load .env before anything else ───────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv(os.path.join(BASE_DIR, '.env'))

# ── OAuth must allow HTTP in dev/desktop mode ─────────────────────────────────
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE']  = '1'

import webview

FLASK_PORT = 5000
FLASK_URL  = f"http://127.0.0.1:{FLASK_PORT}"


def find_free_port():
    """Find a free port if 5000 is taken."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


def start_flask():
    """Start Flask in a background thread — suppresses the dev server banner."""
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    from app import app
    app.run(
        host='127.0.0.1',
        port=FLASK_PORT,
        debug=False,
        use_reloader=False,
        threaded=True,
    )


def wait_for_flask(timeout=15):
    """Poll until Flask is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', FLASK_PORT), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def main():
    # Start Flask in background
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()

    # Wait for Flask to be ready
    if not wait_for_flask():
        webview.create_window(
            'phishradar SOC — Error',
            html='<h2 style="font-family:sans-serif;color:red;padding:40px">Could not start backend server. Please check your Python environment.</h2>',
        )
        webview.start()
        return

    # API class exposed to JavaScript
    class phishradarAPI:
        def open_browser(self, url):
            import webbrowser
            webbrowser.open(url)

    api = phishradarAPI()

    # Create the native window
    window = webview.create_window(
        title='phishradar SOC',
        url=FLASK_URL,
        width=1400,
        height=900,
        min_size=(1100, 700),
        resizable=True,
        text_select=True,
        confirm_close=False,
        background_color='#050a12',
        js_api=api,
    )

    # Start the webview (blocks until window is closed)
    # Use the loaded event to inject JS that intercepts Google OAuth navigation
    def on_loaded():
        # Inject JS into every page to catch Google OAuth clicks
        window.evaluate_js('''
            (function() {
                // Intercept any navigation to Google OAuth
                var origOpen = XMLHttpRequest.prototype.open;
                document.addEventListener("click", function(e) {
                    var el = e.target.closest("a");
                    if (el && el.href && el.href.indexOf("accounts.google.com") !== -1) {
                        e.preventDefault();
                        window.pywebview.api.open_browser(el.href);
                    }
                });
            })();
        ''')

    window.events.loaded += on_loaded
    webview.start(debug=False)


if __name__ == '__main__':
    main()