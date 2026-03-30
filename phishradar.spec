# -*- mode: python ; coding: utf-8 -*-
# PhishGuard SOC — PyInstaller build spec
# Run with: pyinstaller phishguard.spec

import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect all necessary hidden imports
hidden_imports = [
    # Flask and extensions
    'flask', 'flask.templating', 'jinja2', 'jinja2.ext',
    'werkzeug', 'werkzeug.serving', 'werkzeug.routing',
    'click',
    # Google auth
    'google.auth', 'google.auth.transport', 'google.auth.transport.requests',
    'google_auth_oauthlib', 'google_auth_oauthlib.flow',
    'googleapiclient', 'googleapiclient.discovery',
    'google.oauth2', 'google.oauth2.credentials',
    # Groq AI
    'groq',
    # Other
    'dotenv', 'python_dotenv',
    'reportlab', 'reportlab.pdfgen', 'reportlab.lib',
    'requests', 'urllib3', 'certifi',
    'cryptography',
    'email', 'imaplib', 'smtplib',
    # Webview
    'webview', 'webview.platforms.winforms',
    'clr', 'System', 'System.Windows.Forms',
]

# Collect data files (templates, static assets)
datas = [
    ('templates',  'templates'),   # Flask HTML templates
    ('.env',       '.'),           # Environment variables
]

# Add static folder if it exists
if os.path.exists('static'):
    datas.append(('static', 'static'))

a = Analysis(
    ['desktop.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'pandas', 'tkinter', 'PyQt5', 'wx'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='PhishGuard SOC',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # No black terminal window
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='electron\\assets\\icon.ico',   # Use existing icon
    onefile=True,           # Single .exe file
)
