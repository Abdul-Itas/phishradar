"""
phishradar — PDF Report Generator
Generates a professional threat report using ReportLab.
"""

from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ── Colour palette (matches dashboard) ──────────────────────────────────────
BG_DARK     = HexColor('#050a12')
BG_CARD     = HexColor('#0a1628')
BG_MID      = HexColor('#0d1b2e')
BORDER      = HexColor('#1a3a6e')
ACCENT_BLUE = HexColor('#00a8ff')
ACCENT_CYAN = HexColor('#00e5ff')
ACCENT_RED  = HexColor('#ff2d55')
ACCENT_YEL  = HexColor('#ffd700')
ACCENT_GRN  = HexColor('#00ff88')
TEXT_PRI    = HexColor('#e8f0fe')
TEXT_SEC    = HexColor('#7a8fad')
TEXT_MONO   = HexColor('#4a9eff')
WHITE       = HexColor('#ffffff')


def _color_for_score(score: int):
    if score >= 70:  return ACCENT_RED
    if score >= 40:  return ACCENT_YEL
    return ACCENT_GRN


def _status_label(score: int) -> str:
    if score >= 70:  return 'PHISHING'
    if score >= 40:  return 'SUSPICIOUS'
    return 'SAFE'


# ── Paragraph styles
def _styles():
    return {
        'title': ParagraphStyle(
            'title',
            fontName='Helvetica-Bold',
            fontSize=22,
            textColor=WHITE,
            spaceAfter=4,
            leading=26,
        ),
        'subtitle': ParagraphStyle(
            'subtitle',
            fontName='Helvetica',
            fontSize=9,
            textColor=TEXT_SEC,
            spaceAfter=0,
            leading=12,
        ),
        'section': ParagraphStyle(
            'section',
            fontName='Helvetica-Bold',
            fontSize=10,
            textColor=ACCENT_CYAN,
            spaceBefore=14,
            spaceAfter=6,
            leading=14,
        ),
        'body': ParagraphStyle(
            'body',
            fontName='Helvetica',
            fontSize=9,
            textColor=TEXT_PRI,
            spaceAfter=4,
            leading=13,
        ),
        'mono': ParagraphStyle(
            'mono',
            fontName='Courier',
            fontSize=8,
            textColor=TEXT_MONO,
            spaceAfter=2,
            leading=11,
        ),
        'small': ParagraphStyle(
            'small',
            fontName='Helvetica',
            fontSize=8,
            textColor=TEXT_SEC,
            spaceAfter=2,
            leading=10,
        ),
        'center': ParagraphStyle(
            'center',
            fontName='Helvetica',
            fontSize=9,
            textColor=TEXT_PRI,
            alignment=TA_CENTER,
            leading=13,
        ),
        'bold': ParagraphStyle(
            'bold',
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=TEXT_PRI,
            spaceAfter=2,
            leading=13,
        ),
        'red': ParagraphStyle(
            'red',
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=ACCENT_RED,
            leading=13,
        ),
        'green': ParagraphStyle(
            'green',
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=ACCENT_GRN,
            leading=13,
        ),
        'yellow': ParagraphStyle(
            'yellow',
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=ACCENT_YEL,
            leading=13,
        ),
    }


# ── Header / Footer canvas callback ─────────────────────────────────────────
def _make_canvas_callback(generated_at: str):
    def on_page(canvas, doc):
        W, H = A4
        # Dark header bar
        canvas.setFillColor(BG_DARK)
        canvas.rect(0, H - 18*mm, W, 18*mm, fill=1, stroke=0)
        # Cyan accent line under header
        canvas.setFillColor(ACCENT_CYAN)
        canvas.rect(0, H - 18*mm, W, 0.8, fill=1, stroke=0)
        # Logo text
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica-Bold', 13)
        canvas.drawString(14*mm, H - 12*mm, 'phishradar')
        canvas.setFillColor(ACCENT_CYAN)
        canvas.drawString(14*mm + canvas.stringWidth('phishradar', 'Helvetica-Bold', 13),
                          H - 12*mm, ' SOC')
        # Right: report label
        canvas.setFillColor(TEXT_SEC)
        canvas.setFont('Helvetica', 8)
        canvas.drawRightString(W - 14*mm, H - 12*mm, 'THREAT INTELLIGENCE REPORT')

        # Dark footer bar
        canvas.setFillColor(BG_DARK)
        canvas.rect(0, 0, W, 10*mm, fill=1, stroke=0)
        canvas.setFillColor(ACCENT_CYAN)
        canvas.rect(0, 10*mm, W, 0.5, fill=1, stroke=0)
        # Footer text
        canvas.setFillColor(TEXT_SEC)
        canvas.setFont('Helvetica', 7)
        canvas.drawString(14*mm, 4*mm, f'Generated: {generated_at}  |  phishradar Security Operations Center v2.0')
        canvas.drawRightString(W - 14*mm, 4*mm, f'Page {doc.page}')

    return on_page


# ── Public function ──────────────────────────────────────────────────────────
def generate_report(emails: list, connected_email: str = None) -> bytes:
    """
    Builds a professional PDF threat report from a list of scanned email dicts.
    Returns raw PDF bytes ready to send as a Flask response.
    """
    buffer = BytesIO()
    W, H = A4
    margin = 14 * mm

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=margin,
        rightMargin=margin,
        topMargin=22 * mm,
        bottomMargin=14 * mm,
        title='phishradar Threat Report',
        author='phishradar SOC',
    )

    S = _styles()
    generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    story = []

    # ── Cover section ────────────────────────────────────────────────────────
    story.append(Spacer(1, 6*mm))

    # Title block on dark background
    title_data = [[
        Paragraph('THREAT INTELLIGENCE REPORT', S['title']),
        Paragraph(
            f'Generated: {generated_at}<br/>'
            f'Inbox: {connected_email or "IMAP Scan"}<br/>'
            f'Emails Scanned: {len(emails)}',
            S['subtitle']
        ),
    ]]
    title_table = Table(title_data, colWidths=[110*mm, 65*mm])
    title_table.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (-1,-1), BG_CARD),
        ('ROWPADDING',  (0,0), (-1,-1), 10),
        ('TOPPADDING',  (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('LEFTPADDING', (0,0), (0,-1), 14),
        ('ROUNDEDCORNERS', [6]),
        ('BOX', (0,0), (-1,-1), 1, BORDER),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(title_table)
    story.append(Spacer(1, 5*mm))

    # ── Stats summary bar ────────────────────────────────────────────────────
    safe_count      = sum(1 for e in emails if e.get('risk_score', 0) < 40)
    suspicious_count= sum(1 for e in emails if 40 <= e.get('risk_score', 0) < 70)
    phishing_count  = sum(1 for e in emails if e.get('risk_score', 0) >= 70)

    # DEFCON level
    if phishing_count > 0:
        defcon_text  = 'DEFCON 1 — CRITICAL'
        defcon_color = ACCENT_RED
    elif suspicious_count > 0:
        defcon_text  = 'DEFCON 3 — ELEVATED'
        defcon_color = ACCENT_YEL
    else:
        defcon_text  = 'DEFCON 5 — NORMAL'
        defcon_color = ACCENT_GRN

    stats_data = [
        [
            Paragraph(f'<b>{len(emails)}</b>', ParagraphStyle('x', fontName='Helvetica-Bold', fontSize=20, textColor=ACCENT_BLUE, alignment=TA_CENTER, leading=24)),
            Paragraph(f'<b>{phishing_count}</b>', ParagraphStyle('x', fontName='Helvetica-Bold', fontSize=20, textColor=ACCENT_RED, alignment=TA_CENTER, leading=24)),
            Paragraph(f'<b>{suspicious_count}</b>', ParagraphStyle('x', fontName='Helvetica-Bold', fontSize=20, textColor=ACCENT_YEL, alignment=TA_CENTER, leading=24)),
            Paragraph(f'<b>{safe_count}</b>', ParagraphStyle('x', fontName='Helvetica-Bold', fontSize=20, textColor=ACCENT_GRN, alignment=TA_CENTER, leading=24)),
            Paragraph(f'<b>{defcon_text}</b>', ParagraphStyle('x', fontName='Helvetica-Bold', fontSize=9, textColor=defcon_color, alignment=TA_CENTER, leading=13)),
        ],
        [
            Paragraph('SCANNED', ParagraphStyle('lbl', fontName='Helvetica', fontSize=7, textColor=TEXT_SEC, alignment=TA_CENTER)),
            Paragraph('PHISHING', ParagraphStyle('lbl', fontName='Helvetica', fontSize=7, textColor=TEXT_SEC, alignment=TA_CENTER)),
            Paragraph('SUSPICIOUS', ParagraphStyle('lbl', fontName='Helvetica', fontSize=7, textColor=TEXT_SEC, alignment=TA_CENTER)),
            Paragraph('SAFE', ParagraphStyle('lbl', fontName='Helvetica', fontSize=7, textColor=TEXT_SEC, alignment=TA_CENTER)),
            Paragraph('THREAT LEVEL', ParagraphStyle('lbl', fontName='Helvetica', fontSize=7, textColor=TEXT_SEC, alignment=TA_CENTER)),
        ],
    ]

    col_w = (W - 2*margin) / 5
    stats_table = Table(stats_data, colWidths=[col_w]*5, rowHeights=[14*mm, 6*mm])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), BG_CARD),
        ('TOPPADDING',    (0,0), (-1,0),  8),
        ('BOTTOMPADDING', (0,0), (-1,0),  2),
        ('TOPPADDING',    (0,1), (-1,1),  0),
        ('BOTTOMPADDING', (0,1), (-1,1),  8),
        ('BOX',           (0,0), (-1,-1), 1, BORDER),
        ('LINEAFTER',     (0,0), (3,-1),  0.5, BORDER),
        ('ROUNDEDCORNERS', [6]),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 4*mm))

    # ── Email details ────────────────────────────────────────────────────────
    story.append(Paragraph('INBOX ANALYSIS RESULTS', S['section']))
    story.append(HRFlowable(width='100%', thickness=0.5, color=BORDER, spaceAfter=4))

    for i, em in enumerate(emails):
        score  = em.get('risk_score', 0)
        status = _status_label(score)
        color  = _color_for_score(score)
        engine = em.get('engine', 'keyword-engine')
        engine_label = 'CLAUDE AI' if engine == 'claude-ai' else 'RULE ENGINE'

        # Email card
        subject_clean = str(em.get('subject', '(No Subject)'))[:80]
        sender_clean  = str(em.get('sender', 'Unknown'))[:80]
        expl_parts    = str(em.get('explanation', '')).split(' | ')

        header_data = [[
            Paragraph(f'#{i+1}', ParagraphStyle('num', fontName='Helvetica-Bold', fontSize=11, textColor=color, leading=14)),
            Paragraph(f'<b>{subject_clean}</b>', ParagraphStyle('subj', fontName='Helvetica-Bold', fontSize=9, textColor=TEXT_PRI, leading=13)),
            Paragraph(f'<b>{score}%</b><br/><font size="7" color="#{color.hexval()[2:]}">{status}</font>',
                      ParagraphStyle('sc', fontName='Helvetica-Bold', fontSize=13, textColor=color, alignment=TA_CENTER, leading=16)),
        ]]

        header_table = Table(header_data, colWidths=[8*mm, 130*mm, 27*mm])
        header_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,-1), BG_MID),
            ('TOPPADDING',    (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING',   (0,0), (0,-1),  8),
            ('LEFTPADDING',   (1,0), (1,-1),  6),
            ('LINEBELOW',     (0,0), (-1,-1), 0.5, BORDER),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN',         (2,0), (2,-1),  'CENTER'),
        ]))

        # Detail rows
        detail_rows = [
            [Paragraph('FROM', S['small']),    Paragraph(sender_clean, S['mono'])],
            [Paragraph('ENGINE', S['small']),  Paragraph(engine_label, S['mono'])],
        ]
        for j, part in enumerate(expl_parts[:3]):
            label = 'ANALYSIS' if j == 0 else ''
            detail_rows.append([
                Paragraph(label, S['small']),
                Paragraph(f'› {part}', S['small']),
            ])

        detail_table = Table(detail_rows, colWidths=[20*mm, 145*mm])
        detail_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,-1), BG_CARD),
            ('TOPPADDING',    (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING',   (0,0), (-1,-1), 8),
            ('VALIGN',        (0,0), (-1,-1), 'TOP'),
        ]))

        # Bottom border with status color
        border_data = [[Paragraph('', S['small'])]]
        border_table = Table(border_data, colWidths=[W - 2*margin])
        border_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,-1), color),
            ('TOPPADDING',    (0,0), (-1,-1), 1),
            ('BOTTOMPADDING', (0,0), (-1,-1), 1),
        ]))

        card = KeepTogether([
            header_table,
            detail_table,
            border_table,
            Spacer(1, 3*mm),
        ])
        story.append(card)

    # ── Recommendations ──────────────────────────────────────────────────────
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph('SECURITY RECOMMENDATIONS', S['section']))
    story.append(HRFlowable(width='100%', thickness=0.5, color=BORDER, spaceAfter=4))

    recs = [
        ('Never click links in unexpected emails', 'Always navigate directly to websites by typing the URL'),
        ('Verify sender domains carefully', 'Check for typosquatting — "paypa1.com" vs "paypal.com"'),
        ('Do not respond to urgency tactics', 'Legitimate organizations never threaten account closure within 24-48 hours'),
        ('Enable 2-Factor Authentication', 'Even if credentials are stolen, 2FA prevents account takeover'),
        ('Report suspicious emails', 'Forward phishing emails to reportphishing@apwg.org'),
    ]

    rec_data = [[
        Paragraph(f'<b>{r[0]}</b>', S['bold']),
        Paragraph(r[1], S['body']),
    ] for r in recs]

    rec_table = Table(rec_data, colWidths=[65*mm, 100*mm])
    rec_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), BG_CARD),
        ('BACKGROUND',    (0,0), (0,-1),  BG_MID),
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ('LINEBELOW',     (0,0), (-1,-2), 0.3, BORDER),
        ('BOX',           (0,0), (-1,-1), 1, BORDER),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(rec_table)

    # ── Footer note ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        'This report was generated automatically by phishradar SOC '
        'Results are based on AI-assisted pattern analysis and should be reviewed by a security professional for critical decisions.',
        S['small']
    ))

    # ── Build ─────────────────────────────────────────────────────────────────
    cb = _make_canvas_callback(generated_at)
    doc.build(story, onFirstPage=cb, onLaterPages=cb)
    return buffer.getvalue()