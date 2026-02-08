"""Page renderer — assembles full HTML page from widgets and templates."""

from datetime import datetime
from html import escape

from ..templates import load_css, load_js
from .widgets import (
    ThreatGaugeWidget,
    AuthWidget,
    LinkAnalysisWidget,
    SenderWidget,
    UrgencyWidget,
    AttachmentWidget,
    LanguageWidget,
    DomainAgeWidget,
    URLScanWidget,
    GeminiWidget,
    IPIntelWidget,
    HopTraceWidget,
)


class PageRenderer:
    def __init__(self):
        self.widgets = [
            ThreatGaugeWidget(),
            GeminiWidget(),
            SenderWidget(),
            AuthWidget(),
            LinkAnalysisWidget(),
            UrgencyWidget(),
            LanguageWidget(),
            DomainAgeWidget(),
            AttachmentWidget(),
            IPIntelWidget(),
            URLScanWidget(),
            HopTraceWidget(),
        ]

    def _build_nav_html(self) -> str:
        groups = {}
        for w in self.widgets:
            if w.nav_group and w.nav_id:
                groups.setdefault(w.nav_group, []).append(w)

        group_labels = {
            "assessment": "ASSESS",
            "email": "EMAIL",
            "network": "NETWORK",
        }

        nav_groups = ""
        for group_key in ("assessment", "email", "network"):
            widgets_in_group = groups.get(group_key, [])
            if not widgets_in_group:
                continue
            dots = ""
            for w in widgets_in_group:
                dots += f'<a href="#{w.nav_id}" class="nav-dot" data-section="{w.nav_id}"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">{w.nav_label}</span></a>\n'
            label = group_labels.get(group_key, group_key.upper())
            nav_groups += f"""
            <div class="nav-group" data-group="{group_key}">
                <div class="nav-group-label">{label}</div>
                {dots}
            </div>"""

        # Static raw section nav
        nav_groups += """
            <div class="nav-group" data-group="raw">
                <div class="nav-group-label">RAW</div>
                <a href="#nav-metadata" class="nav-dot" data-section="nav-metadata"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Meta</span></a>
                <a href="#nav-envelope" class="nav-dot" data-section="nav-envelope"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Envelope</span></a>
                <a href="#nav-body" class="nav-dot" data-section="nav-body"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Body</span></a>
                <a href="#nav-logs" class="nav-dot" data-section="nav-logs"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Logs</span></a>
            </div>"""

        return f'<nav class="section-nav">{nav_groups}\n        </nav>'

    def _build_log_widget(self, analysis: dict) -> str:
        logs = analysis.get("logs", [])
        if not logs:
            return ""
        entries = "\n".join(f'<div class="log-entry">{escape(line)}</div>' for line in logs)
        return f'''<div class="widget log-widget" id="nav-logs">
<div class="widget-header"><span class="widget-icon">◇</span> ANALYSIS LOG</div>
<div class="widget-content collapsed"><div class="log-entries">{entries}</div></div>
</div>'''

    def build(self, parsed: dict, analysis: dict, interactive: bool = False) -> str:
        headers = parsed.get("headers", {})
        body_html = (
            analysis.get("highlighted_body")
            or parsed.get("html_body", "")
            or f"<pre style='white-space:pre-wrap;font-family:inherit;'>{escape(parsed.get('text_body', '') or '(empty)')}</pre>"
        )

        # Envelope rows
        env_rows = ""
        for key in ["From", "To", "Cc", "Bcc", "Reply-To", "Date", "Subject"]:
            val = headers.get(key, "")
            if val:
                env_rows += f'<div class="env-row"><span class="env-label">{key.upper()}</span><span class="env-val">{escape(val)}</span></div>'

        # Metadata widget
        meta_rows = ""
        for label, val in [
            ("MESSAGE-ID", headers.get("Message-ID", "")),
            ("RETURN-PATH", headers.get("Return-Path", "")),
            ("X-MAILER", headers.get("X-Mailer", "") or headers.get("User-Agent", "")),
            ("MIME", headers.get("MIME-Version", "")),
            ("CONTENT-TYPE", headers.get("Content-Type", "")[:80]),
        ]:
            if val:
                meta_rows += f'<div class="meta-row"><span class="meta-label">{label}</span><span class="meta-val">{escape(val)}</span></div>'

        meta_widget = ""
        if meta_rows:
            meta_widget = f'<div class="widget meta-widget" id="nav-metadata"><div class="widget-header"><span class="widget-icon">◇</span> MESSAGE METADATA</div>{meta_rows}</div>'

        # Render widgets
        threat_html = self.widgets[0].render(analysis, parsed)  # ThreatGauge
        gemini_html = self.widgets[1].render(analysis, parsed)  # Gemini
        sender_html = self.widgets[2].render(analysis, parsed)  # Sender
        auth_html = self.widgets[3].render(analysis, parsed)    # Auth
        links_html = self.widgets[4].render(analysis, parsed)   # Links
        urgency_html = self.widgets[5].render(analysis, parsed) # Urgency
        language_html = self.widgets[6].render(analysis, parsed) # Language
        domain_html = self.widgets[7].render(analysis, parsed)  # Domain
        att_html = self.widgets[8].render(analysis, parsed)     # Attachments
        ip_html = self.widgets[9].render(analysis, parsed)      # IP
        urlscan_html = self.widgets[10].render(analysis, parsed) # URLScan
        hops_html = self.widgets[11].render(analysis, parsed)   # Hops

        # Load CSS
        base_css = load_css("base.css")
        interactive_css = load_css("interactive.css") if interactive else ""

        # Interactive JS
        interactive_js = ""
        nav_html = ""
        nav_js = ""
        if interactive:
            interactive_js = f"<script>\n{load_js('interactive.js')}\n</script>"
            nav_html = self._build_nav_html()
            nav_js = f"<script>\n{load_js('navigation.js')}\n</script>"

        log_widget = self._build_log_widget(analysis)

        now = datetime.now()

        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
{base_css}
{interactive_css}
</style>
</head>
<body{' class="interactive"' if interactive else ''}>
{nav_html}
<div class="topbar">
    <div>
        <div class="topbar-title">▲ PHISHING EMAIL FORENSIC ANALYSIS</div>
        <div class="topbar-sub">{escape(headers.get('Subject','untitled')[:80])}</div>
    </div>
    <div style="display:flex;align-items:center;gap:12px;">
        {'<button class="print-btn" onclick="window.print()" title="Print report (Ctrl+P)">&#9113; PRINT</button>' if interactive else ''}
        <div class="topbar-sub">{now.strftime('%Y-%m-%d %H:%M UTC')}</div>
    </div>
</div>
<div class="container">

{threat_html}

{gemini_html}

<div class="row-2">
    {sender_html}
    <div>
        {auth_html}
    </div>
</div>

{links_html}
{urgency_html}

<div class="row-2">
    {language_html}
    {domain_html}
</div>

{att_html}
{ip_html}
{urlscan_html}
{hops_html}

{meta_widget}

<div class="envelope" id="nav-envelope">{env_rows}</div>

<div class="body-label">▼ EMAIL BODY (RENDERED)</div>
<div class="body-section" id="nav-body">{body_html}</div>

{log_widget}

</div>
<div class="footer">GENERATED BY EML2PNG PHISHING ANALYZER · {now.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
{interactive_js}
{nav_js}
</body>
</html>"""
