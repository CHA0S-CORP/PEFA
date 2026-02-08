"""Page renderer — assembles full HTML page from widgets and templates."""

from datetime import datetime
from html import escape

from ..highlighting import get_highlight_popup_js
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
    IOCLookupWidget,
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
            IOCLookupWidget(),
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

    def _build_body_widget(self, body_section_html: str, analysis: dict) -> str:
        """Wrap email body in a proper widget card with highlight summary bar."""
        urgency_count = len(analysis.get("urgency", {}).get("matches", []))
        link_flags = [l for l in analysis.get("links", {}).get("links", []) if l.get("flags")]
        link_count = len(link_flags)

        badges = ""
        if urgency_count:
            badges += f'<span class="body-hl-badge body-hl-amber">{urgency_count} urgency pattern{"s" if urgency_count != 1 else ""}</span>'
        if link_count:
            badges += f'<span class="body-hl-badge body-hl-red">{link_count} suspicious link{"s" if link_count != 1 else ""}</span>'

        summary = ""
        if badges:
            summary = f'<div class="body-highlight-summary">{badges}</div>'

        return (
            f'<div class="widget body-widget" id="nav-body">'
            f'<div class="widget-header"><span class="widget-icon">◇</span> EMAIL BODY (RENDERED)</div>'
            f'{summary}'
            f'<div class="body-section">{body_section_html}</div>'
            f'</div>'
        )

    def _build_log_widget(self, analysis: dict) -> str:
        logs = analysis.get("logs", [])
        if not logs:
            return ""
        entries = "\n".join(f'<div class="log-entry">{escape(line)}</div>' for line in logs)
        return f'''<div class="widget log-widget" id="nav-logs">
<div class="widget-header"><span class="widget-icon">◇</span> ANALYSIS LOG</div>
<div class="widget-content collapsed"><div class="log-entries">{entries}</div></div>
</div>'''

    def build(self, parsed: dict, analysis: dict, interactive: bool = False,
              csp_nonce: str = None) -> str:
        headers = parsed.get("headers", {})
        raw_body_html = (
            analysis.get("highlighted_body")
            or parsed.get("html_body", "")
            or f"<pre style='white-space:pre-wrap;font-family:inherit;'>{escape(parsed.get('text_body', '') or '(empty)')}</pre>"
        )

        # Build sandboxed iframe srcdoc for email body
        iframe_inner = (
            '<!DOCTYPE html><html><head><meta charset="utf-8">'
            '<style>'
            'body{margin:0;padding:0;background:transparent;color:#c9d1d9;'
            'font-size:14px;line-height:1.7;font-family:Inter,-apple-system,BlinkMacSystemFont,sans-serif;}'
            'img{max-width:100%!important;height:auto!important;filter:brightness(0.92);}'
            'table{max-width:100%!important;}'
            'a{color:#60a5fa;text-decoration:underline;text-decoration-color:rgba(96,165,250,0.3);'
            'text-underline-offset:2px;pointer-events:none;cursor:default;}'
            'td,th{color:#c9d1d9!important;}'
            'p,div,span{color:inherit;}'
            '</style></head><body>'
            + raw_body_html
            + '</body></html>'
        )
        iframe_srcdoc = escape(iframe_inner, quote=True)
        body_section_html = (
            f'<iframe sandbox="allow-same-origin" srcdoc="{iframe_srcdoc}" '
            f'style="width:100%;border:none;min-height:200px;display:block;background:transparent;" '
            f'title="Email body content"></iframe>'
        )

        # Envelope rows
        env_rows = ""
        for key in ["From", "To", "Cc", "Bcc", "Reply-To", "Date", "Subject"]:
            val = headers.get(key, "")
            if val:
                env_rows += f'<div class="env-row"><span class="env-label">{key.upper()}</span><span class="env-val">{escape(val)}</span></div>'
            if key == "Date" and analysis.get("sender_local_time"):
                env_rows += f'<div class="env-row"><span class="env-label" style="color:var(--accent)">SENDER TIME</span><span class="env-val" style="color:var(--accent)">{escape(analysis["sender_local_time"])}</span></div>'

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
        iocs_html = self.widgets[12].render(analysis, parsed)   # IOCs

        # Load CSS
        base_css = load_css("base.css")
        interactive_css = load_css("interactive.css") if interactive else ""

        # Interactive JS
        nonce_attr = f' nonce="{csp_nonce}"' if csp_nonce else ""
        interactive_js = ""
        popup_js = ""
        nav_html = ""
        nav_js = ""
        if interactive:
            interactive_js = f"<script{nonce_attr}>\n{load_js('interactive.js')}\n</script>"
            popup_js = f"<script{nonce_attr}>\n{get_highlight_popup_js(analysis.get('gemini'))}\n</script>"
            nav_html = self._build_nav_html()
            nav_js = f"<script{nonce_attr}>\n{load_js('navigation.js')}\n</script>"

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
        {'<button class="topbar-btn new-analysis-btn" title="Analyze new email">&#8853; NEW ANALYSIS</button>' if interactive else ''}
        {'<button class="topbar-btn download-html-btn" title="Download HTML report">&#10515; HTML</button>' if interactive else ''}
        {'<button class="topbar-btn download-png-btn" title="Download PNG report">&#10515; PNG</button>' if interactive else ''}
        {'<button class="topbar-btn print-btn" title="Print report (Ctrl+P)">&#9113; PRINT</button>' if interactive else ''}
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
        {language_html}
    </div>
</div>

{links_html}
{urgency_html}

{domain_html}

{att_html}
{ip_html}
{urlscan_html}
{hops_html}
{iocs_html}

{meta_widget}

<div class="envelope" id="nav-envelope">{env_rows}</div>

{self._build_body_widget(body_section_html, analysis)}

{log_widget}

</div>
<div class="footer">GENERATED BY pefa PHISHING ANALYZER · {now.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
{interactive_js}
{popup_js}
{nav_js}
</body>
</html>"""
