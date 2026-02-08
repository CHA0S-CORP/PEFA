"""Sender analysis widget."""

from html import escape

from ..base import Widget
from ..ioc import ioc_email_html


class SenderWidget(Widget):
    nav_id = "nav-sender"
    nav_label = "Sender"
    nav_group = "email"

    def render(self, analysis: dict, parsed: dict) -> str:
        sender = analysis["sender"]
        flags = sender.get("flags", [])
        findings = sender.get("findings", [])
        if not flags and not findings:
            return ""

        flag_badges = "".join(
            f'<span class="flag-badge {"flag-crit" if s == "critical" else "flag-warn"}">{l}</span>'
            for l, s in flags
        )

        rows = f"""
    <div class="sender-grid">
        <div class="sender-item"><span class="sender-label">FROM (DISPLAY)</span><span class="sender-val">{escape(sender.get('from_display', '—'))}</span></div>
        <div class="sender-item"><span class="sender-label">FROM (EMAIL)</span><span class="sender-val mono">{ioc_email_html(sender.get('from_email', '—'))}</span></div>
        <div class="sender-item"><span class="sender-label">RETURN-PATH</span><span class="sender-val mono">{ioc_email_html(sender.get('return_path', '—'))}</span></div>
        <div class="sender-item"><span class="sender-label">REPLY-TO</span><span class="sender-val mono">{ioc_email_html(sender.get('reply_to', '—') or '—')}</span></div>
    </div>"""

        findings_html = "".join(f'<div class="finding-item">⚠ {escape(f)}</div>' for f in findings)

        return f"""
    <div class="widget sender-widget" id="nav-sender">
        <div class="widget-header"><span class="widget-icon">👤</span> SENDER ANALYSIS</div>
        <div class="sender-flags">{flag_badges}</div>
        {rows}
        {f'<div class="link-findings">{findings_html}</div>' if findings_html else ''}
    </div>"""
