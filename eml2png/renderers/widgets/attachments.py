"""Attachment analysis widget."""

from html import escape

from ..base import Widget
from ...utils import fmt_bytes


class AttachmentWidget(Widget):
    nav_id = "nav-attachments"
    nav_label = "Files"
    nav_group = "email"

    def render(self, analysis: dict, parsed: dict) -> str:
        att_data = analysis["attachments"]
        atts = att_data.get("attachments", [])
        if not atts:
            return ""

        rows = ""
        for a in atts:
            flag_badges = "".join(
                f'<span class="flag-badge {"flag-crit" if s == "critical" else "flag-warn"}">{l}</span>'
                for l, s in a.get("flags", [])
            )
            rows += f"""
        <div class="att-row">
            <div class="att-info">
                <span class="att-name">{escape(a['name'])}</span>
                <span class="att-meta">{escape(a['type'])} · {fmt_bytes(a['size'])}</span>
            </div>
            <div class="att-hashes">
                <span class="att-hash" data-full="{a.get('md5','')}" title="{a.get('md5','—')}">MD5: {a.get('md5','—')[:16]}…</span>
                <span class="att-hash" data-full="{a.get('sha256','')}" title="{a.get('sha256','—')}">SHA256: {a.get('sha256','—')[:16]}…</span>
            </div>
            <div class="att-flags">{flag_badges}</div>
        </div>"""

        return f"""
    <div class="widget att-widget" id="nav-attachments">
        <div class="widget-header"><span class="widget-icon">📎</span> ATTACHMENT ANALYSIS — {len(atts)} FILES</div>
        {rows}
    </div>"""
