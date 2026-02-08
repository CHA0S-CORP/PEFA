"""Link analysis widget."""

from html import escape

from ..base import Widget
from ..ioc import ioc_url_html


class LinkAnalysisWidget(Widget):
    nav_id = "nav-links"
    nav_label = "Links"
    nav_group = "email"

    def render(self, analysis: dict, parsed: dict) -> str:
        links_data = analysis["links"]
        links = links_data.get("links", [])
        if not links:
            return ""

        rows = ""
        for link in links:
            href = link["href"]
            display = link["display"] or "—"
            flags = link.get("flags", [])

            flag_badges = ""
            for label, severity in flags:
                cls = "flag-crit" if severity == "critical" else "flag-warn"
                flag_badges += f'<span class="flag-badge {cls}">{label}</span>'

            mismatch_class = " link-flagged" if flags else ""

            rows += f"""
        <div class="link-row{mismatch_class}">
            <div class="link-display">{escape(display[:80])}</div>
            <div class="link-href">{ioc_url_html(href)}</div>
            <div class="link-flags">{flag_badges}</div>
        </div>"""

        findings_html = ""
        if links_data.get("findings"):
            findings_html = '<div class="link-findings">' + "".join(
                f'<div class="finding-item">⚠ {escape(f)}</div>' for f in links_data["findings"]
            ) + "</div>"

        return f"""
    <div class="widget link-widget" id="nav-links">
        <div class="widget-header"><span class="widget-icon">🔗</span> LINK ANALYSIS — {len(links)} URLs EXTRACTED</div>
        {findings_html}
        <div class="link-table">
            <div class="link-table-header">
                <span>DISPLAY TEXT</span><span>ACTUAL URL</span><span>FLAGS</span>
            </div>
            {rows}
        </div>
    </div>"""
