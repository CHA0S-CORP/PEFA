"""urlscan.io intelligence widget."""

from html import escape

from ..base import Widget


class URLScanWidget(Widget):
    nav_id = "nav-urlscan"
    nav_label = "URLScan"
    nav_group = "network"

    def render(self, analysis: dict, parsed: dict) -> str:
        urlscan_data = analysis.get("urlscan") or {}
        if not urlscan_data or "error" in urlscan_data or "info" in urlscan_data:
            return ""

        verdict = urlscan_data.get("verdict", {})
        page = urlscan_data.get("page", {})
        malicious = verdict.get("malicious", False)
        score_val = verdict.get("score", 0)
        color = "#ef4444" if malicious else "#34d399"

        return f"""
    <div class="widget urlscan-widget" id="nav-urlscan">
        <div class="widget-header"><span class="widget-icon">🔍</span> URLSCAN.IO INTELLIGENCE</div>
        <div class="urlscan-content">
            <div class="urlscan-verdict" style="color:{color}">{'⚠ MALICIOUS' if malicious else '✓ NOT FLAGGED'} (score: {score_val})</div>
            <div class="urlscan-detail">Server: {escape(page.get('server', '—'))} · IP: {escape(page.get('ip', '—'))} · Country: {escape(page.get('country', '—'))}</div>
            <div class="urlscan-link"><a href="{escape(urlscan_data.get('url', '#'))}" style="color:var(--accent);">View full report →</a></div>
        </div>
    </div>"""
