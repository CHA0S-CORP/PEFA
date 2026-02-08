"""Urgency/social engineering widget."""

from html import escape

from ..base import Widget


class UrgencyWidget(Widget):
    nav_id = "nav-urgency"
    nav_label = "Urgency"
    nav_group = "email"

    def render(self, analysis: dict, parsed: dict) -> str:
        urgency = analysis.get("urgency", {"total_count": 0, "counter": {}, "matches": [], "density": 0})
        if urgency["total_count"] == 0:
            return ""

        bars = ""
        for keyword, count in sorted(urgency["counter"].items(), key=lambda x: -x[1]):
            width = min(100, count * 25)
            bars += f"""
        <div class="urgency-bar-row">
            <span class="urgency-keyword">{escape(keyword)}</span>
            <div class="urgency-bar"><div class="urgency-fill" style="width:{width}%"></div></div>
            <span class="urgency-count">×{count}</span>
        </div>"""

        return f"""
    <div class="widget urgency-widget" id="nav-urgency">
        <div class="widget-header"><span class="widget-icon">⚡</span> SOCIAL ENGINEERING INDICATORS — {urgency['unique_count']} PATTERNS MATCHED</div>
        <div class="urgency-content">{bars}</div>
        {f'<div class="urgency-note">⚠ Generic greeting detected — not addressing recipient by name</div>' if urgency['generic_greeting'] else ''}
    </div>"""
