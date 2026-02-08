"""Language quality widget."""

from html import escape

from ..base import Widget


class LanguageWidget(Widget):
    nav_id = "nav-language"
    nav_label = "Language"
    nav_group = "email"

    def render(self, analysis: dict, parsed: dict) -> str:
        lang = analysis.get("language", {"score": None, "findings": []})
        if lang.get("score") is None:
            return ""

        score = lang["score"]
        if score >= 80: color, label = "#34d399", "GOOD"
        elif score >= 60: color, label = "#eab308", "FAIR"
        else: color, label = "#f87171", "POOR"

        findings = "".join(f'<div class="finding-item">• {escape(f)}</div>' for f in lang.get("findings", []))

        return f"""
    <div class="widget lang-widget" id="nav-language">
        <div class="widget-header"><span class="widget-icon">📝</span> LANGUAGE ANALYSIS</div>
        <div class="lang-content">
            <div class="lang-score" style="color:{color}">{score}/100 <span class="lang-label">{label}</span></div>
            {f'<div class="lang-findings">{findings}</div>' if findings else '<div class="dim" style="padding:0 18px 14px;font-size:12px;">No significant language anomalies</div>'}
        </div>
    </div>"""
