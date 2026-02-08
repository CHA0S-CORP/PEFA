"""Threat gauge widget."""

from html import escape

from ..base import Widget


class ThreatGaugeWidget(Widget):
    nav_id = "nav-threat"
    nav_label = "Threat"
    nav_group = "assessment"

    def render(self, analysis: dict, parsed: dict) -> str:
        threat = analysis["threat"]
        score = threat["score"]
        level = threat["level"]
        if score >= 70: color, glow = "#ef4444", "rgba(239,68,68,0.3)"
        elif score >= 45: color, glow = "#f97316", "rgba(249,115,22,0.3)"
        elif score >= 25: color, glow = "#eab308", "rgba(234,179,8,0.3)"
        elif score >= 10: color, glow = "#22d3ee", "rgba(34,211,238,0.2)"
        else: color, glow = "#34d399", "rgba(52,211,153,0.2)"

        factor_rows = ""
        for desc, pts in threat["factors"]:
            sign = "+" if pts >= 0 else ""
            factor_rows += f'<div class="factor-row"><span class="factor-desc">{escape(desc)}</span><span class="factor-pts">{sign}{pts}</span></div>'

        target_dash = round(score * 3.267, 1)
        return f"""
    <div class="widget threat-widget" id="nav-threat">
        <div class="widget-header"><span class="widget-icon">⬡</span> PHISHING THREAT ASSESSMENT</div>
        <div class="threat-content">
            <div class="gauge-container">
                <div class="gauge-ring" style="--score:{score};--color:{color};--glow:{glow}">
                    <svg viewBox="0 0 120 120" class="gauge-svg">
                        <circle cx="60" cy="60" r="52" fill="none" stroke="#1e293b" stroke-width="8"/>
                        <circle cx="60" cy="60" r="52" fill="none" stroke="{color}"
                            stroke-width="8" stroke-linecap="round"
                            stroke-dasharray="0 326.7" data-target-dash="{target_dash}"
                            transform="rotate(-90 60 60)"
                            style="filter: drop-shadow(0 0 6px {glow});"/>
                    </svg>
                    <div class="gauge-text">
                        <div class="gauge-score" style="color:{color}" data-target="{score}">0</div>
                        <div class="gauge-label">{level}</div>
                    </div>
                    <div class="gauge-glow" style="background:radial-gradient(circle, {glow} 0%, transparent 70%);"></div>
                </div>
            </div>
            <div class="threat-factors">
                <div class="factors-title">CONTRIBUTING FACTORS</div>
                {factor_rows if factor_rows else '<div class="factor-row"><span class="factor-desc dim">No significant risk factors detected</span></div>'}
            </div>
        </div>
    </div>"""
