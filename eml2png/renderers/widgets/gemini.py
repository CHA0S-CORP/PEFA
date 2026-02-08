"""Gemini AI assessment widget."""

import re
from html import escape

from ..base import Widget


class GeminiWidget(Widget):
    nav_id = "nav-ai"
    nav_label = "AI"
    nav_group = "assessment"

    def render(self, analysis: dict, parsed: dict) -> str:
        gemini_data = analysis.get("gemini") or {}
        if not gemini_data or "error" in gemini_data:
            err = gemini_data.get("error", "") if gemini_data else ""
            if err and err != "GEMINI_API_KEY not set":
                return f"""
            <div class="widget gemini-widget" id="nav-ai">
                <div class="widget-header"><span class="widget-icon">🤖</span> AI ASSESSMENT — ERROR</div>
                <div class="gemini-content"><div class="dim" style="padding:14px 18px;font-size:12px;">{escape(err)}</div></div>
            </div>"""
            return ""

        text = gemini_data.get("text", "")
        model = gemini_data.get("model", "gemini")

        formatted = escape(text)
        formatted = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', formatted)
        lines = formatted.split("\n")
        result_lines = []
        in_list = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("- ") or stripped.startswith("* "):
                if not in_list:
                    result_lines.append('<ul class="gemini-list">')
                    in_list = True
                result_lines.append(f"<li>{escape(stripped[2:])}</li>")
            else:
                if in_list:
                    result_lines.append("</ul>")
                    in_list = False
                if stripped.startswith("# "):
                    result_lines.append(f'<div class="gemini-h1">{escape(stripped[2:])}</div>')
                elif stripped.startswith("## "):
                    result_lines.append(f'<div class="gemini-h2">{escape(stripped[3:])}</div>')
                elif stripped:
                    result_lines.append(f"<p>{stripped}</p>")
        if in_list:
            result_lines.append("</ul>")
        formatted = "\n".join(result_lines)

        return f"""
    <div class="widget gemini-widget" id="nav-ai">
        <div class="widget-header"><span class="widget-icon">🤖</span> AI PHISHING ASSESSMENT — {escape(model.upper())}</div>
        <div class="gemini-content">
            {formatted}
        </div>
    </div>"""
