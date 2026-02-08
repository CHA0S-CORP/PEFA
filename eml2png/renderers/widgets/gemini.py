"""Gemini AI assessment widget."""

import re
from html import escape

from ..base import Widget

# Section names we expect from the Gemini prompt
_SECTION_NAMES = [
    "VERDICT",
    "CONFIDENCE",
    "EXECUTIVE SUMMARY",
    "TECHNICAL ANALYSIS",
    "ATTACK TECHNIQUE",
    "RECOMMENDED ACTIONS",
    "INDICATORS OF COMPROMISE",
]

# Regex to split on **SECTION_NAME** or **SECTION_NAME:** headers
_SECTION_RE = re.compile(
    r'\*\*(' + '|'.join(re.escape(s) for s in _SECTION_NAMES) + r')\*\*:?\s*',
    re.IGNORECASE,
)

_VERDICT_COLORS = {
    "phishing":    ("#ef4444", "rgba(239,68,68,0.12)", "⛔"),
    "suspicious":  ("#f59e0b", "rgba(251,191,36,0.12)", "⚠️"),
    "legitimate":  ("#34d399", "rgba(52,211,153,0.12)", "✅"),
}

_SECTION_ICONS = {
    "TECHNICAL ANALYSIS": "🔬",
    "ATTACK TECHNIQUE": "🎯",
    "RECOMMENDED ACTIONS": "🛡️",
    "INDICATORS OF COMPROMISE": "🔍",
}


def _parse_sections(text: str) -> dict | None:
    """Split Gemini text into a dict keyed by section name.

    Returns None if the expected structure is not found (fallback to raw).
    """
    parts = _SECTION_RE.split(text)
    # parts looks like: [preamble, "VERDICT", content, "CONFIDENCE", content, ...]
    if len(parts) < 3:
        return None

    sections = {}
    i = 1  # skip preamble
    while i < len(parts) - 1:
        key = parts[i].upper()
        val = parts[i + 1].strip()
        sections[key] = val
        i += 2

    # Need at least verdict to consider it structured
    if "VERDICT" not in sections:
        return None
    return sections


def _md_to_html(text: str) -> str:
    """Minimal markdown-to-HTML for a section body. Text is raw (unescaped)."""
    escaped = escape(text)
    # Bold
    escaped = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', escaped)

    lines = escaped.split("\n")
    result = []
    in_list = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                result.append('<ul class="gemini-list">')
                in_list = True
            result.append(f"<li>{stripped[2:]}</li>")
        else:
            if in_list:
                result.append("</ul>")
                in_list = False
            if stripped.startswith("# "):
                result.append(f'<div class="gemini-h1">{stripped[2:]}</div>')
            elif stripped.startswith("## "):
                result.append(f'<div class="gemini-h2">{stripped[3:]}</div>')
            elif stripped:
                result.append(f"<p>{stripped}</p>")
    if in_list:
        result.append("</ul>")
    return "\n".join(result)


def _render_verdict_banner(sections: dict) -> str:
    """Render color-coded verdict banner with confidence badge."""
    verdict_raw = sections.get("VERDICT", "").strip().rstrip(".")
    confidence_raw = sections.get("CONFIDENCE", "").strip().rstrip(".")

    verdict_lower = verdict_raw.lower()
    color, bg, icon = _VERDICT_COLORS.get("suspicious")  # default
    for key, vals in _VERDICT_COLORS.items():
        if key in verdict_lower:
            color, bg, icon = vals
            break

    confidence_html = ""
    if confidence_raw:
        confidence_html = (
            f'<span class="gemini-confidence" style="background:{bg};color:{color};">'
            f'{escape(confidence_raw)}</span>'
        )

    return (
        f'<div class="gemini-verdict-banner" style="border-color:{color};background:{bg};">'
        f'<span class="gemini-verdict-icon">{icon}</span>'
        f'<span class="gemini-verdict-text" style="color:{color};">{escape(verdict_raw)}</span>'
        f'{confidence_html}'
        f'</div>'
    )


def _render_summary(sections: dict) -> str:
    """Render executive summary callout box."""
    summary = sections.get("EXECUTIVE SUMMARY", "")
    if not summary:
        return ""
    return (
        f'<div class="gemini-summary">'
        f'<div class="gemini-summary-label">EXECUTIVE SUMMARY</div>'
        f'{_md_to_html(summary)}'
        f'</div>'
    )


def _render_section_card(name: str, body: str) -> str:
    """Render a section as a styled card."""
    icon = _SECTION_ICONS.get(name, "📋")
    is_ioc = name == "INDICATORS OF COMPROMISE"

    inner = _md_to_html(body)

    # For IOC section, also wrap lines that look like indicators in monospace
    if is_ioc:
        inner = re.sub(
            r'<li>(.*?)</li>',
            r'<li><span class="gemini-ioc-item">\1</span></li>',
            inner,
        )

    return (
        f'<div class="gemini-section">'
        f'<div class="gemini-section-header">'
        f'<span class="gemini-section-icon">{icon}</span> {escape(name)}'
        f'</div>'
        f'<div class="gemini-section-body">{inner}</div>'
        f'</div>'
    )


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

        # Try structured rendering
        sections = _parse_sections(text)
        if sections:
            body = self._render_structured(sections)
        else:
            body = _md_to_html(text)

        return f"""
    <div class="widget gemini-widget" id="nav-ai">
        <div class="widget-header"><span class="widget-icon">🤖</span> AI PHISHING ASSESSMENT — {escape(model.upper())}</div>
        <div class="gemini-content">
            {body}
        </div>
    </div>"""

    @staticmethod
    def _render_structured(sections: dict) -> str:
        """Render parsed sections as structured UI components."""
        parts = []

        # Verdict banner
        parts.append(_render_verdict_banner(sections))

        # Executive summary callout
        parts.append(_render_summary(sections))

        # Remaining sections as cards
        for name in ("TECHNICAL ANALYSIS", "ATTACK TECHNIQUE",
                     "RECOMMENDED ACTIONS", "INDICATORS OF COMPROMISE"):
            body = sections.get(name, "")
            if body:
                parts.append(_render_section_card(name, body))

        return "\n".join(parts)
