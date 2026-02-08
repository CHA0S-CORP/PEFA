"""Email authentication widget."""

from html import escape

from ..base import Widget


def auth_badge_html(label, value):
    if not value:
        cls, icon = "unknown", "—"
    elif value.lower() == "pass":
        cls, icon = "pass", "✓"
    elif value.lower() in ("fail", "softfail"):
        cls, icon = "fail", "✗"
    else:
        cls, icon = "unknown", "?"
    return f'<div class="auth-chip {cls}"><span class="auth-icon">{icon}</span><span class="auth-label">{label}</span><span class="auth-val">{escape(value or "N/A")}</span></div>'


class AuthWidget(Widget):
    nav_id = "nav-auth"
    nav_label = "Auth"
    nav_group = "email"

    def render(self, analysis: dict, parsed: dict) -> str:
        auth = parsed.get("auth", {})
        if not auth:
            return ""
        return f"""
    <div class="widget auth-widget" id="nav-auth">
        <div class="widget-header"><span class="widget-icon">◈</span> EMAIL AUTHENTICATION</div>
        <div class="auth-badges">
            {auth_badge_html("SPF", auth["spf"])}
            {auth_badge_html("DKIM", auth["dkim"])}
            {auth_badge_html("DMARC", auth["dmarc"])}
        </div>
    </div>"""
