"""Email authentication widget."""

from html import escape

from ..base import Widget


def auth_badge_html(label, value, evidence=None):
    if not value:
        cls, icon = "unknown", "—"
    elif value.lower() == "pass":
        cls, icon = "pass", "✓"
    elif value.lower() in ("fail", "softfail"):
        cls, icon = "fail", "✗"
    else:
        cls, icon = "unknown", "?"
    evidence_html = ""
    if evidence:
        items = "".join(
            f'<div class="auth-evidence-item">{escape(e)}</div>' for e in evidence
        )
        evidence_html = f'<div class="auth-evidence">{items}</div>'
    return (
        f'<div class="auth-check {cls}">'
        f'<div class="auth-chip">'
        f'<span class="auth-icon">{icon}</span>'
        f'<span class="auth-label">{label}</span>'
        f'<span class="auth-val">{escape(value or "N/A")}</span>'
        f'</div>'
        f'{evidence_html}'
        f'</div>'
    )


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
            {auth_badge_html("SPF", auth["spf"], auth.get("spf_evidence"))}
            {auth_badge_html("DKIM", auth["dkim"], auth.get("dkim_evidence"))}
            {auth_badge_html("DMARC", auth["dmarc"], auth.get("dmarc_evidence"))}
        </div>
    </div>"""
