"""Domain age widget."""

from html import escape

from ..base import Widget


class DomainAgeWidget(Widget):
    nav_id = "nav-domain"
    nav_label = "Domain"
    nav_group = "network"

    def render(self, analysis: dict, parsed: dict) -> str:
        domain_info = analysis.get("domain_age") or {}
        domain = analysis.get("sender", {}).get("from_domain", "")
        if not domain_info or "error" in domain_info:
            return ""

        age = domain_info.get("age_days", 0)
        if age < 30: color, label = "#ef4444", "NEWLY REGISTERED"
        elif age < 90: color, label = "#f97316", "RECENT"
        elif age < 365: color, label = "#eab308", "< 1 YEAR"
        else: color, label = "#34d399", f"{age // 365} YEARS"

        return f"""
    <div class="widget domain-widget" id="nav-domain">
        <div class="widget-header"><span class="widget-icon">🌐</span> DOMAIN INTELLIGENCE — {escape(domain)}</div>
        <div class="domain-content">
            <div class="domain-age" style="color:{color}">{age} days <span class="domain-label">{label}</span></div>
            <div class="domain-detail">Created: {escape(domain_info.get('creation_date', '—'))} · Registrar: {escape(domain_info.get('registrar', '—'))}</div>
        </div>
    </div>"""
