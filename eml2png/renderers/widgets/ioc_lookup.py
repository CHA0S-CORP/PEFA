"""Consolidated IOC lookup widget."""

from html import escape

from ..base import Widget
from ..ioc import ioc_ip_html, ioc_url_html, ioc_email_html


def _intel_badges(intel: dict) -> str:
    """Render color-coded threat intel badges for an IOC entry."""
    badges = ""
    vt = intel.get("virustotal", {})
    if vt and "error" not in vt:
        mal = vt.get("malicious", 0)
        cls = "intel-badge-red" if mal > 0 else "intel-badge-dim"
        badges += f'<span class="intel-badge {cls}" title="VirusTotal malicious detections">VT:{mal}</span>'
    abuse = intel.get("abuseipdb", {})
    if abuse and "error" not in abuse:
        score = abuse.get("abuseConfidenceScore", 0)
        cls = "intel-badge-red" if score > 25 else ("intel-badge-amber" if score > 0 else "intel-badge-dim")
        badges += f'<span class="intel-badge {cls}" title="AbuseIPDB confidence score">ABUSE:{score}%</span>'
    otx = intel.get("alienvault", {})
    if otx and "error" not in otx:
        pulses = otx.get("pulse_count", 0)
        cls = "intel-badge-red" if pulses > 5 else ("intel-badge-amber" if pulses > 0 else "intel-badge-dim")
        badges += f'<span class="intel-badge {cls}" title="AlienVault OTX pulse count">OTX:{pulses}</span>'
    return badges


def _render_section(title: str, items: list, render_fn) -> str:
    if not items:
        return ""
    rows = ""
    for item in items:
        rows += render_fn(item)
    return f"""<div class="ioc-section">
    <div class="ioc-section-header">{title} ({len(items)})</div>
    {rows}
</div>"""


class IOCLookupWidget(Widget):
    nav_id = "nav-iocs"
    nav_label = "IOCs"
    nav_group = "network"

    def render(self, analysis: dict, parsed: dict) -> str:
        iocs = analysis.get("iocs")
        if not iocs:
            return ""

        total = (len(iocs.get("ips", [])) + len(iocs.get("domains", []))
                 + len(iocs.get("urls", [])) + len(iocs.get("emails", []))
                 + len(iocs.get("hashes", [])))
        if total == 0:
            return ""

        summary = iocs.get("enrichment_summary", {})
        services = summary.get("services", [])
        status = summary.get("status", "")
        svc_label = ""
        if services:
            svc_label = f' <span class="dim">via {", ".join(services)}</span>'
        elif status == "skipped":
            svc_label = ' <span class="dim">(API calls skipped)</span>'
        elif status == "no_services":
            svc_label = ' <span class="dim">(no TI services configured)</span>'

        def ip_row(entry):
            intel = entry.get("threat_intel", {})
            badges = _intel_badges(intel)
            ip_geo = analysis.get("ip_geo_map", {}).get(entry["value"])
            return f'<div class="ioc-row"><span class="ioc-value">{ioc_ip_html(entry["value"], geo=ip_geo)}</span>{badges}</div>'

        def domain_row(entry):
            intel = entry.get("threat_intel", {})
            badges = _intel_badges(intel)
            return f'<div class="ioc-row"><span class="ioc-value mono">{escape(entry["value"])}</span>{badges}</div>'

        def url_row(entry):
            intel = entry.get("threat_intel", {})
            badges = _intel_badges(intel)
            return f'<div class="ioc-row"><span class="ioc-value">{ioc_url_html(entry["value"])}</span>{badges}</div>'

        def email_row(entry):
            return f'<div class="ioc-row"><span class="ioc-value">{ioc_email_html(entry["value"])}</span></div>'

        def hash_row(entry):
            intel = entry.get("threat_intel", {})
            badges = _intel_badges(intel)
            label = f'{entry.get("type", "").upper()}'
            fname = escape(entry.get("filename", ""))
            fname_span = f' <span class="dim">({fname})</span>' if fname else ""
            return f'<div class="ioc-row"><span class="ioc-hash-label">{label}</span><span class="ioc-value mono">{escape(entry["value"])}</span>{fname_span}{badges}</div>'

        sections = ""
        sections += _render_section("IP ADDRESSES", iocs.get("ips", []), ip_row)
        sections += _render_section("DOMAINS", iocs.get("domains", []), domain_row)
        sections += _render_section("URLS", iocs.get("urls", []), url_row)
        sections += _render_section("EMAIL ADDRESSES", iocs.get("emails", []), email_row)
        sections += _render_section("FILE HASHES", iocs.get("hashes", []), hash_row)

        return f"""
    <div class="widget ioc-lookup-widget" id="nav-iocs">
        <div class="widget-header"><span class="widget-icon">◈</span> CONSOLIDATED IOCs — {total} INDICATORS{svc_label}</div>
        <div class="widget-content">{sections}</div>
    </div>"""
