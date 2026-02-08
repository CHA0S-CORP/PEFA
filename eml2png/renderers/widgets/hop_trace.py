"""Delivery path hop trace widget."""

from html import escape

from ..base import Widget
from ..ioc import ioc_ip_html
from ...utils import country_code_to_flag


def _host_resolved(hostname: str, host_ip_map: dict, host_geo_map: dict) -> str:
    """Return resolved IP with flag for a hostname, or empty string."""
    rip = host_ip_map.get(hostname, "")
    if not rip:
        return ""
    geo = host_geo_map.get(hostname)
    flag = ""
    if geo and "error" not in geo:
        cc = geo.get("countryCode", "")
        f = country_code_to_flag(cc)
        if f:
            tip_parts = [geo.get("country", "")]
            if geo.get("city"):
                tip_parts.append(geo["city"])
            tip = escape(", ".join(p for p in tip_parts if p))
            flag = f'<span class="ip-flag" title="{tip}">{f}</span>'
    return f' <span class="hop-resolved">({escape(rip)}{flag})</span>'


class HopTraceWidget(Widget):
    nav_id = "nav-hops"
    nav_label = "Hops"
    nav_group = "network"

    def render(self, analysis: dict, parsed: dict) -> str:
        hops = analysis.get("hops", [])
        if not hops:
            return ""
        ip_geo_map = analysis.get("ip_geo_map", {})
        host_geo_map = analysis.get("host_geo_map", {})
        host_ip_map = analysis.get("host_ip_map", {})
        items = ""
        for h in hops:
            fr_name = h.get("from", "—")
            by_name = h.get("by", "—")
            fr = escape(fr_name) + _host_resolved(fr_name, host_ip_map, host_geo_map)
            by = escape(by_name) + _host_resolved(by_name, host_ip_map, host_geo_map)
            ip = h.get("ip", "")
            dt = escape(h.get("date", ""))
            hop_geo = ip_geo_map.get(ip)
            ip_tag = f'<span class="hop-ip">{ioc_ip_html(ip, geo=hop_geo)}</span>' if ip else ""
            items += f"""
        <div class="hop-item">
            <div class="hop-num">{h.get('index', '?')}</div>
            <div class="hop-line"></div>
            <div class="hop-detail">
                <span class="hop-from">{fr}</span><span class="hop-arrow">→</span><span class="hop-to">{by}</span>{ip_tag}
                <div class="hop-date">{dt}</div>
            </div>
        </div>"""
        return f"""
    <div class="widget hop-widget" id="nav-hops">
        <div class="widget-header"><span class="widget-icon">◆</span> DELIVERY PATH — {len(hops)} HOPS</div>
        <div class="hop-trace">{items}</div>
    </div>"""
