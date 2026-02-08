"""Delivery path hop trace widget."""

from html import escape

from ..base import Widget
from ..ioc import ioc_ip_html


class HopTraceWidget(Widget):
    nav_id = "nav-hops"
    nav_label = "Hops"
    nav_group = "network"

    def render(self, analysis: dict, parsed: dict) -> str:
        hops = analysis.get("hops", [])
        if not hops:
            return ""
        ip_geo_map = analysis.get("ip_geo_map", {})
        items = ""
        for h in hops:
            fr = escape(h.get("from", "—"))
            by = escape(h.get("by", "—"))
            ip = h.get("ip", "")
            dt = escape(h.get("date", ""))
            hop_geo = ip_geo_map.get(ip)
            ip_tag = f'<span class="hop-ip">{ioc_ip_html(ip, geo=hop_geo)}</span>' if ip else ""
            items += f"""
        <div class="hop-item">
            <div class="hop-num">{h['index']}</div>
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
