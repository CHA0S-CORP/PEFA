"""Origin IP intelligence widget."""

from html import escape

from ..base import Widget
from ..ioc import ioc_ip_html


class IPIntelWidget(Widget):
    nav_id = "nav-ip"
    nav_label = "IP"
    nav_group = "network"

    def render(self, analysis: dict, parsed: dict) -> str:
        source_ip = analysis.get("source_ip", "")
        ip_data = analysis.get("ip_data")
        if not source_ip:
            return ""
        if ip_data and "error" not in ip_data:
            cc = ip_data.get('countryCode', '')
            from ...utils import country_code_to_flag
            flag = country_code_to_flag(cc)
            flag_span = f'<span class="ip-flag" title="{escape(ip_data.get("country", ""))}">{flag}</span>' if flag else ''
            return f"""
        <div class="widget ip-widget" id="nav-ip">
            <div class="widget-header"><span class="widget-icon">◉</span> ORIGIN IP INTELLIGENCE</div>
            <div class="ip-grid">
                <div class="ip-main">
                    <div class="ip-address">{ioc_ip_html(source_ip, geo=ip_data)}</div>
                    <div class="ip-org">{escape(ip_data.get('org','') or ip_data.get('isp',''))}</div>
                    <div class="ip-asn">{escape(ip_data.get('as',''))}</div>
                </div>
                <div class="ip-geo">
                    <div class="geo-row"><span class="geo-label">LOCATION</span><span class="geo-val">{escape(ip_data.get('city',''))}, {escape(ip_data.get('regionName',''))}</span></div>
                    <div class="geo-row"><span class="geo-label">COUNTRY</span><span class="geo-val">{flag_span} {escape(ip_data.get('country',''))} [{escape(ip_data.get('countryCode',''))}]</span></div>
                    <div class="geo-row"><span class="geo-label">COORDS</span><span class="geo-val mono">{ip_data.get('lat','—')}, {ip_data.get('lon','—')}</span></div>
                    <div class="geo-row"><span class="geo-label">TIMEZONE</span><span class="geo-val">{escape(ip_data.get('timezone',''))}</span></div>
                    {"" if not analysis.get("sender_local_time") else f'<div class="geo-row"><span class="geo-label">SENDER TIME</span><span class="geo-val" style="color:var(--accent)">{escape(analysis["sender_local_time"])}</span></div>'}
                    <div class="geo-row"><span class="geo-label">ISP</span><span class="geo-val">{escape(ip_data.get('isp',''))}</span></div>
                </div>
            </div>
        </div>"""
        else:
            err = ip_data.get("error", "skipped") if ip_data else "skipped"
            return f"""
        <div class="widget ip-widget" id="nav-ip">
            <div class="widget-header"><span class="widget-icon">◉</span> ORIGIN IP</div>
            <div class="ip-main" style="padding:18px"><div class="ip-address">{ioc_ip_html(source_ip)}</div><div class="dim">{escape(err)}</div></div>
        </div>"""
