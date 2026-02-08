"""IOC linking helpers — VirusTotal and urlscan.io lookup links."""

from html import escape
from urllib.parse import quote

from ..utils import country_code_to_flag


def vt_url_link(url: str) -> str:
    vt = f"https://www.virustotal.com/gui/search/{quote(url, safe='')}"
    return f'<a href="{escape(vt)}" target="_blank" rel="noopener" class="ioc-link vt" title="Look up on VirusTotal">{escape(url)}<span class="ioc-badge vt-badge">VT</span></a>'


def vt_domain_link(domain: str) -> str:
    vt = f"https://www.virustotal.com/gui/domain/{quote(domain, safe='')}"
    return f'<a href="{escape(vt)}" target="_blank" rel="noopener" class="ioc-link vt" title="Look up on VirusTotal">{escape(domain)}<span class="ioc-badge vt-badge">VT</span></a>'


def vt_ip_link(ip: str) -> str:
    vt = f"https://www.virustotal.com/gui/ip-address/{quote(ip, safe='')}"
    return f'<a href="{escape(vt)}" target="_blank" rel="noopener" class="ioc-link vt" title="Look up on VirusTotal">{escape(ip)}<span class="ioc-badge vt-badge">VT</span></a>'


def urlscan_domain_link(domain: str) -> str:
    us = f"https://urlscan.io/search/#{quote(domain, safe='')}"
    return f'<a href="{escape(us)}" target="_blank" rel="noopener" class="ioc-link us" title="Look up on urlscan.io">{escape(domain)}<span class="ioc-badge us-badge">US</span></a>'


def urlscan_url_link(url: str) -> str:
    us = f"https://urlscan.io/search/#{quote(url, safe='')}"
    return f'<a href="{escape(us)}" target="_blank" rel="noopener" class="ioc-link us" title="Look up on urlscan.io">{escape(url)}<span class="ioc-badge us-badge">US</span></a>'


def ioc_url_html(url: str) -> str:
    vt = f"https://www.virustotal.com/gui/search/{quote(url, safe='')}"
    us = f"https://urlscan.io/search/#{quote(url, safe='')}"
    return (f'<span class="ioc-wrap">{escape(url[:120])}'
            f'<a href="{escape(vt)}" target="_blank" rel="noopener" class="ioc-badge vt-badge" title="VirusTotal">VT</a>'
            f'<a href="{escape(us)}" target="_blank" rel="noopener" class="ioc-badge us-badge" title="urlscan.io">US</a>'
            f'</span>')


def ioc_email_html(addr: str) -> str:
    domain = addr.split("@")[-1] if "@" in addr else ""
    if domain:
        vt = f"https://www.virustotal.com/gui/domain/{quote(domain, safe='')}"
        badge = f'<a href="{escape(vt)}" target="_blank" rel="noopener" class="ioc-badge vt-badge" title="VirusTotal domain lookup">VT</a>'
    else:
        badge = ""
    return f'<span class="ioc-wrap">{escape(addr)}{badge}</span>'


def ioc_ip_html(ip: str, geo=None) -> str:
    vt = f"https://www.virustotal.com/gui/ip-address/{quote(ip, safe='')}"
    us = f"https://urlscan.io/search/#{quote(ip, safe='')}"
    flag_html = ""
    if geo and isinstance(geo, dict) and "error" not in geo:
        cc = geo.get("countryCode", "")
        flag = country_code_to_flag(cc)
        if flag:
            tip_parts = [geo.get("country", "")]
            if geo.get("city"):
                tip_parts.append(geo["city"])
            if geo.get("isp"):
                tip_parts.append(geo["isp"])
            tip = escape(", ".join(p for p in tip_parts if p))
            flag_html = f'<span class="ip-flag" title="{tip}">{flag}</span>'
    return (f'<span class="ioc-wrap">{escape(ip)}{flag_html}'
            f'<a href="{escape(vt)}" target="_blank" rel="noopener" class="ioc-badge vt-badge" title="VirusTotal">VT</a>'
            f'<a href="{escape(us)}" target="_blank" rel="noopener" class="ioc-badge us-badge" title="urlscan.io">US</a>'
            f'</span>')
