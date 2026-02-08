"""IP geolocation lookup and delivery path parsing."""

import re

from ..constants import PRIVATE_IP_RE
from ..deps import req_lib
from .base import BaseAPIClient


class IPLookupClient(BaseAPIClient):
    # IPv6 in email headers is typically enclosed in parens or brackets
    _IPV6_HDR_RE = re.compile(r"[\(\[]([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})[\)\]]")

    @classmethod
    def extract_ips(cls, received_headers: list) -> list:
        ips = []
        ipv4_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        for hdr in reversed(received_headers):
            for ip in ipv4_re.findall(hdr):
                if any(int(o) > 255 for o in ip.split('.')):
                    continue
                if not PRIVATE_IP_RE.match(ip) and ip not in ips:
                    ips.append(ip)
            for ip in cls._IPV6_HDR_RE.findall(hdr):
                if not PRIVATE_IP_RE.match(ip) and ip not in ips:
                    ips.append(ip)
        return ips

    _IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    _IPV6_RE = re.compile(r'^[0-9a-fA-F:]+$')

    @classmethod
    def is_valid_ip(cls, ip: str) -> bool:
        if cls._IPV4_RE.match(ip):
            return not any(int(o) > 255 for o in ip.split('.'))
        return bool(cls._IPV6_RE.match(ip) and ':' in ip)

    @staticmethod
    def lookup(ip: str) -> dict:
        is_v4 = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip)
        is_v6 = not is_v4 and re.match(r'^[0-9a-fA-F:]+$', ip) and ':' in ip
        if is_v4 and any(int(o) > 255 for o in ip.split('.')):
            return {"error": "invalid IP"}
        if not is_v4 and not is_v6:
            return {"error": "invalid IP"}
        if not req_lib:
            return {"error": "requests not installed"}
        try:
            r = req_lib.get(
                f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,"
                f"region,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
                timeout=5,
            )
            data = r.json()
            return data if data.get("status") == "success" else {"error": data.get("message", "failed")}
        except Exception as e:
            return {"error": str(e)}

    @classmethod
    def parse_hops(cls, received_headers: list) -> list:
        hops = []
        from_re = re.compile(r"from\s+([\w.\-]+)", re.I)
        by_re = re.compile(r"by\s+([\w.\-]+)", re.I)
        ipv4_re = re.compile(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?")
        date_re = re.compile(r";\s*(.+)$")

        for i, hdr in enumerate(received_headers):
            hop = {"index": len(received_headers) - i, "raw": hdr.strip()}
            fm = from_re.search(hdr)
            bm = by_re.search(hdr)
            dm = date_re.search(hdr)
            if fm:
                hop["from"] = fm.group(1)
            if bm:
                hop["by"] = bm.group(1)
            # Try IPv4 first, fall back to bracketed/parenthesized IPv6
            im4 = ipv4_re.search(hdr)
            if im4:
                hop["ip"] = im4.group(1)
            else:
                im6 = cls._IPV6_HDR_RE.search(hdr)
                if im6:
                    hop["ip"] = im6.group(1)
            if dm:
                hop["date"] = dm.group(1).strip()[:50]
            hops.append(hop)
        return hops
