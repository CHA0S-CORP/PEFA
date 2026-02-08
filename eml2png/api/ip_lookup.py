"""IP geolocation lookup and delivery path parsing."""

import re

from ..constants import PRIVATE_IP_RE
from ..deps import req_lib
from .base import BaseAPIClient


class IPLookupClient(BaseAPIClient):
    @staticmethod
    def extract_ips(received_headers: list) -> list:
        ips = []
        ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        for hdr in reversed(received_headers):
            for ip in ip_re.findall(hdr):
                if any(int(o) > 255 for o in ip.split('.')):
                    continue
                if not PRIVATE_IP_RE.match(ip) and ip not in ips:
                    ips.append(ip)
        return ips

    @staticmethod
    def lookup(ip: str) -> dict:
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) or \
                any(int(o) > 255 for o in ip.split('.')):
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

    @staticmethod
    def parse_hops(received_headers: list) -> list:
        hops = []
        from_re = re.compile(r"from\s+([\w.\-]+)", re.I)
        by_re = re.compile(r"by\s+([\w.\-]+)", re.I)
        ip_re = re.compile(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?")
        date_re = re.compile(r";\s*(.+)$")

        for i, hdr in enumerate(received_headers):
            hop = {"index": len(received_headers) - i, "raw": hdr.strip()}
            fm = from_re.search(hdr)
            bm = by_re.search(hdr)
            im = ip_re.search(hdr)
            dm = date_re.search(hdr)
            if fm:
                hop["from"] = fm.group(1)
            if bm:
                hop["by"] = bm.group(1)
            if im:
                hop["ip"] = im.group(1)
            if dm:
                hop["date"] = dm.group(1).strip()[:50]
            hops.append(hop)
        return hops
