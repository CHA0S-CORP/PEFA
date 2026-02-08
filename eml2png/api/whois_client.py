"""WHOIS domain age lookup client."""

from datetime import datetime

from ..deps import whois_lib


class WhoisClient:
    @staticmethod
    def lookup(domain: str) -> dict:
        if not whois_lib:
            return {"error": "python-whois not installed"}
        try:
            w = whois_lib.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if not isinstance(creation, datetime):
                return {"domain": domain, "age_days": None, "creation_date": None, "error": "unparseable creation date"}
            if creation:
                age_days = (datetime.now() - creation).days
                return {
                    "creation_date": creation.strftime("%Y-%m-%d"),
                    "age_days": age_days,
                    "registrar": w.registrar or "",
                }
            return {"error": "no creation date"}
        except Exception as e:
            return {"error": str(e)}
