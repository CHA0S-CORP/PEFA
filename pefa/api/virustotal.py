"""VirusTotal API v3 client."""

import base64
import os

from .base import BaseAPIClient


class VirusTotalClient(BaseAPIClient):
    _API_KEY_VAR = "VT_API_KEY"
    _BASE = "https://www.virustotal.com/api/v3"

    @classmethod
    def available(cls) -> bool:
        return cls._has_requests() and bool(os.environ.get(cls._API_KEY_VAR))

    @classmethod
    def _headers(cls) -> dict:
        return {"x-apikey": os.environ.get(cls._API_KEY_VAR, "")}

    @classmethod
    def lookup_ip(cls, ip: str) -> dict:
        if not cls.available():
            return {"error": "VirusTotal not configured"}
        data = cls._get(f"{cls._BASE}/ip_addresses/{ip}", headers=cls._headers())
        if "error" in data:
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
        }

    @classmethod
    def lookup_domain(cls, domain: str) -> dict:
        if not cls.available():
            return {"error": "VirusTotal not configured"}
        data = cls._get(f"{cls._BASE}/domains/{domain}", headers=cls._headers())
        if "error" in data:
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
        }

    @classmethod
    def lookup_url(cls, url: str) -> dict:
        if not cls.available():
            return {"error": "VirusTotal not configured"}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data = cls._get(f"{cls._BASE}/urls/{url_id}", headers=cls._headers())
        if "error" in data:
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

    @classmethod
    def lookup_hash(cls, file_hash: str) -> dict:
        if not cls.available():
            return {"error": "VirusTotal not configured"}
        data = cls._get(f"{cls._BASE}/files/{file_hash}", headers=cls._headers())
        if "error" in data:
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "name": attrs.get("meaningful_name", ""),
        }
