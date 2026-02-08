"""AbuseIPDB API v2 client."""

import os

from .base import BaseAPIClient


class AbuseIPDBClient(BaseAPIClient):
    _API_KEY_VAR = "ABUSEIPDB_API_KEY"
    _BASE = "https://api.abuseipdb.com/api/v2"

    @classmethod
    def available(cls) -> bool:
        return cls._has_requests() and bool(os.environ.get(cls._API_KEY_VAR))

    @classmethod
    def lookup(cls, ip: str) -> dict:
        if not cls.available():
            return {"error": "AbuseIPDB not configured"}
        headers = {
            "Key": os.environ.get(cls._API_KEY_VAR, ""),
            "Accept": "application/json",
        }
        data = cls._get(
            f"{cls._BASE}/check?ipAddress={ip}&maxAgeInDays=90",
            headers=headers,
        )
        if "error" in data:
            return data
        d = data.get("data", {})
        return {
            "abuseConfidenceScore": d.get("abuseConfidenceScore", 0),
            "totalReports": d.get("totalReports", 0),
            "isWhitelisted": d.get("isWhitelisted", False),
            "countryCode": d.get("countryCode", ""),
            "isp": d.get("isp", ""),
        }
