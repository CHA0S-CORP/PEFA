"""AlienVault OTX API v1 client."""

import os

from .base import BaseAPIClient


class AlienVaultClient(BaseAPIClient):
    _API_KEY_VAR = "OTX_API_KEY"
    _BASE = "https://otx.alienvault.com/api/v1"

    @classmethod
    def available(cls) -> bool:
        return cls._has_requests() and bool(os.environ.get(cls._API_KEY_VAR))

    @classmethod
    def _headers(cls) -> dict:
        return {"X-OTX-API-KEY": os.environ.get(cls._API_KEY_VAR, "")}

    @classmethod
    def _parse(cls, data: dict) -> dict:
        if "error" in data:
            return data
        pulse_info = data.get("pulse_info", {})
        return {
            "pulse_count": pulse_info.get("count", 0),
            "reputation": data.get("reputation", 0),
        }

    @classmethod
    def lookup_ip(cls, ip: str) -> dict:
        if not cls.available():
            return {"error": "AlienVault OTX not configured"}
        return cls._parse(
            cls._get(f"{cls._BASE}/indicators/IPv4/{ip}/general", headers=cls._headers())
        )

    @classmethod
    def lookup_domain(cls, domain: str) -> dict:
        if not cls.available():
            return {"error": "AlienVault OTX not configured"}
        return cls._parse(
            cls._get(f"{cls._BASE}/indicators/domain/{domain}/general", headers=cls._headers())
        )

    @classmethod
    def lookup_url(cls, url: str) -> dict:
        if not cls.available():
            return {"error": "AlienVault OTX not configured"}
        return cls._parse(
            cls._get(f"{cls._BASE}/indicators/url/{url}/general", headers=cls._headers())
        )

    @classmethod
    def lookup_hash(cls, file_hash: str) -> dict:
        if not cls.available():
            return {"error": "AlienVault OTX not configured"}
        return cls._parse(
            cls._get(f"{cls._BASE}/indicators/file/{file_hash}/general", headers=cls._headers())
        )
