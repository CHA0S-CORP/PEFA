"""urlscan.io search client."""

import os
from urllib.parse import urlparse

from ..deps import req_lib
from .base import BaseAPIClient


class URLScanClient(BaseAPIClient):
    @staticmethod
    def lookup(url: str) -> dict:
        api_key = os.environ.get("URLSCAN_API_KEY", "")
        if not req_lib:
            return {"error": "requests not installed"}
        try:
            domain = urlparse(url).hostname or ""
            headers = {}
            if api_key:
                headers["API-Key"] = api_key
            r = req_lib.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1",
                headers=headers, timeout=8,
            )
            data = r.json()
            results = data.get("results", [])
            if results:
                res = results[0]
                return {
                    "verdict": res.get("verdicts", {}).get("overall", {}),
                    "page": res.get("page", {}),
                    "stats": res.get("stats", {}),
                    "url": f"https://urlscan.io/result/{res.get('_id', '')}/",
                }
            return {"info": "no results"}
        except Exception as e:
            return {"error": str(e)}
