"""MXToolbox SPF/DKIM/DMARC validation client."""

import os

from ..deps import req_lib
from .base import BaseAPIClient


class MXToolboxClient(BaseAPIClient):
    @staticmethod
    def lookup(domain: str) -> dict:
        api_key = os.environ.get("MXTOOLBOX_API_KEY", "")
        if not api_key or not req_lib:
            return {"error": "no API key or requests not installed"}

        results = {}
        headers = {"Authorization": api_key}

        for check in ("spf", "dkim", "dmarc"):
            try:
                r = req_lib.get(
                    f"https://mxtoolbox.com/api/v1/lookup/{check}/{domain}",
                    headers=headers,
                    timeout=8,
                )
                data = r.json()
                failed = data.get("Failed", [])
                warnings = data.get("Warnings", [])
                passed = data.get("Passed", [])
                info = data.get("Information", [])

                if failed:
                    status = "fail"
                elif warnings:
                    status = "warning"
                elif passed:
                    status = "pass"
                else:
                    status = "unknown"

                results[check] = {
                    "status": status,
                    "failed": failed,
                    "warnings": warnings,
                    "passed": passed,
                    "info": info,
                }
            except Exception as e:
                results[check] = {"error": str(e)}

        return results
