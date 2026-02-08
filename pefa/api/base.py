"""Base API client with shared HTTP helpers."""

from abc import ABC

from ..deps import req_lib


class BaseAPIClient(ABC):
    @staticmethod
    def _has_requests() -> bool:
        return req_lib is not None

    @staticmethod
    def _get(url: str, headers: dict = None, timeout: int = 8) -> dict:
        if not req_lib:
            return {"error": "requests not installed"}
        try:
            r = req_lib.get(url, headers=headers or {}, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _post(url: str, headers: dict = None, json_data: dict = None, timeout: int = 30) -> dict:
        if not req_lib:
            return {"error": "requests not installed"}
        try:
            r = req_lib.post(url, headers=headers or {}, json=json_data, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"error": str(e)}
