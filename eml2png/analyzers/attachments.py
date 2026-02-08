"""Attachment threat assessment."""

from ..constants import DANGEROUS_EXTENSIONS, MACRO_EXTENSIONS
from .base import BaseAnalyzer

EXTENSION_MIME_MAP = {
    ".pdf": {"application/pdf"},
    ".doc": {"application/msword"},
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ".xls": {"application/vnd.ms-excel"},
    ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".png": {"image/png"},
    ".txt": {"text/plain"},
    ".csv": {"text/csv", "text/plain"},
    ".zip": {"application/zip", "application/x-zip-compressed"},
}

DANGEROUS_MIMES = {
    "application/x-msdownload", "application/x-executable", "application/x-dosexec",
    "application/x-msdos-program", "application/x-sh", "application/x-shellscript",
    "application/vnd.microsoft.portable-executable",
}


class AttachmentAnalyzer(BaseAnalyzer):
    def analyze(self, parsed: dict) -> dict:
        results = []
        for att in parsed["attachments"]:
            name = att["name"]
            flags = []

            ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if ext in DANGEROUS_EXTENSIONS:
                flags.append(("DANGEROUS EXTENSION", "critical"))
            if ext in MACRO_EXTENSIONS:
                flags.append(("MACRO-ENABLED", "critical"))

            parts = name.rsplit(".", 2)
            if len(parts) >= 3:
                fake_ext = "." + parts[-2].lower()
                real_ext = "." + parts[-1].lower()
                if fake_ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}:
                    if real_ext in DANGEROUS_EXTENSIONS:
                        flags.append(("DOUBLE EXTENSION", "critical"))

            if ext in {".zip", ".rar", ".7z"}:
                flags.append(("ARCHIVE", "warning"))

            mime_type = (att.get("mime_type") or att.get("content_type") or "").lower().split(";")[0].strip()
            if mime_type and mime_type != "application/octet-stream":
                expected_mimes = EXTENSION_MIME_MAP.get(ext)
                if expected_mimes and mime_type not in expected_mimes:
                    flags.append(("MIME MISMATCH", "critical"))
                if mime_type in DANGEROUS_MIMES and ext not in DANGEROUS_EXTENSIONS:
                    flags.append(("DANGEROUS MIME TYPE", "critical"))

            results.append({**att, "ext": ext, "flags": flags})

        return {"attachments": results}
