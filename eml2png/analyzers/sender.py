"""Sender spoofing detection."""

import re

from ..utils import check_brand_impersonation, check_homoglyph_domain
from .base import BaseAnalyzer


class SenderAnalyzer(BaseAnalyzer):
    def analyze(self, parsed: dict) -> dict:
        headers = parsed["headers"]
        findings = []
        flags = []

        from_header = headers.get("From", "")
        return_path = headers.get("Return-Path", "")
        reply_to = headers.get("Reply-To", "")

        from_match = re.match(r'^["\']?(.+?)["\']?\s*<(.+?)>$', from_header)
        from_display = from_match.group(1).strip() if from_match else ""
        from_email = from_match.group(2).strip() if from_match else from_header.strip()
        from_domain = from_email.split("@")[-1] if "@" in from_email else ""

        if from_display and "@" in from_display:
            display_email_domain = from_display.split("@")[-1].strip(">").strip('"').strip()
            if display_email_domain.lower() != from_domain.lower():
                flags.append(("DISPLAY NAME SPOOFING", "critical"))
                findings.append(f"Display name contains different email: '{from_display}'")

        rp_email = re.search(r"<(.+?)>", return_path)
        rp_email = rp_email.group(1) if rp_email else return_path.strip()
        rp_domain = rp_email.split("@")[-1] if "@" in rp_email else ""
        if rp_domain and from_domain and rp_domain.lower() != from_domain.lower():
            flags.append(("RETURN-PATH MISMATCH", "warning"))
            findings.append(f"Return-Path domain ({rp_domain}) ≠ From domain ({from_domain})")

        if reply_to:
            rt_match = re.search(r"<(.+?)>", reply_to)
            rt_email = rt_match.group(1) if rt_match else reply_to.strip()
            rt_domain = rt_email.split("@")[-1] if "@" in rt_email else ""
            if rt_domain and from_domain and rt_domain.lower() != from_domain.lower():
                flags.append(("REPLY-TO MISMATCH", "critical"))
                findings.append(f"Reply-To ({rt_email}) differs from From ({from_email})")

        brand, is_impersonation = check_brand_impersonation(from_domain)
        if is_impersonation:
            flags.append(("DOMAIN IMPERSONATION", "critical"))
            findings.append(f"Sender domain '{from_domain}' may impersonate '{brand}'")

        normalized_domain, has_homoglyphs = check_homoglyph_domain(from_domain)
        if has_homoglyphs:
            flags.append(("HOMOGLYPH DOMAIN", "critical"))
            findings.append(f"Sender domain '{from_domain}' contains homoglyph characters (normalized: '{normalized_domain}')")

        return {
            "from_display": from_display,
            "from_email": from_email,
            "from_domain": from_domain,
            "return_path": rp_email,
            "rp_domain": rp_domain,
            "reply_to": reply_to,
            "flags": flags,
            "findings": findings,
        }
