"""Utility functions."""

from email.utils import parsedate_to_datetime

from .constants import KNOWN_BRANDS, HOMOGLYPH_MAP

LEGITIMATE_TLDS = (".com", ".net", ".org", ".io", ".co", ".co.uk")


def check_brand_impersonation(domain: str):
    """Check if a domain impersonates a known brand.

    Returns (brand, True) if impersonation detected, (None, False) otherwise.
    """
    domain_lower = domain.lower().replace("-", "").replace(".", "")
    for brand in KNOWN_BRANDS:
        if brand in domain_lower and brand + "." not in domain.lower():
            legit_patterns = [f"{brand}{tld}" for tld in LEGITIMATE_TLDS]
            if not any(domain.lower().endswith(p) for p in legit_patterns):
                return brand, True
    return None, False


def check_homoglyph_domain(domain: str):
    """Normalize a domain by replacing homoglyphs with ASCII equivalents.

    Returns (normalized_domain, has_homoglyphs).
    """
    reverse_map = {}
    for ascii_char, glyphs in HOMOGLYPH_MAP.items():
        for glyph in glyphs:
            if len(glyph) == 1 and not glyph.isascii():  # non-ASCII single-char homoglyphs only
                reverse_map[glyph] = ascii_char

    normalized = []
    has_homoglyphs = False
    for ch in domain:
        if ch in reverse_map:
            normalized.append(reverse_map[ch])
            has_homoglyphs = True
        else:
            normalized.append(ch)

    return "".join(normalized), has_homoglyphs


def fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024**2:
        return f"{n/1024:.1f} KB"
    return f"{n/1024**2:.1f} MB"


def convert_to_sender_timezone(date_header: str, timezone_name: str):
    """Convert an email Date header to the sender's inferred local timezone.

    Returns (formatted_time_str, tz_abbrev) or None on any failure.
    """
    try:
        from zoneinfo import ZoneInfo
    except ImportError:
        return None
    if not date_header or not timezone_name:
        return None
    try:
        dt = parsedate_to_datetime(date_header)
        tz = ZoneInfo(timezone_name)
        local_dt = dt.astimezone(tz)
        abbrev = local_dt.strftime("%Z") or timezone_name
        formatted = local_dt.strftime("%Y-%m-%d %H:%M:%S") + f" ({abbrev})"
        return formatted, abbrev
    except Exception:
        return None


def resolve_hostname(hostname: str) -> str:
    """Resolve a hostname to an IP address via DNS (tries IPv4, then IPv6). Returns '' on failure."""
    import socket
    import re
    if not hostname:
        return ""
    # Already an IP address
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        return ""
    if re.match(r"^[0-9a-fA-F:]+$", hostname) and ":" in hostname:
        return ""
    # Try IPv4 first
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        if results:
            return results[0][4][0]
    except (socket.gaierror, OSError, IndexError):
        pass
    # Fall back to IPv6
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM)
        if results:
            return results[0][4][0]
    except (socket.gaierror, OSError, IndexError):
        pass
    return ""


def country_code_to_flag(code: str) -> str:
    """Convert a 2-letter country code to a flag emoji."""
    if not code or len(code) != 2:
        return ""
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code.upper())
