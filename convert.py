#!/usr/bin/env python3
"""
eml2png - Phishing Email Forensic Analyzer

Converts .eml files into cyber-infographic PNGs and interactive HTML reports.
Analyzes links, sender spoofing, urgency language, attachments, authentication,
delivery path, domain age, and generates a phishing threat score.

Setup:
    pip3 install playwright requests python-whois beautifulsoup4
    playwright install chromium

Optional API keys (env vars):
    GEMINI_API_KEY    - Google Gemini (free at https://aistudio.google.com/apikey)
    URLSCAN_API_KEY   - urlscan.io (free at https://urlscan.io/user/signup)
    MXTOOLBOX_API_KEY - MXToolbox (free at https://mxtoolbox.com/user/api)

Usage:
    python3 eml2png.py input.eml                     # PNG output
    python3 eml2png.py input.eml --html               # also emit interactive HTML
    python3 eml2png.py input.eml --gemini              # include AI assessment
    python3 eml2png.py input.eml --gemini-model gemini-2.5-pro  # pick model
    python3 eml2png.py input.eml --width 1100          # wider viewport
    python3 eml2png.py input.eml --scale 2             # retina
    python3 eml2png.py input.eml --no-api              # skip all API calls
    python3 eml2png.py ./emails/ -o ./reports/         # batch
"""

import argparse
import base64
import email
import email.policy
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import urlparse, urljoin

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("pip3 install playwright && playwright install chromium")

try:
    import requests as req_lib
except ImportError:
    req_lib = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    import whois as whois_lib
except ImportError:
    whois_lib = None


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc",
    ".click", ".link", ".site", ".online", ".icu", ".buzz", ".fun",
    ".monster", ".rest", ".cam", ".surf", ".best", ".cyou", ".cfd",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "bl.ink", "short.io", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "lnkd.in", "qr.ae",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd",
    ".ps1", ".msi", ".dll", ".com", ".pif", ".wsf", ".wsh", ".cpl",
    ".iso", ".img", ".vhd", ".vhdx",
    ".html", ".htm", ".hta", ".svg",
    ".lnk", ".url", ".reg",
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}

URGENCY_PATTERNS = [
    (r"\bimmediate(?:ly)?\s+action\b", "immediate action"),
    (r"\burgent(?:ly)?\b", "urgent"),
    (r"\bexpir(?:es?|ing|ed|ation)\b", "expiration"),
    (r"\bsuspend(?:ed)?\b", "suspended"),
    (r"\bverif(?:y|ication)\b", "verify"),
    (r"\bconfirm\s+(?:your|identity|account)\b", "confirm identity"),
    (r"\bunauthori[sz]ed\b", "unauthorized"),
    (r"\bsecurity\s+alert\b", "security alert"),
    (r"\bwithin\s+\d+\s*(?:hour|day|minute)\b", "time pressure"),
    (r"\byour\s+account\s+(?:has been|will be|is)\b", "account threat"),
    (r"\bclick\s+here\b", "click here"),
    (r"\bact\s+now\b", "act now"),
    (r"\blimited\s+time\b", "limited time"),
    (r"\bfailure\s+to\b", "failure to"),
    (r"\bfinal\s+(?:notice|warning|reminder)\b", "final notice"),
    (r"\block(?:ed)?\s+out\b", "locked out"),
    (r"\bdeactivat(?:e|ed|ion)\b", "deactivation"),
    (r"\bunusual\s+(?:activity|sign.?in|login)\b", "unusual activity"),
    (r"\brestr(?:ict|ained)\b", "restricted"),
    (r"\bpenalt(?:y|ies)\b", "penalty"),
    (r"\blegal\s+action\b", "legal action"),
    (r"\bdo\s+not\s+ignore\b", "do not ignore"),
    (r"\brequired\s+(?:action|update|verification)\b", "required action"),
    (r"\bwe\s+(?:noticed|detected)\b", "we detected"),
    (r"\bsomeone\s+(?:tried|attempted)\b", "someone attempted"),
]

GENERIC_GREETINGS = [
    r"\bdear\s+(?:customer|user|client|member|sir|madam|valued|account\s+holder)\b",
    r"\bhello\s+(?:customer|user|client|member)\b",
    r"\bto\s+whom\s+it\s+may\s+concern\b",
    r"\bdear\s+(?:sir|madam)\b",
]

HOMOGLYPH_MAP = {
    "a": ["а", "ɑ", "α"],  # cyrillic а, latin alpha
    "c": ["с", "ϲ"],
    "d": ["ԁ", "ɗ"],
    "e": ["е", "ε", "ё"],
    "g": ["ɡ"],
    "h": ["һ"],
    "i": ["і", "ι", "1", "l"],
    "j": ["ј"],
    "k": ["κ"],
    "l": ["1", "i", "ⅼ", "ⅰ"],
    "m": ["rn", "ⅿ"],
    "n": ["ո"],
    "o": ["о", "ο", "0"],
    "p": ["р", "ρ"],
    "q": ["ԛ"],
    "s": ["ѕ", "ꜱ"],
    "t": ["τ"],
    "u": ["υ", "ս"],
    "v": ["ν", "ⅴ"],
    "w": ["ω", "vv", "ⅳ"],
    "x": ["х", "χ"],
    "y": ["у", "γ"],
    "z": ["ⅿ"],
}

# Common legit domains for lookalike detection
KNOWN_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix", "facebook",
    "instagram", "linkedin", "twitter", "chase", "wellsfargo", "bankofamerica",
    "citibank", "usps", "fedex", "ups", "dhl", "irs", "costco", "walmart",
    "target", "bestbuy", "ebay", "dropbox", "icloud", "outlook", "yahoo",
    "docusign", "adobe", "zoom", "slack", "stripe", "shopify", "coinbase",
]


# ═══════════════════════════════════════════════════════════════════════════════
# EMAIL PARSING
# ═══════════════════════════════════════════════════════════════════════════════

def parse_eml(eml_path: str) -> dict:
    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    headers = {}
    for key in [
        "From", "To", "Cc", "Bcc", "Reply-To", "Date", "Subject",
        "Message-ID", "X-Mailer", "User-Agent", "MIME-Version",
        "Content-Type", "Return-Path", "X-Originating-IP",
    ]:
        val = msg.get(key, "")
        if val:
            headers[key] = val

    received = msg.get_all("Received") or []
    auth_results = msg.get("Authentication-Results", "")
    dkim_sig = msg.get("DKIM-Signature", "")

    auth = {"spf": "", "dkim": "", "dmarc": ""}
    if auth_results:
        for proto in ("spf", "dkim", "dmarc"):
            m = re.search(rf"{proto}=(\w+)", auth_results, re.I)
            if m:
                auth[proto] = m.group(1)

    html_body = None
    text_body = None
    inline_images = {}
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            cid = part.get("Content-ID", "")

            if cid and ct.startswith("image/"):
                payload = part.get_payload(decode=True)
                if payload:
                    b64 = base64.b64encode(payload).decode("ascii")
                    inline_images[cid.strip("<>")] = f"data:{ct};base64,{b64}"

            if "attachment" in disp:
                fname = part.get_filename() or "unnamed"
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "name": fname,
                    "type": ct,
                    "size": len(payload),
                    "md5": hashlib.md5(payload).hexdigest() if payload else "",
                    "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
                })
                continue

            if ct == "text/html" and html_body is None:
                html_body = part.get_content()
            elif ct == "text/plain" and text_body is None:
                text_body = part.get_content()
    else:
        if msg.get_content_type() == "text/html":
            html_body = msg.get_content()
        else:
            text_body = msg.get_content()

    if html_body and inline_images:
        for cid, uri in inline_images.items():
            html_body = html_body.replace(f"cid:{cid}", uri)

    return {
        "headers": headers,
        "received": received,
        "auth": auth,
        "dkim_signature": dkim_sig,
        "html_body": html_body,
        "text_body": text_body,
        "attachments": attachments,
        "raw_msg": msg,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS MODULES
# ═══════════════════════════════════════════════════════════════════════════════

def extract_plain_text(parsed: dict) -> str:
    """Get plain text from email, stripping HTML if needed."""
    if parsed["text_body"]:
        return parsed["text_body"]
    if parsed["html_body"] and BeautifulSoup:
        soup = BeautifulSoup(parsed["html_body"], "html.parser")
        return soup.get_text(separator=" ", strip=True)
    if parsed["html_body"]:
        return re.sub(r"<[^>]+>", " ", parsed["html_body"])
    return ""


def analyze_links(parsed: dict) -> dict:
    """Extract and analyze all links in the email."""
    links = []
    if not parsed["html_body"]:
        return {"links": [], "findings": []}

    if BeautifulSoup:
        soup = BeautifulSoup(parsed["html_body"], "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            display = a.get_text(strip=True) or ""
            links.append({"href": href, "display": display})
    else:
        for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', parsed["html_body"], re.I | re.S):
            href = m.group(1).strip()
            display = re.sub(r"<[^>]+>", "", m.group(2)).strip()
            links.append({"href": href, "display": display})

    findings = []
    analyzed = []

    for link in links:
        href = link["href"]
        display = link["display"]
        flags = []

        if not href or href.startswith("mailto:") or href.startswith("#"):
            continue

        try:
            parsed_url = urlparse(href)
            domain = parsed_url.hostname or ""
            tld = "." + domain.split(".")[-1] if "." in domain else ""
        except Exception:
            domain = ""
            tld = ""
            flags.append(("MALFORMED URL", "critical"))

        # Display text vs href mismatch
        display_clean = display.strip().lower()
        if display_clean.startswith("http") or re.match(r"[\w.-]+\.\w{2,}", display_clean):
            try:
                display_domain = urlparse(display_clean if "://" in display_clean else "http://" + display_clean).hostname or ""
            except Exception:
                display_domain = ""
            if display_domain and domain and display_domain.lower() != domain.lower():
                flags.append(("HREF MISMATCH", "critical"))
                findings.append(f"Link text shows '{display_domain}' but goes to '{domain}'")

        # URL shortener
        if domain.lower() in URL_SHORTENERS:
            flags.append(("URL SHORTENER", "warning"))
            findings.append(f"Shortened URL via {domain}")

        # IP-based URL
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            flags.append(("IP-BASED URL", "critical"))
            findings.append(f"Direct IP address URL: {domain}")

        # Suspicious TLD
        if tld.lower() in SUSPICIOUS_TLDS:
            flags.append(("SUSPICIOUS TLD", "warning"))

        # Lookalike domain detection
        domain_lower = domain.lower().replace("-", "").replace(".", "")
        for brand in KNOWN_BRANDS:
            if brand in domain_lower and brand + "." not in domain.lower():
                # check it's not the actual domain
                legit_patterns = [f"{brand}.com", f"{brand}.net", f"{brand}.org", f"{brand}.io", f"{brand}.co"]
                if not any(domain.lower().endswith(p) for p in legit_patterns):
                    flags.append(("BRAND LOOKALIKE", "critical"))
                    findings.append(f"Domain '{domain}' mimics '{brand}'")
                    break

        # Homoglyph / punycode
        if domain.startswith("xn--"):
            flags.append(("PUNYCODE DOMAIN", "warning"))
            findings.append(f"Internationalized domain (punycode): {domain}")

        # data: URI or javascript:
        if href.lower().startswith("javascript:"):
            flags.append(("JAVASCRIPT URI", "critical"))
        if href.lower().startswith("data:"):
            flags.append(("DATA URI", "critical"))

        analyzed.append({
            "href": href,
            "display": display,
            "domain": domain,
            "flags": flags,
        })

    return {"links": analyzed, "findings": list(set(findings))}


def analyze_sender(parsed: dict) -> dict:
    """Detect sender spoofing indicators."""
    headers = parsed["headers"]
    findings = []
    flags = []

    from_header = headers.get("From", "")
    return_path = headers.get("Return-Path", "")
    reply_to = headers.get("Reply-To", "")

    # Parse From: display name vs email
    from_match = re.match(r'^["\']?(.+?)["\']?\s*<(.+?)>$', from_header)
    from_display = from_match.group(1).strip() if from_match else ""
    from_email = from_match.group(2).strip() if from_match else from_header.strip()
    from_domain = from_email.split("@")[-1] if "@" in from_email else ""

    # Display name contains email address (spoofing trick)
    if from_display and "@" in from_display:
        display_email_domain = from_display.split("@")[-1].strip(">").strip('"').strip()
        if display_email_domain.lower() != from_domain.lower():
            flags.append(("DISPLAY NAME SPOOFING", "critical"))
            findings.append(f"Display name contains different email: '{from_display}'")

    # Return-Path mismatch
    rp_email = re.search(r"<(.+?)>", return_path)
    rp_email = rp_email.group(1) if rp_email else return_path.strip()
    rp_domain = rp_email.split("@")[-1] if "@" in rp_email else ""
    if rp_domain and from_domain and rp_domain.lower() != from_domain.lower():
        flags.append(("RETURN-PATH MISMATCH", "warning"))
        findings.append(f"Return-Path domain ({rp_domain}) ≠ From domain ({from_domain})")

    # Reply-To mismatch
    if reply_to:
        rt_match = re.search(r"<(.+?)>", reply_to)
        rt_email = rt_match.group(1) if rt_match else reply_to.strip()
        rt_domain = rt_email.split("@")[-1] if "@" in rt_email else ""
        if rt_domain and from_domain and rt_domain.lower() != from_domain.lower():
            flags.append(("REPLY-TO MISMATCH", "critical"))
            findings.append(f"Reply-To ({rt_email}) differs from From ({from_email})")

    # Homoglyph check on from domain
    for brand in KNOWN_BRANDS:
        d = from_domain.lower().replace("-", "").replace(".", "")
        if brand in d:
            legit = [f"{brand}.com", f"{brand}.net", f"{brand}.org", f"{brand}.io"]
            if not any(from_domain.lower().endswith(p) for p in legit):
                flags.append(("DOMAIN IMPERSONATION", "critical"))
                findings.append(f"Sender domain '{from_domain}' may impersonate '{brand}'")
                break

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


def analyze_urgency(parsed: dict) -> dict:
    """Scan for urgency and social engineering language."""
    text = extract_plain_text(parsed).lower()
    matches = []
    positions = []

    for pattern, label in URGENCY_PATTERNS:
        for m in re.finditer(pattern, text, re.I):
            matches.append(label)
            positions.append({"start": m.start(), "end": m.end(), "label": label, "text": m.group()})

    # Generic greeting check
    generic_greeting = False
    for pattern in GENERIC_GREETINGS:
        if re.search(pattern, text, re.I):
            generic_greeting = True
            matches.append("generic greeting")
            break

    density = len(matches) / max(len(text.split()), 1) * 100

    return {
        "matches": matches,
        "positions": positions,
        "unique_count": len(set(matches)),
        "total_count": len(matches),
        "density": round(density, 2),
        "generic_greeting": generic_greeting,
        "counter": dict(Counter(matches)),
    }


def analyze_attachments(parsed: dict) -> dict:
    """Assess attachment threat level."""
    results = []
    for att in parsed["attachments"]:
        name = att["name"]
        flags = []

        # Check extension
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in DANGEROUS_EXTENSIONS:
            flags.append(("DANGEROUS EXTENSION", "critical"))
        if ext in MACRO_EXTENSIONS:
            flags.append(("MACRO-ENABLED", "critical"))

        # Double extension
        parts = name.rsplit(".", 2)
        if len(parts) >= 3:
            fake_ext = "." + parts[-2].lower()
            real_ext = "." + parts[-1].lower()
            if fake_ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}:
                if real_ext in DANGEROUS_EXTENSIONS:
                    flags.append(("DOUBLE EXTENSION", "critical"))

        # Password-protected archives
        if ext in {".zip", ".rar", ".7z"}:
            flags.append(("ARCHIVE", "warning"))

        results.append({**att, "ext": ext, "flags": flags})

    return {"attachments": results}


def analyze_language(parsed: dict) -> dict:
    """Basic language quality analysis."""
    text = extract_plain_text(parsed)
    if not text or len(text) < 50:
        return {"score": None, "findings": [], "note": "insufficient text"}

    findings = []
    issues = 0
    total_sentences = len(re.split(r'[.!?]+', text))

    # Mixed character sets
    if re.search(r'[\u0400-\u04FF]', text) and re.search(r'[a-zA-Z]', text):
        findings.append("Mixed Cyrillic and Latin characters detected")
        issues += 3

    # Unusual spacing
    if re.search(r'[a-zA-Z]  +[a-zA-Z]', text):
        cnt = len(re.findall(r'[a-zA-Z]  +[a-zA-Z]', text))
        if cnt > 2:
            findings.append(f"Irregular spacing ({cnt} instances)")
            issues += 1

    # Missing articles (common non-native pattern)
    article_omissions = len(re.findall(r'\b(?:please|kindly)\s+(?:click|verify|confirm|update|provide)\b', text, re.I))
    if article_omissions > 1:
        findings.append("Imperative phrasing without articles (possible non-native)")
        issues += 1

    # Excessive capitalization
    words = text.split()
    caps_words = sum(1 for w in words if w.isupper() and len(w) > 2)
    if caps_words > 5:
        findings.append(f"Excessive capitalization ({caps_words} ALL-CAPS words)")
        issues += 1

    # Grammar score (rough heuristic, 100 = perfect)
    score = max(0, 100 - (issues * 15))

    return {"score": score, "findings": findings, "issues": issues}


def calculate_threat_score(auth, sender, links, urgency, attachments, language, ip_data, domain_age_days) -> dict:
    """Calculate overall phishing threat score 0-100."""
    score = 0
    factors = []

    # Auth failures (max 20)
    if auth.get("spf", "").lower() in ("fail", "softfail"):
        score += 10; factors.append(("SPF failure", 10))
    if auth.get("dkim", "").lower() == "fail":
        score += 5; factors.append(("DKIM failure", 5))
    if auth.get("dmarc", "").lower() == "fail":
        score += 5; factors.append(("DMARC failure", 5))
    if not auth.get("spf") and not auth.get("dkim") and not auth.get("dmarc"):
        score += 8; factors.append(("No authentication", 8))

    # Sender (max 20)
    for flag, _ in sender.get("flags", []):
        if "SPOOFING" in flag or "IMPERSONATION" in flag:
            score += 12; factors.append((flag, 12)); break
    for flag, _ in sender.get("flags", []):
        if "REPLY-TO MISMATCH" in flag:
            score += 8; factors.append((flag, 8)); break
    for flag, _ in sender.get("flags", []):
        if "RETURN-PATH MISMATCH" in flag:
            score += 4; factors.append((flag, 4)); break

    # Links (max 25)
    crit_links = sum(1 for l in links.get("links", []) for f, s in l.get("flags", []) if s == "critical")
    warn_links = sum(1 for l in links.get("links", []) for f, s in l.get("flags", []) if s == "warning")
    if crit_links:
        pts = min(20, crit_links * 8)
        score += pts; factors.append((f"{crit_links} critical link flags", pts))
    if warn_links:
        pts = min(5, warn_links * 2)
        score += pts; factors.append((f"{warn_links} link warnings", pts))

    # Urgency (max 15)
    u_count = urgency.get("unique_count", 0)
    if u_count >= 5:
        score += 15; factors.append(("Heavy urgency language", 15))
    elif u_count >= 3:
        score += 10; factors.append(("Moderate urgency language", 10))
    elif u_count >= 1:
        score += 5; factors.append(("Some urgency language", 5))

    if urgency.get("generic_greeting"):
        score += 3; factors.append(("Generic greeting", 3))

    # Attachments (max 10)
    att_crits = sum(1 for a in attachments.get("attachments", []) for f, s in a.get("flags", []) if s == "critical")
    if att_crits:
        pts = min(10, att_crits * 5)
        score += pts; factors.append((f"{att_crits} dangerous attachments", pts))

    # Language (max 5)
    lang_score = language.get("score")
    if lang_score is not None and lang_score < 70:
        score += 5; factors.append(("Poor language quality", 5))

    # Domain age (max 10)
    if domain_age_days is not None and domain_age_days < 30:
        score += 10; factors.append((f"Domain age: {domain_age_days} days", 10))
    elif domain_age_days is not None and domain_age_days < 90:
        score += 5; factors.append((f"Domain age: {domain_age_days} days", 5))

    score = min(100, score)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 45:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    elif score >= 10:
        level = "LOW"
    else:
        level = "CLEAN"

    return {"score": score, "level": level, "factors": factors}


# ═══════════════════════════════════════════════════════════════════════════════
# API INTEGRATIONS
# ═══════════════════════════════════════════════════════════════════════════════

_PRIVATE_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fe80|fc00|fd00)"
)


def extract_ips(received_headers: list) -> list:
    ips = []
    ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    for hdr in reversed(received_headers):
        for ip in ip_re.findall(hdr):
            if not _PRIVATE_RE.match(ip) and ip not in ips:
                ips.append(ip)
    return ips


def lookup_ip(ip: str) -> dict:
    if not req_lib:
        return {"error": "requests not installed"}
    try:
        r = req_lib.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,"
            f"region,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
            timeout=5,
        )
        data = r.json()
        return data if data.get("status") == "success" else {"error": data.get("message", "failed")}
    except Exception as e:
        return {"error": str(e)}


def country_code_to_flag(code: str) -> str:
    """Convert a 2-letter country code to a flag emoji."""
    if not code or len(code) != 2:
        return ""
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code.upper())


def lookup_urlscan(url: str) -> dict:
    """Search urlscan.io for a URL."""
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


def lookup_mxtoolbox(domain: str) -> dict:
    """Validate SPF, DKIM, and DMARC for domain via MXToolbox API."""
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


def parse_gemini_verdict(gemini_result: dict) -> str:
    """Extract the verdict (phishing/suspicious/legitimate) from Gemini response text."""
    text = gemini_result.get("text", "")
    if not text:
        return ""
    # Look for VERDICT line: "**VERDICT**: Phishing" or "VERDICT: Phishing" etc.
    m = re.search(r"VERDICT[:\s*]+\*{0,2}\s*(phishing|suspicious|legitimate)", text, re.I)
    if m:
        return m.group(1).lower()
    return ""


def build_gemini_context(parsed: dict, analysis: dict) -> str:
    """Build a structured context string from all analysis for the LLM."""
    headers = parsed["headers"]
    auth = parsed["auth"]
    sender = analysis["sender"]
    links = analysis["links"]
    urgency = analysis["urgency"]
    att = analysis["attachments"]
    lang = analysis["language"]
    threat = analysis["threat"]
    ip_data = analysis.get("ip_data") or {}
    domain_age = analysis.get("domain_age") or {}

    ctx = f"""=== EMAIL FORENSIC ANALYSIS CONTEXT ===

SUBJECT: {headers.get('Subject', '?')}
FROM: {headers.get('From', '?')}
TO: {headers.get('To', '?')}
REPLY-TO: {headers.get('Reply-To', 'same as From')}
RETURN-PATH: {headers.get('Return-Path', '?')}
DATE: {headers.get('Date', '?')}
X-MAILER: {headers.get('X-Mailer', headers.get('User-Agent', 'unknown'))}

--- AUTHENTICATION ---
SPF: {auth.get('spf', 'N/A')}
DKIM: {auth.get('dkim', 'N/A')}
DMARC: {auth.get('dmarc', 'N/A')}

--- SENDER ANALYSIS ---
From Display Name: {sender.get('from_display', '?')}
From Email: {sender.get('from_email', '?')}
From Domain: {sender.get('from_domain', '?')}
Return-Path Domain: {sender.get('rp_domain', '?')}
Sender Flags: {', '.join(f[0] for f in sender.get('flags', [])) or 'none'}
Sender Findings: {'; '.join(sender.get('findings', [])) or 'none'}

--- LINK ANALYSIS ({len(links.get('links', []))} URLs) ---
"""
    for i, link in enumerate(links.get("links", [])[:15], 1):
        flags = ", ".join(f[0] for f in link.get("flags", []))
        ctx += f"  [{i}] Display: {link.get('display', '?')[:60]}\n"
        ctx += f"      Href: {link.get('href', '?')[:100]}\n"
        ctx += f"      Domain: {link.get('domain', '?')} | Flags: {flags or 'none'}\n"
    ctx += f"Link Findings: {'; '.join(links.get('findings', [])) or 'none'}\n"

    ctx += f"""
--- URGENCY / SOCIAL ENGINEERING ---
Unique Patterns Matched: {urgency.get('unique_count', 0)}
Total Matches: {urgency.get('total_count', 0)}
Keywords: {', '.join(urgency.get('counter', {}).keys()) or 'none'}
Generic Greeting: {'YES' if urgency.get('generic_greeting') else 'no'}

--- ATTACHMENTS ({len(att.get('attachments', []))}) ---
"""
    for a in att.get("attachments", []):
        flags = ", ".join(f[0] for f in a.get("flags", []))
        ctx += f"  {a['name']} ({a['type']}, {fmt_bytes(a['size'])}) Flags: {flags or 'none'}\n"

    ctx += f"""
--- LANGUAGE ANALYSIS ---
Score: {lang.get('score', 'N/A')}/100
Findings: {'; '.join(lang.get('findings', [])) or 'none'}

--- ORIGIN IP ---
IP: {analysis.get('source_ip', 'unknown')}
"""
    if ip_data and "error" not in ip_data:
        ctx += f"ISP: {ip_data.get('isp', '?')}\nOrg: {ip_data.get('org', '?')}\nASN: {ip_data.get('as', '?')}\n"
        ctx += f"Location: {ip_data.get('city', '?')}, {ip_data.get('regionName', '?')}, {ip_data.get('country', '?')}\n"

    if domain_age and "error" not in domain_age:
        ctx += f"\n--- DOMAIN AGE ---\nDomain: {sender.get('from_domain', '?')}\nCreated: {domain_age.get('creation_date', '?')}\nAge: {domain_age.get('age_days', '?')} days\nRegistrar: {domain_age.get('registrar', '?')}\n"

    ctx += f"""
--- AUTOMATED THREAT SCORE ---
Score: {threat['score']}/100 ({threat['level']})
Factors: {'; '.join(f'{d} (+{p})' for d, p in threat['factors']) or 'none'}

--- EMAIL BODY (plain text excerpt) ---
{extract_plain_text(parsed)[:3000]}
"""
    return ctx


def query_gemini(context: str, model: str = "gemini-2.5-flash") -> dict:
    """Send analysis context to Gemini for AI phishing assessment."""
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        return {"error": "GEMINI_API_KEY not set"}
    if not req_lib:
        return {"error": "requests not installed"}

    prompt = f"""You are an expert email security analyst and phishing investigator.

Analyze the following email forensic data and provide:

1. **VERDICT**: Is this email phishing, suspicious, or legitimate? (one word)
2. **CONFIDENCE**: Your confidence level (0-100%)
3. **EXECUTIVE SUMMARY**: 2-3 sentence summary for a non-technical audience explaining what this email is and whether it's safe.
4. **TECHNICAL ANALYSIS**: Key technical indicators that informed your verdict (3-5 bullet points).
5. **ATTACK TECHNIQUE**: If phishing, classify the technique (e.g., credential harvesting, BEC, spear phishing, malware delivery, brand impersonation, etc.)
6. **RECOMMENDED ACTIONS**: What should the recipient do? (3-5 bullet points)
7. **INDICATORS OF COMPROMISE (IOCs)**: List any domains, IPs, URLs, or file hashes that should be blocked or investigated.

Be specific and reference actual data from the analysis. Do not hedge unnecessarily — give a clear call.

{context}"""

    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 2048,
            },
        }
        r = req_lib.post(
            url,
            headers={
                "x-goog-api-key": api_key,
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=30,
        )
        data = r.json()

        if "error" in data:
            return {"error": data["error"].get("message", str(data["error"]))}

        candidates = data.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts)
            return {"text": text, "model": model}

        return {"error": "no response from model"}

    except Exception as e:
        return {"error": str(e)}


def lookup_domain_age(domain: str) -> dict:
    """Get domain creation date via WHOIS."""
    if not whois_lib:
        return {"error": "python-whois not installed"}
    try:
        w = whois_lib.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
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


def parse_hops(received_headers: list) -> list:
    hops = []
    from_re = re.compile(r"from\s+([\w.\-]+)", re.I)
    by_re = re.compile(r"by\s+([\w.\-]+)", re.I)
    ip_re = re.compile(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?")
    date_re = re.compile(r";\s*(.+)$")

    for i, hdr in enumerate(received_headers):
        hop = {"index": len(received_headers) - i, "raw": hdr.strip()}
        fm = from_re.search(hdr)
        bm = by_re.search(hdr)
        im = ip_re.search(hdr)
        dm = date_re.search(hdr)
        if fm: hop["from"] = fm.group(1)
        if bm: hop["by"] = bm.group(1)
        if im: hop["ip"] = im.group(1)
        if dm: hop["date"] = dm.group(1).strip()[:50]
        hops.append(hop)
    return hops


# ═══════════════════════════════════════════════════════════════════════════════
# IOC LINKING (VirusTotal / URLscan)
# ═══════════════════════════════════════════════════════════════════════════════

def vt_url_link(url: str) -> str:
    """Return an HTML anchor linking a URL to VirusTotal search."""
    from urllib.parse import quote
    vt = f"https://www.virustotal.com/gui/search/{quote(url, safe='')}"
    return f'<a href="{escape(vt)}" target="_blank" rel="noopener" class="ioc-link vt" title="Look up on VirusTotal">{escape(url)}<span class="ioc-badge vt-badge">VT</span></a>'


def vt_domain_link(domain: str) -> str:
    """Return an HTML anchor linking a domain to VirusTotal."""
    vt = f"https://www.virustotal.com/gui/domain/{escape(domain)}"
    return f'<a href="{vt}" target="_blank" rel="noopener" class="ioc-link vt" title="Look up on VirusTotal">{escape(domain)}<span class="ioc-badge vt-badge">VT</span></a>'


def vt_ip_link(ip: str) -> str:
    """Return an HTML anchor linking an IP to VirusTotal."""
    vt = f"https://www.virustotal.com/gui/ip-address/{escape(ip)}"
    return f'<a href="{vt}" target="_blank" rel="noopener" class="ioc-link vt" title="Look up on VirusTotal">{escape(ip)}<span class="ioc-badge vt-badge">VT</span></a>'


def urlscan_domain_link(domain: str) -> str:
    """Return an HTML anchor linking a domain to urlscan.io search."""
    us = f"https://urlscan.io/search/#{escape(domain)}"
    return f'<a href="{us}" target="_blank" rel="noopener" class="ioc-link us" title="Look up on urlscan.io">{escape(domain)}<span class="ioc-badge us-badge">US</span></a>'


def urlscan_url_link(url: str) -> str:
    """Return an HTML anchor linking a URL to urlscan.io search."""
    from urllib.parse import quote
    us = f"https://urlscan.io/search/#{quote(url, safe='')}"
    return f'<a href="{escape(us)}" target="_blank" rel="noopener" class="ioc-link us" title="Look up on urlscan.io">{escape(url)}<span class="ioc-badge us-badge">US</span></a>'


def ioc_url_html(url: str) -> str:
    """Render a URL IOC with VT + URLscan links."""
    from urllib.parse import quote
    vt = f"https://www.virustotal.com/gui/search/{quote(url, safe='')}"
    us = f"https://urlscan.io/search/#{quote(url, safe='')}"
    return (f'<span class="ioc-wrap">{escape(url[:120])}'
            f'<a href="{escape(vt)}" target="_blank" rel="noopener" class="ioc-badge vt-badge" title="VirusTotal">VT</a>'
            f'<a href="{escape(us)}" target="_blank" rel="noopener" class="ioc-badge us-badge" title="urlscan.io">US</a>'
            f'</span>')


def ioc_email_html(addr: str) -> str:
    """Render an email IOC with VT domain link."""
    domain = addr.split("@")[-1] if "@" in addr else ""
    if domain:
        vt = f"https://www.virustotal.com/gui/domain/{escape(domain)}"
        badge = f'<a href="{vt}" target="_blank" rel="noopener" class="ioc-badge vt-badge" title="VirusTotal domain lookup">VT</a>'
    else:
        badge = ""
    return f'<span class="ioc-wrap">{escape(addr)}{badge}</span>'


def ioc_ip_html(ip: str, geo=None) -> str:
    """Render an IP IOC with VT + URLscan links and optional country flag."""
    vt = f"https://www.virustotal.com/gui/ip-address/{escape(ip)}"
    us = f"https://urlscan.io/search/#{escape(ip)}"
    flag_html = ""
    if geo and isinstance(geo, dict) and "error" not in geo:
        cc = geo.get("countryCode", "")
        flag = country_code_to_flag(cc)
        if flag:
            tip_parts = [geo.get("country", "")]
            if geo.get("city"):
                tip_parts.append(geo["city"])
            if geo.get("isp"):
                tip_parts.append(geo["isp"])
            tip = escape(", ".join(p for p in tip_parts if p))
            flag_html = f'<span class="ip-flag" title="{tip}">{flag}</span>'
    return (f'<span class="ioc-wrap">{escape(ip)}{flag_html}'
            f'<a href="{vt}" target="_blank" rel="noopener" class="ioc-badge vt-badge" title="VirusTotal">VT</a>'
            f'<a href="{us}" target="_blank" rel="noopener" class="ioc-badge us-badge" title="urlscan.io">US</a>'
            f'</span>')


# ═══════════════════════════════════════════════════════════════════════════════
# BODY HIGHLIGHTING
# ═══════════════════════════════════════════════════════════════════════════════

def highlight_body(html_body: str, urgency_positions: list, link_analysis: dict) -> str:
    """Inject highlight styles into the email HTML body."""
    if not html_body:
        return html_body

    # Build a lookup of flagged domains -> their flags for popup details
    flagged_links = {}
    for link in link_analysis.get("links", []):
        if link.get("flags"):
            domain = link.get("domain", "").lower()
            flag_labels = [f[0] for f in link["flags"]]
            flagged_links[domain] = flag_labels

    # Inject styles + popup container + hover script
    style_inject = """
    <style>
    @keyframes phish-pulse {
        0%, 100% { box-shadow: 0 0 4px rgba(251,191,36,0.3); }
        50% { box-shadow: 0 0 12px rgba(251,191,36,0.5); }
    }
    @keyframes phish-link-pulse {
        0%, 100% { box-shadow: 0 0 4px rgba(248,113,113,0.3); }
        50% { box-shadow: 0 0 14px rgba(248,113,113,0.5); }
    }
    .phish-hl-urgency {
        background: linear-gradient(135deg, rgba(251,191,36,0.2), rgba(245,158,11,0.15));
        border-bottom: 2px solid #fbbf24;
        padding: 1px 4px;
        border-radius: 3px;
        cursor: help;
        transition: all 0.2s ease;
        animation: phish-pulse 2.5s ease-in-out infinite;
    }
    .phish-hl-urgency:hover {
        background: rgba(251,191,36,0.35);
        box-shadow: 0 0 16px rgba(251,191,36,0.4);
    }
    .phish-hl-link-warn {
        outline: 2px solid rgba(248,113,113,0.7);
        outline-offset: 2px;
        border-radius: 3px;
        position: relative;
        cursor: help;
        transition: all 0.2s ease;
        animation: phish-link-pulse 2s ease-in-out infinite;
    }
    .phish-hl-link-warn:hover {
        outline-color: #f87171;
        outline-width: 3px;
        box-shadow: 0 0 20px rgba(248,113,113,0.35);
    }
    .phish-link-badge {
        font-size: 8px;
        font-family: monospace;
        font-weight: 700;
        background: linear-gradient(135deg, #dc2626, #b91c1c);
        color: white;
        padding: 2px 6px;
        border-radius: 3px;
        margin-left: 5px;
        vertical-align: middle;
        letter-spacing: 0.8px;
        text-transform: uppercase;
        box-shadow: 0 2px 6px rgba(220,38,38,0.3);
    }
    </style>
    <div id="phish-popup-el" style="display:none;position:fixed;z-index:10000;
        background:linear-gradient(135deg,#1e1032,#1a0a2e);border:1px solid rgba(139,92,246,0.5);
        border-radius:8px;padding:10px 14px;font-family:monospace;font-size:11px;color:#e2e8f0;
        max-width:340px;box-shadow:0 8px 32px rgba(0,0,0,0.5),0 0 20px rgba(139,92,246,0.15);
        pointer-events:none;line-height:1.5;backdrop-filter:blur(8px);"></div>
    <script>
    (function(){
        var popup = document.getElementById('phish-popup-el');
        if (!popup) return;
        function showPopup(e, html) {
            popup.innerHTML = html;
            popup.style.display = 'block';
            var r = e.target.getBoundingClientRect();
            var x = r.left;
            var y = r.bottom + 6;
            if (x + 340 > window.innerWidth) x = window.innerWidth - 350;
            if (x < 4) x = 4;
            if (y + 200 > window.innerHeight) y = r.top - popup.offsetHeight - 6;
            popup.style.left = x + 'px';
            popup.style.top = y + 'px';
        }
        function hidePopup() { popup.style.display = 'none'; }
        document.querySelectorAll('.phish-hl-urgency').forEach(function(el) {
            el.addEventListener('mouseenter', function(e) {
                var label = el.getAttribute('data-threat') || el.getAttribute('title') || '';
                showPopup(e, '<div style="font-size:9px;font-weight:700;letter-spacing:1.5px;color:#fbbf24;margin-bottom:4px;">SOCIAL ENGINEERING</div>'
                    + '<div style="color:#94a3b8;">Pattern: <span style="color:#fbbf24;">' + label + '</span></div>'
                    + '<div style="color:#64748b;font-size:10px;margin-top:3px;">Urgency/pressure language used in phishing</div>');
            });
            el.addEventListener('mouseleave', hidePopup);
        });
        document.querySelectorAll('.phish-hl-link-warn').forEach(function(el) {
            el.addEventListener('mouseenter', function(e) {
                var flags = el.getAttribute('data-flags') || 'SUSPICIOUS';
                var href = el.getAttribute('data-real-href') || el.getAttribute('href') || '';
                showPopup(e, '<div style="font-size:9px;font-weight:700;letter-spacing:1.5px;color:#f87171;margin-bottom:4px;">SUSPICIOUS LINK</div>'
                    + '<div style="color:#94a3b8;">Flags: <span style="color:#f87171;">' + flags + '</span></div>'
                    + (href ? '<div style="color:#64748b;font-size:10px;margin-top:3px;word-break:break-all;">Destination: ' + href.substring(0,120) + '</div>' : ''));
            });
            el.addEventListener('mouseleave', hidePopup);
        });
    })();
    </script>
    """

    modified = style_inject + html_body

    # Highlight urgency keywords in visible text
    for pattern, label in URGENCY_PATTERNS:
        modified = re.sub(
            f"(>)([^<]*?)({pattern})([^<]*?)(<)",
            lambda m: f'{m.group(1)}{m.group(2)}<span class="phish-hl-urgency" data-threat="{label}" title="⚠ {label}">{m.group(3)}</span>{m.group(4)}{m.group(5)}',
            modified,
            flags=re.I,
        )

    # Flag suspicious links with a badge and popup data
    suspicious_domains = set(flagged_links.keys())

    if suspicious_domains and BeautifulSoup:
        soup = BeautifulSoup(modified, "html.parser")
        for a in soup.find_all("a", href=True):
            try:
                d = urlparse(a["href"]).hostname or ""
            except Exception:
                d = ""
            if d.lower() in suspicious_domains:
                a["class"] = a.get("class", []) + ["phish-hl-link-warn"]
                a["data-flags"] = ", ".join(flagged_links.get(d.lower(), []))
                a["data-real-href"] = a["href"]
                badge = soup.new_tag("span")
                badge["class"] = ["phish-link-badge"]
                badge.string = "⚠ SUSPICIOUS"
                a.append(badge)
        modified = str(soup)

    return modified


# ═══════════════════════════════════════════════════════════════════════════════
# HTML TEMPLATE HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def fmt_bytes(n: int) -> str:
    if n < 1024: return f"{n} B"
    if n < 1024**2: return f"{n/1024:.1f} KB"
    return f"{n/1024**2:.1f} MB"


def auth_badge_html(label, value):
    if not value:
        cls, icon = "unknown", "—"
    elif value.lower() == "pass":
        cls, icon = "pass", "✓"
    elif value.lower() in ("fail", "softfail"):
        cls, icon = "fail", "✗"
    else:
        cls, icon = "unknown", "?"
    return f'<div class="auth-chip {cls}"><span class="auth-icon">{icon}</span><span class="auth-label">{label}</span><span class="auth-val">{escape(value or "N/A")}</span></div>'


def threat_gauge_html(threat: dict) -> str:
    score = threat["score"]
    level = threat["level"]
    if score >= 70: color, glow = "#ef4444", "rgba(239,68,68,0.3)"
    elif score >= 45: color, glow = "#f97316", "rgba(249,115,22,0.3)"
    elif score >= 25: color, glow = "#eab308", "rgba(234,179,8,0.3)"
    elif score >= 10: color, glow = "#22d3ee", "rgba(34,211,238,0.2)"
    else: color, glow = "#34d399", "rgba(52,211,153,0.2)"

    factor_rows = ""
    for desc, pts in threat["factors"]:
        factor_rows += f'<div class="factor-row"><span class="factor-desc">{escape(desc)}</span><span class="factor-pts">+{pts}</span></div>'

    target_dash = round(score * 3.267, 1)
    return f"""
    <div class="widget threat-widget" id="nav-threat">
        <div class="widget-header"><span class="widget-icon">⬡</span> PHISHING THREAT ASSESSMENT</div>
        <div class="threat-content">
            <div class="gauge-container">
                <div class="gauge-ring" style="--score:{score};--color:{color};--glow:{glow}">
                    <svg viewBox="0 0 120 120" class="gauge-svg">
                        <circle cx="60" cy="60" r="52" fill="none" stroke="#1e293b" stroke-width="8"/>
                        <circle cx="60" cy="60" r="52" fill="none" stroke="{color}"
                            stroke-width="8" stroke-linecap="round"
                            stroke-dasharray="0 326.7" data-target-dash="{target_dash}"
                            transform="rotate(-90 60 60)"
                            style="filter: drop-shadow(0 0 6px {glow});"/>
                    </svg>
                    <div class="gauge-text">
                        <div class="gauge-score" style="color:{color}" data-target="{score}">0</div>
                        <div class="gauge-label">{level}</div>
                    </div>
                    <div class="gauge-glow" style="background:radial-gradient(circle, {glow} 0%, transparent 70%);"></div>
                </div>
            </div>
            <div class="threat-factors">
                <div class="factors-title">CONTRIBUTING FACTORS</div>
                {factor_rows if factor_rows else '<div class="factor-row"><span class="factor-desc dim">No significant risk factors detected</span></div>'}
            </div>
        </div>
    </div>"""


def link_analysis_html(links_data: dict) -> str:
    links = links_data.get("links", [])
    if not links:
        return ""

    rows = ""
    for link in links:
        href = link["href"]
        display = link["display"] or "—"
        flags = link.get("flags", [])

        flag_badges = ""
        for label, severity in flags:
            cls = "flag-crit" if severity == "critical" else "flag-warn"
            flag_badges += f'<span class="flag-badge {cls}">{label}</span>'

        mismatch_class = " link-flagged" if flags else ""

        rows += f"""
        <div class="link-row{mismatch_class}">
            <div class="link-display">{escape(display[:80])}</div>
            <div class="link-href">{ioc_url_html(href)}</div>
            <div class="link-flags">{flag_badges}</div>
        </div>"""

    findings_html = ""
    if links_data.get("findings"):
        findings_html = '<div class="link-findings">' + "".join(
            f'<div class="finding-item">⚠ {escape(f)}</div>' for f in links_data["findings"]
        ) + "</div>"

    return f"""
    <div class="widget link-widget" id="nav-links">
        <div class="widget-header"><span class="widget-icon">🔗</span> LINK ANALYSIS — {len(links)} URLs EXTRACTED</div>
        {findings_html}
        <div class="link-table">
            <div class="link-table-header">
                <span>DISPLAY TEXT</span><span>ACTUAL URL</span><span>FLAGS</span>
            </div>
            {rows}
        </div>
    </div>"""


def sender_analysis_html(sender: dict) -> str:
    flags = sender.get("flags", [])
    findings = sender.get("findings", [])
    if not flags and not findings:
        return ""

    flag_badges = "".join(
        f'<span class="flag-badge {"flag-crit" if s == "critical" else "flag-warn"}">{l}</span>'
        for l, s in flags
    )

    rows = f"""
    <div class="sender-grid">
        <div class="sender-item"><span class="sender-label">FROM (DISPLAY)</span><span class="sender-val">{escape(sender.get('from_display', '—'))}</span></div>
        <div class="sender-item"><span class="sender-label">FROM (EMAIL)</span><span class="sender-val mono">{ioc_email_html(sender.get('from_email', '—'))}</span></div>
        <div class="sender-item"><span class="sender-label">RETURN-PATH</span><span class="sender-val mono">{ioc_email_html(sender.get('return_path', '—'))}</span></div>
        <div class="sender-item"><span class="sender-label">REPLY-TO</span><span class="sender-val mono">{ioc_email_html(sender.get('reply_to', '—') or '—')}</span></div>
    </div>"""

    findings_html = "".join(f'<div class="finding-item">⚠ {escape(f)}</div>' for f in findings)

    return f"""
    <div class="widget sender-widget" id="nav-sender">
        <div class="widget-header"><span class="widget-icon">👤</span> SENDER ANALYSIS</div>
        <div class="sender-flags">{flag_badges}</div>
        {rows}
        {f'<div class="link-findings">{findings_html}</div>' if findings_html else ''}
    </div>"""


def urgency_html(urgency: dict) -> str:
    if urgency["total_count"] == 0:
        return ""

    bars = ""
    for keyword, count in sorted(urgency["counter"].items(), key=lambda x: -x[1]):
        width = min(100, count * 25)
        bars += f"""
        <div class="urgency-bar-row">
            <span class="urgency-keyword">{escape(keyword)}</span>
            <div class="urgency-bar"><div class="urgency-fill" style="width:{width}%"></div></div>
            <span class="urgency-count">×{count}</span>
        </div>"""

    return f"""
    <div class="widget urgency-widget" id="nav-urgency">
        <div class="widget-header"><span class="widget-icon">⚡</span> SOCIAL ENGINEERING INDICATORS — {urgency['unique_count']} PATTERNS MATCHED</div>
        <div class="urgency-content">{bars}</div>
        {f'<div class="urgency-note">⚠ Generic greeting detected — not addressing recipient by name</div>' if urgency['generic_greeting'] else ''}
    </div>"""


def attachment_html(att_data: dict) -> str:
    atts = att_data.get("attachments", [])
    if not atts:
        return ""

    rows = ""
    for a in atts:
        flag_badges = "".join(
            f'<span class="flag-badge {"flag-crit" if s == "critical" else "flag-warn"}">{l}</span>'
            for l, s in a.get("flags", [])
        )
        rows += f"""
        <div class="att-row">
            <div class="att-info">
                <span class="att-name">{escape(a['name'])}</span>
                <span class="att-meta">{escape(a['type'])} · {fmt_bytes(a['size'])}</span>
            </div>
            <div class="att-hashes">
                <span class="att-hash" data-full="{a.get('md5','')}" title="{a.get('md5','—')}">MD5: {a.get('md5','—')[:16]}…</span>
                <span class="att-hash" data-full="{a.get('sha256','')}" title="{a.get('sha256','—')}">SHA256: {a.get('sha256','—')[:16]}…</span>
            </div>
            <div class="att-flags">{flag_badges}</div>
        </div>"""

    return f"""
    <div class="widget att-widget" id="nav-attachments">
        <div class="widget-header"><span class="widget-icon">📎</span> ATTACHMENT ANALYSIS — {len(atts)} FILES</div>
        {rows}
    </div>"""


def language_html(lang: dict) -> str:
    if lang.get("score") is None:
        return ""

    score = lang["score"]
    if score >= 80: color, label = "#34d399", "GOOD"
    elif score >= 60: color, label = "#eab308", "FAIR"
    else: color, label = "#f87171", "POOR"

    findings = "".join(f'<div class="finding-item">• {escape(f)}</div>' for f in lang.get("findings", []))

    return f"""
    <div class="widget lang-widget" id="nav-language">
        <div class="widget-header"><span class="widget-icon">📝</span> LANGUAGE ANALYSIS</div>
        <div class="lang-content">
            <div class="lang-score" style="color:{color}">{score}/100 <span class="lang-label">{label}</span></div>
            {f'<div class="lang-findings">{findings}</div>' if findings else '<div class="dim" style="padding:0 18px 14px;font-size:12px;">No significant language anomalies</div>'}
        </div>
    </div>"""


def domain_age_html(domain_info: dict, domain: str) -> str:
    if not domain_info or "error" in domain_info:
        return ""

    age = domain_info.get("age_days", 0)
    if age < 30: color, label = "#ef4444", "NEWLY REGISTERED"
    elif age < 90: color, label = "#f97316", "RECENT"
    elif age < 365: color, label = "#eab308", "< 1 YEAR"
    else: color, label = "#34d399", f"{age // 365} YEARS"

    return f"""
    <div class="widget domain-widget" id="nav-domain">
        <div class="widget-header"><span class="widget-icon">🌐</span> DOMAIN INTELLIGENCE — {escape(domain)}</div>
        <div class="domain-content">
            <div class="domain-age" style="color:{color}">{age} days <span class="domain-label">{label}</span></div>
            <div class="domain-detail">Created: {escape(domain_info.get('creation_date', '—'))} · Registrar: {escape(domain_info.get('registrar', '—'))}</div>
        </div>
    </div>"""


def urlscan_html(urlscan_data: dict) -> str:
    if not urlscan_data or "error" in urlscan_data or "info" in urlscan_data:
        return ""

    verdict = urlscan_data.get("verdict", {})
    page = urlscan_data.get("page", {})
    malicious = verdict.get("malicious", False)
    score_val = verdict.get("score", 0)
    color = "#ef4444" if malicious else "#34d399"

    return f"""
    <div class="widget urlscan-widget" id="nav-urlscan">
        <div class="widget-header"><span class="widget-icon">🔍</span> URLSCAN.IO INTELLIGENCE</div>
        <div class="urlscan-content">
            <div class="urlscan-verdict" style="color:{color}">{'⚠ MALICIOUS' if malicious else '✓ NOT FLAGGED'} (score: {score_val})</div>
            <div class="urlscan-detail">Server: {escape(page.get('server', '—'))} · IP: {escape(page.get('ip', '—'))} · Country: {escape(page.get('country', '—'))}</div>
            <div class="urlscan-link"><a href="{escape(urlscan_data.get('url', '#'))}" style="color:var(--accent);">View full report →</a></div>
        </div>
    </div>"""


def gemini_widget_html(gemini_data: dict) -> str:
    """Render the Gemini AI assessment widget."""
    if not gemini_data or "error" in gemini_data:
        err = gemini_data.get("error", "") if gemini_data else ""
        if err and err != "GEMINI_API_KEY not set":
            return f"""
            <div class="widget gemini-widget" id="nav-ai">
                <div class="widget-header"><span class="widget-icon">🤖</span> AI ASSESSMENT — ERROR</div>
                <div class="gemini-content"><div class="dim" style="padding:14px 18px;font-size:12px;">{escape(err)}</div></div>
            </div>"""
        return ""

    text = gemini_data.get("text", "")
    model = gemini_data.get("model", "gemini")

    # Convert markdown-style formatting to HTML
    import re as _re
    formatted = escape(text)
    # Bold
    formatted = _re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', formatted)
    # Bullet points
    lines = formatted.split("\n")
    result_lines = []
    in_list = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                result_lines.append('<ul class="gemini-list">')
                in_list = True
            result_lines.append(f"<li>{stripped[2:]}</li>")
        else:
            if in_list:
                result_lines.append("</ul>")
                in_list = False
            if stripped.startswith("# "):
                result_lines.append(f'<div class="gemini-h1">{stripped[2:]}</div>')
            elif stripped.startswith("## "):
                result_lines.append(f'<div class="gemini-h2">{stripped[3:]}</div>')
            elif stripped:
                result_lines.append(f"<p>{stripped}</p>")
    if in_list:
        result_lines.append("</ul>")
    formatted = "\n".join(result_lines)

    return f"""
    <div class="widget gemini-widget" id="nav-ai">
        <div class="widget-header"><span class="widget-icon">🤖</span> AI PHISHING ASSESSMENT — {escape(model.upper())}</div>
        <div class="gemini-content">
            {formatted}
        </div>
    </div>"""


# ═══════════════════════════════════════════════════════════════════════════════
# IP WIDGET (reuse from before, enhanced)
# ═══════════════════════════════════════════════════════════════════════════════

def ip_widget_html(ip_data, source_ip):
    if not source_ip:
        return ""
    if ip_data and "error" not in ip_data:
        cc = ip_data.get('countryCode', '')
        flag = country_code_to_flag(cc)
        flag_span = f'<span class="ip-flag" title="{escape(ip_data.get("country", ""))}">{flag}</span>' if flag else ''
        return f"""
        <div class="widget ip-widget" id="nav-ip">
            <div class="widget-header"><span class="widget-icon">◉</span> ORIGIN IP INTELLIGENCE</div>
            <div class="ip-grid">
                <div class="ip-main">
                    <div class="ip-address">{ioc_ip_html(source_ip, geo=ip_data)}</div>
                    <div class="ip-org">{escape(ip_data.get('org','') or ip_data.get('isp',''))}</div>
                    <div class="ip-asn">{escape(ip_data.get('as',''))}</div>
                </div>
                <div class="ip-geo">
                    <div class="geo-row"><span class="geo-label">LOCATION</span><span class="geo-val">{escape(ip_data.get('city',''))}, {escape(ip_data.get('regionName',''))}</span></div>
                    <div class="geo-row"><span class="geo-label">COUNTRY</span><span class="geo-val">{flag_span} {escape(ip_data.get('country',''))} [{escape(ip_data.get('countryCode',''))}]</span></div>
                    <div class="geo-row"><span class="geo-label">COORDS</span><span class="geo-val mono">{ip_data.get('lat','—')}, {ip_data.get('lon','—')}</span></div>
                    <div class="geo-row"><span class="geo-label">TIMEZONE</span><span class="geo-val">{escape(ip_data.get('timezone',''))}</span></div>
                    <div class="geo-row"><span class="geo-label">ISP</span><span class="geo-val">{escape(ip_data.get('isp',''))}</span></div>
                </div>
            </div>
        </div>"""
    else:
        err = ip_data.get("error", "skipped") if ip_data else "skipped"
        return f"""
        <div class="widget ip-widget" id="nav-ip">
            <div class="widget-header"><span class="widget-icon">◉</span> ORIGIN IP</div>
            <div class="ip-main" style="padding:18px"><div class="ip-address">{ioc_ip_html(source_ip)}</div><div class="dim">{escape(err)}</div></div>
        </div>"""


def hop_trace_html(hops, ip_geo_map=None):
    if not hops:
        return ""
    if ip_geo_map is None:
        ip_geo_map = {}
    items = ""
    for h in hops:
        fr = escape(h.get("from", "—"))
        by = escape(h.get("by", "—"))
        ip = h.get("ip", "")
        dt = escape(h.get("date", ""))
        hop_geo = ip_geo_map.get(ip)
        ip_tag = f'<span class="hop-ip">{ioc_ip_html(ip, geo=hop_geo)}</span>' if ip else ""
        items += f"""
        <div class="hop-item">
            <div class="hop-num">{h['index']}</div>
            <div class="hop-line"></div>
            <div class="hop-detail">
                <span class="hop-from">{fr}</span><span class="hop-arrow">→</span><span class="hop-to">{by}</span>{ip_tag}
                <div class="hop-date">{dt}</div>
            </div>
        </div>"""
    return f"""
    <div class="widget hop-widget" id="nav-hops">
        <div class="widget-header"><span class="widget-icon">◆</span> DELIVERY PATH — {len(hops)} HOPS</div>
        <div class="hop-trace">{items}</div>
    </div>"""


# ═══════════════════════════════════════════════════════════════════════════════
# FULL HTML BUILD
# ═══════════════════════════════════════════════════════════════════════════════

def build_full_html(parsed, analysis, interactive=False):
    """Build the complete infographic HTML."""
    headers = parsed["headers"]
    threat = analysis["threat"]
    body_html = analysis.get("highlighted_body") or parsed["html_body"] or f"<pre style='white-space:pre-wrap;font-family:inherit;'>{escape(parsed['text_body'] or '(empty)')}</pre>"

    # Envelope rows
    env_rows = ""
    for key in ["From", "To", "Cc", "Bcc", "Reply-To", "Date", "Subject"]:
        val = headers.get(key, "")
        if val:
            env_rows += f'<div class="env-row"><span class="env-label">{key.upper()}</span><span class="env-val">{escape(val)}</span></div>'

    # Metadata
    meta_rows = ""
    for label, val in [
        ("MESSAGE-ID", headers.get("Message-ID", "")),
        ("RETURN-PATH", headers.get("Return-Path", "")),
        ("X-MAILER", headers.get("X-Mailer", "") or headers.get("User-Agent", "")),
        ("MIME", headers.get("MIME-Version", "")),
        ("CONTENT-TYPE", headers.get("Content-Type", "")[:80]),
    ]:
        if val:
            meta_rows += f'<div class="meta-row"><span class="meta-label">{label}</span><span class="meta-val">{escape(val)}</span></div>'

    meta_widget = f'<div class="widget meta-widget" id="nav-metadata"><div class="widget-header"><span class="widget-icon">◇</span> MESSAGE METADATA</div>{meta_rows}</div>' if meta_rows else ""
    auth = parsed["auth"]

    # Interactive-only additions
    interactive_js = ""
    nav_html = ""
    nav_js = ""
    if interactive:
        interactive_js = """
        <script>
        (function() {
            // === Smooth widget collapse/expand ===
            document.querySelectorAll('.widget').forEach(w => {
                const header = w.querySelector('.widget-header');
                if (!header) return;
                // Wrap non-header children into .widget-content
                const children = Array.from(w.children).filter(c => c !== header);
                if (children.length === 0) return;
                const wrapper = document.createElement('div');
                wrapper.className = 'widget-content';
                children.forEach(c => wrapper.appendChild(c));
                w.appendChild(wrapper);
                header.style.cursor = 'pointer';
                header.addEventListener('click', () => {
                    wrapper.classList.toggle('collapsed');
                    header.classList.toggle('collapsed-header');
                });
            });

            // === Widget entrance animations (IntersectionObserver) ===
            const animObs = new IntersectionObserver((entries) => {
                entries.forEach(e => {
                    if (e.isIntersecting) {
                        e.target.classList.add('visible');
                        animObs.unobserve(e.target);
                    }
                });
            }, { threshold: 0.08 });
            document.querySelectorAll('.widget, .envelope').forEach(w => {
                if (w.classList.contains('threat-widget')) {
                    w.classList.add('visible');
                } else {
                    animObs.observe(w);
                }
            });

            // === Threat gauge count-up + ring animation ===
            const gaugeObs = new IntersectionObserver((entries) => {
                entries.forEach(e => {
                    if (!e.isIntersecting) return;
                    gaugeObs.unobserve(e.target);
                    const scoreEl = e.target.querySelector('.gauge-score[data-target]');
                    const ringEl = e.target.querySelector('circle[data-target-dash]');
                    if (!scoreEl) return;
                    const target = parseInt(scoreEl.dataset.target) || 0;
                    const targetDash = parseFloat(ringEl ? ringEl.dataset.targetDash : 0);
                    const duration = 1200;
                    const start = performance.now();
                    function easeOut(t) { return 1 - Math.pow(1 - t, 3); }
                    function tick(now) {
                        const elapsed = now - start;
                        const progress = Math.min(elapsed / duration, 1);
                        const eased = easeOut(progress);
                        scoreEl.textContent = Math.round(target * eased);
                        if (ringEl) ringEl.setAttribute('stroke-dasharray', (targetDash * eased).toFixed(1) + ' 326.7');
                        if (progress < 1) requestAnimationFrame(tick);
                    }
                    requestAnimationFrame(tick);
                });
            }, { threshold: 0.3 });
            const threatW = document.querySelector('.threat-widget');
            if (threatW) gaugeObs.observe(threatW);

            // === Copy-to-clipboard buttons ===
            function addCopyBtn(el, textFn) {
                const btn = document.createElement('button');
                btn.className = 'copy-btn';
                btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
                btn.title = 'Copy to clipboard';
                btn.addEventListener('click', (ev) => {
                    ev.stopPropagation();
                    const text = textFn();
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
                    } else { fallbackCopy(text); }
                    btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>';
                    const pill = document.createElement('span');
                    pill.className = 'copy-feedback';
                    pill.textContent = 'Copied!';
                    btn.parentElement.style.position = 'relative';
                    btn.parentElement.appendChild(pill);
                    setTimeout(() => {
                        btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
                        if (pill.parentElement) pill.remove();
                    }, 1500);
                });
                el.style.position = 'relative';
                el.appendChild(btn);
            }
            function fallbackCopy(text) {
                const ta = document.createElement('textarea');
                ta.value = text;
                ta.style.cssText = 'position:fixed;left:-9999px';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                ta.remove();
            }
            // IOC spans
            document.querySelectorAll('.ioc-wrap').forEach(el => {
                addCopyBtn(el, () => {
                    const clone = el.cloneNode(true);
                    clone.querySelectorAll('.ioc-badge, .copy-btn, .copy-feedback').forEach(x => x.remove());
                    return clone.textContent.trim();
                });
            });
            // Attachment hashes
            document.querySelectorAll('.att-hash[data-full]').forEach(el => {
                addCopyBtn(el, () => el.dataset.full || el.textContent.trim());
            });

            // === Collapsible email body ===
            const bodySection = document.querySelector('.body-section');
            if (bodySection) {
                const container = document.createElement('div');
                container.className = 'body-collapse-container';
                bodySection.parentNode.insertBefore(container, bodySection);
                container.appendChild(bodySection);
                const overlay = document.createElement('div');
                overlay.className = 'body-fade-overlay';
                container.appendChild(overlay);
                const toggleBtn = document.createElement('button');
                toggleBtn.className = 'body-toggle-btn';
                toggleBtn.textContent = 'Show full email \\u25BC';
                container.appendChild(toggleBtn);
                if (bodySection.scrollHeight > 500) {
                    bodySection.classList.add('collapsed-body');
                    toggleBtn.addEventListener('click', () => {
                        const isCollapsed = bodySection.classList.contains('collapsed-body');
                        bodySection.classList.toggle('collapsed-body');
                        overlay.style.display = isCollapsed ? 'none' : '';
                        toggleBtn.textContent = isCollapsed ? 'Collapse email \\u25B2' : 'Show full email \\u25BC';
                    });
                } else {
                    overlay.style.display = 'none';
                    toggleBtn.style.display = 'none';
                }
            }

            // === Custom styled tooltips ===
            const tooltip = document.createElement('div');
            tooltip.className = 'custom-tooltip';
            document.body.appendChild(tooltip);
            document.querySelectorAll('[title]').forEach(el => {
                if (el.classList.contains('phish-hl-urgency') || el.classList.contains('phish-hl-link-warn')) return;
                const text = el.getAttribute('title');
                if (!text) return;
                el.setAttribute('data-tooltip', text);
                el.removeAttribute('title');
                el.addEventListener('mouseenter', (ev) => {
                    tooltip.textContent = el.dataset.tooltip;
                    tooltip.style.display = 'block';
                    const rect = el.getBoundingClientRect();
                    let top = rect.top - tooltip.offsetHeight - 8;
                    let left = rect.left + rect.width / 2 - tooltip.offsetWidth / 2;
                    if (top < 4) top = rect.bottom + 8;
                    if (left < 4) left = 4;
                    if (left + tooltip.offsetWidth > window.innerWidth - 4) left = window.innerWidth - tooltip.offsetWidth - 4;
                    tooltip.style.top = top + 'px';
                    tooltip.style.left = left + 'px';
                    tooltip.style.opacity = '1';
                });
                el.addEventListener('mouseleave', () => {
                    tooltip.style.display = 'none';
                    tooltip.style.opacity = '0';
                });
            });

            // === Defang all remaining links in body ===
            document.querySelectorAll('.body-section a').forEach(a => {
                a.removeAttribute('href');
                a.style.cursor = 'default';
                a.title = '(link disabled for safety)';
            });
        })();
        </script>"""

        # === Section navigation (floating dot-nav) ===
        nav_html = """
        <nav class="section-nav">
            <div class="nav-group" data-group="assessment">
                <div class="nav-group-label">ASSESS</div>
                <a href="#nav-threat" class="nav-dot" data-section="nav-threat"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Threat</span></a>
                <a href="#nav-ai" class="nav-dot" data-section="nav-ai"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">AI</span></a>
            </div>
            <div class="nav-group" data-group="email">
                <div class="nav-group-label">EMAIL</div>
                <a href="#nav-sender" class="nav-dot" data-section="nav-sender"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Sender</span></a>
                <a href="#nav-auth" class="nav-dot" data-section="nav-auth"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Auth</span></a>
                <a href="#nav-links" class="nav-dot" data-section="nav-links"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Links</span></a>
                <a href="#nav-urgency" class="nav-dot" data-section="nav-urgency"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Urgency</span></a>
                <a href="#nav-language" class="nav-dot" data-section="nav-language"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Language</span></a>
                <a href="#nav-attachments" class="nav-dot" data-section="nav-attachments"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Files</span></a>
            </div>
            <div class="nav-group" data-group="network">
                <div class="nav-group-label">NETWORK</div>
                <a href="#nav-domain" class="nav-dot" data-section="nav-domain"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Domain</span></a>
                <a href="#nav-ip" class="nav-dot" data-section="nav-ip"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">IP</span></a>
                <a href="#nav-urlscan" class="nav-dot" data-section="nav-urlscan"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">URLScan</span></a>
                <a href="#nav-hops" class="nav-dot" data-section="nav-hops"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Hops</span></a>
            </div>
            <div class="nav-group" data-group="raw">
                <div class="nav-group-label">RAW</div>
                <a href="#nav-metadata" class="nav-dot" data-section="nav-metadata"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Meta</span></a>
                <a href="#nav-envelope" class="nav-dot" data-section="nav-envelope"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Envelope</span></a>
                <a href="#nav-body" class="nav-dot" data-section="nav-body"><span class="nav-dot-icon">◈</span><span class="nav-dot-text">Body</span></a>
            </div>
        </nav>"""

        nav_js = """
        <script>
        (function() {
            // Hide dots whose target section doesn't exist
            document.querySelectorAll('.nav-dot').forEach(dot => {
                const targetId = dot.dataset.section;
                if (!document.getElementById(targetId)) {
                    dot.style.display = 'none';
                }
            });
            // Hide empty nav groups
            document.querySelectorAll('.nav-group').forEach(g => {
                const visibleDots = g.querySelectorAll('.nav-dot:not([style*="display: none"])');
                if (visibleDots.length === 0) g.style.display = 'none';
            });
            // Scroll-spy with IntersectionObserver
            const dots = document.querySelectorAll('.nav-dot');
            const sectionIds = Array.from(dots).map(d => d.dataset.section).filter(id => document.getElementById(id));
            const navObs = new IntersectionObserver((entries) => {
                entries.forEach(e => {
                    const dot = document.querySelector('.nav-dot[data-section="' + e.target.id + '"]');
                    if (dot) {
                        if (e.isIntersecting) dot.classList.add('active');
                        else dot.classList.remove('active');
                    }
                });
            }, { rootMargin: '-20% 0px -60% 0px', threshold: 0 });
            sectionIds.forEach(id => navObs.observe(document.getElementById(id)));
            // Click handlers with smooth scroll + offset
            dots.forEach(dot => {
                dot.addEventListener('click', (ev) => {
                    ev.preventDefault();
                    const target = document.getElementById(dot.dataset.section);
                    if (target) {
                        const y = target.getBoundingClientRect().top + window.pageYOffset - 20;
                        window.scrollTo({ top: y, behavior: 'smooth' });
                    }
                });
            });
        })();
        </script>"""

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {{
    --bg: #0a0e17;
    --surface: #111827;
    --surface2: #1a2236;
    --border: #1e293b;
    --border-bright: #2d3f5f;
    --text: #e2e8f0;
    --text-dim: #64748b;
    --text-muted: #475569;
    --accent: #22d3ee;
    --accent-glow: rgba(34,211,238,0.15);
    --green: #34d399;
    --green-glow: rgba(52,211,153,0.15);
    --red: #f87171;
    --red-glow: rgba(248,113,113,0.12);
    --amber: #fbbf24;
    --amber-glow: rgba(251,191,36,0.12);
    --mono: 'JetBrains Mono','SF Mono','Fira Code',monospace;
    --sans: 'Inter',-apple-system,BlinkMacSystemFont,sans-serif;
}}
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ background:var(--bg); color:var(--text); font-family:var(--sans); font-size:13px; line-height:1.55; }}

.topbar {{
    background:linear-gradient(135deg,#0f172a 0%,#1a1040 50%,#1a0a2e 100%);
    border-bottom:1px solid var(--border-bright);
    padding:16px 28px;
    display:flex; align-items:center; justify-content:space-between;
}}
.topbar-title {{ font-family:var(--mono); font-size:11px; font-weight:600; letter-spacing:3px; text-transform:uppercase; color:var(--accent); }}
.topbar-sub {{ font-family:var(--mono); font-size:10px; color:var(--text-muted); letter-spacing:1px; }}
.container {{ padding:24px 28px 32px; }}

/* Widgets */
.widget {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; margin-bottom:16px; overflow:hidden; }}
.widget-header {{ font-family:var(--mono); font-size:10px; font-weight:600; letter-spacing:2px; color:var(--accent); padding:12px 18px; background:var(--surface2); border-bottom:1px solid var(--border); display:flex; align-items:center; gap:8px; }}
.widget-icon {{ font-size:12px; opacity:0.7; }}
.dim {{ color:var(--text-dim)!important; font-style:italic; }}
.mono {{ font-family:var(--mono); }}

/* Threat gauge */
.threat-content {{ display:flex; align-items:center; gap:28px; padding:20px 24px; }}
.gauge-container {{ flex-shrink:0; }}
.gauge-ring {{ width:130px; height:130px; position:relative; }}
.gauge-svg {{ width:100%; height:100%; }}
.gauge-text {{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; }}
.gauge-score {{ font-family:var(--mono); font-size:38px; font-weight:700; line-height:1; text-shadow: 0 0 20px currentColor; }}
.gauge-label {{ font-family:var(--mono); font-size:10px; font-weight:600; letter-spacing:2px; color:var(--text-dim); margin-top:4px; }}
.threat-factors {{ flex:1; min-width:0; }}
.factors-title {{ font-family:var(--mono); font-size:9px; font-weight:600; letter-spacing:2px; color:var(--text-muted); margin-bottom:8px; }}
.factor-row {{ display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid rgba(30,41,59,0.5); font-size:12px; }}
.factor-desc {{ color:var(--text); }}
.factor-pts {{ font-family:var(--mono); color:var(--red); font-weight:600; font-size:11px; }}

/* Auth */
.auth-badges {{ display:flex; flex-direction:column; gap:8px; padding:14px 18px; }}
.auth-chip {{ display:flex; align-items:center; gap:8px; padding:10px 14px; border-radius:6px; border:1px solid var(--border); background:var(--surface2); }}
.auth-chip.pass {{ border-color:rgba(52,211,153,0.3); background:var(--green-glow); }}
.auth-chip.fail {{ border-color:rgba(248,113,113,0.3); background:var(--red-glow); }}
.auth-icon {{ font-family:var(--mono); font-weight:700; font-size:14px; }}
.auth-chip.pass .auth-icon {{ color:var(--green); }}
.auth-chip.fail .auth-icon {{ color:var(--red); }}
.auth-chip.unknown .auth-icon {{ color:var(--text-muted); }}
.auth-label {{ font-family:var(--mono); font-size:10px; font-weight:600; letter-spacing:1px; color:var(--text-dim); }}
.auth-val {{ font-family:var(--mono); font-size:12px; font-weight:600; margin-left:auto; }}
.auth-chip.pass .auth-val {{ color:var(--green); }}
.auth-chip.fail .auth-val {{ color:var(--red); }}
.auth-chip.unknown .auth-val {{ color:var(--text-muted); }}

/* Sender */
.sender-flags {{ padding:12px 18px; display:flex; gap:8px; flex-wrap:wrap; }}
.sender-grid {{ display:grid; grid-template-columns:1fr 1fr; }}
.sender-item {{ padding:10px 18px; border-bottom:1px solid var(--border); border-right:1px solid var(--border); }}
.sender-item:nth-child(even) {{ border-right:none; }}
.sender-label {{ font-family:var(--mono); font-size:9px; font-weight:600; letter-spacing:1.5px; color:var(--text-muted); display:block; margin-bottom:3px; }}
.sender-val {{ font-size:12px; color:var(--text); word-break:break-all; }}

/* Flag badges */
.flag-badge {{ font-family:var(--mono); font-size:9px; font-weight:700; letter-spacing:1px; padding:3px 8px; border-radius:4px; }}
.flag-crit {{ background:rgba(239,68,68,0.15); color:#f87171; border:1px solid rgba(239,68,68,0.3); }}
.flag-warn {{ background:rgba(251,191,36,0.12); color:#fbbf24; border:1px solid rgba(251,191,36,0.25); }}

/* Link analysis */
.link-table {{ font-size:12px; }}
.link-table-header {{ display:grid; grid-template-columns:1fr 1.5fr auto; gap:12px; padding:10px 18px; background:var(--surface2); font-family:var(--mono); font-size:9px; font-weight:600; letter-spacing:1.5px; color:var(--text-muted); border-bottom:1px solid var(--border); }}
.link-row {{ display:grid; grid-template-columns:1fr 1.5fr auto; gap:12px; padding:10px 18px; border-bottom:1px solid var(--border); align-items:start; }}
.link-flagged {{ background:rgba(248,113,113,0.04); }}
.link-display {{ color:var(--text); word-break:break-all; }}
.link-href {{ font-family:var(--mono); font-size:11px; color:var(--text-dim); word-break:break-all; }}
.link-flags {{ display:flex; gap:4px; flex-wrap:wrap; }}
.link-findings {{ padding:12px 18px; border-bottom:1px solid var(--border); }}
.finding-item {{ font-size:12px; color:var(--amber); padding:3px 0; }}

/* Urgency */
.urgency-content {{ padding:14px 18px; }}
.urgency-bar-row {{ display:flex; align-items:center; gap:12px; margin-bottom:8px; }}
.urgency-keyword {{ font-family:var(--mono); font-size:11px; color:var(--text); width:140px; flex-shrink:0; }}
.urgency-bar {{ flex:1; height:6px; background:var(--surface2); border-radius:3px; overflow:hidden; }}
.urgency-fill {{ height:100%; background:linear-gradient(90deg,#fbbf24,#f97316); border-radius:3px; }}
.urgency-count {{ font-family:var(--mono); font-size:11px; color:var(--amber); width:30px; text-align:right; }}
.urgency-note {{ padding:10px 18px; font-size:12px; color:var(--amber); border-top:1px solid var(--border); }}

/* Attachments */
.att-row {{ padding:12px 18px; border-bottom:1px solid var(--border); }}
.att-info {{ display:flex; align-items:baseline; gap:12px; margin-bottom:4px; }}
.att-name {{ font-weight:500; color:var(--text); }}
.att-meta {{ font-family:var(--mono); font-size:11px; color:var(--text-dim); }}
.att-hashes {{ font-family:var(--mono); font-size:10px; color:var(--text-muted); display:flex; gap:16px; margin-bottom:4px; }}
.att-flags {{ display:flex; gap:4px; }}

/* Language */
.lang-content {{ padding:14px 18px; }}
.lang-score {{ font-family:var(--mono); font-size:18px; font-weight:700; margin-bottom:6px; }}
.lang-label {{ font-size:11px; font-weight:600; letter-spacing:1px; opacity:0.8; }}
.lang-findings {{ padding:4px 0; }}

/* Domain age */
.domain-content {{ padding:14px 18px; }}
.domain-age {{ font-family:var(--mono); font-size:18px; font-weight:700; margin-bottom:4px; }}
.domain-label {{ font-size:11px; font-weight:600; letter-spacing:1px; opacity:0.8; }}
.domain-detail {{ font-size:12px; color:var(--text-dim); }}

/* URL scan */
.urlscan-content {{ padding:14px 18px; }}
.urlscan-verdict {{ font-family:var(--mono); font-size:14px; font-weight:700; margin-bottom:6px; }}
.urlscan-detail {{ font-size:12px; color:var(--text-dim); margin-bottom:4px; }}
.urlscan-link {{ font-size:12px; }}

/* IP */
.ip-grid {{ display:grid; grid-template-columns:1fr 1fr; }}
.ip-main {{ padding:18px; border-right:1px solid var(--border); }}
.ip-address {{ font-family:var(--mono); font-size:22px; font-weight:700; color:var(--accent); text-shadow:0 0 20px var(--accent-glow); margin-bottom:6px; }}
.ip-org {{ font-size:13px; color:var(--text); font-weight:500; margin-bottom:2px; }}
.ip-asn {{ font-family:var(--mono); font-size:11px; color:var(--text-dim); }}
.ip-geo {{ padding:14px 18px; }}
.geo-row {{ display:flex; align-items:baseline; padding:4px 0; border-bottom:1px solid rgba(30,41,59,0.5); }}
.geo-row:last-child {{ border-bottom:none; }}
.geo-label {{ font-family:var(--mono); font-size:9px; font-weight:600; letter-spacing:1.5px; color:var(--text-muted); width:80px; flex-shrink:0; }}
.geo-val {{ font-size:12px; color:var(--text); }}

/* Metadata */
.meta-row {{ display:flex; padding:8px 18px; border-bottom:1px solid var(--border); }}
.meta-row:last-child {{ border-bottom:none; }}
.meta-label {{ font-family:var(--mono); font-size:9px; font-weight:600; letter-spacing:1.5px; color:var(--text-muted); width:120px; flex-shrink:0; padding-top:2px; }}
.meta-val {{ font-family:var(--mono); font-size:11px; color:var(--text-dim); word-break:break-all; }}

/* Hops */
.hop-trace {{ padding:16px 18px; }}
.hop-item {{ display:flex; align-items:flex-start; gap:12px; margin-bottom:12px; position:relative; }}
.hop-item:last-child {{ margin-bottom:0; }}
.hop-num {{ font-family:var(--mono); font-size:10px; font-weight:700; color:var(--accent); width:20px; height:20px; border:1.5px solid var(--accent); border-radius:50%; display:flex; align-items:center; justify-content:center; flex-shrink:0; background:var(--accent-glow); }}
.hop-line {{ position:absolute; left:9px; top:22px; bottom:-14px; width:1px; background:var(--border-bright); }}
.hop-item:last-child .hop-line {{ display:none; }}
.hop-detail {{ font-size:12px; }}
.hop-from {{ color:var(--text); font-weight:500; }}
.hop-arrow {{ color:var(--accent); margin:0 6px; font-family:var(--mono); }}
.hop-to {{ color:var(--text); font-weight:500; }}
.hop-ip {{ font-family:var(--mono); font-size:11px; color:var(--amber); margin-left:6px; }}
.hop-date {{ font-family:var(--mono); font-size:10px; color:var(--text-muted); margin-top:2px; }}

/* Country flags */
.ip-flag {{ cursor: help; font-size: 14px; margin-left: 4px; vertical-align: middle; }}
.ip-flag:hover {{ filter: drop-shadow(0 0 4px rgba(34,211,238,0.5)); }}

/* Envelope */
.envelope {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; margin-bottom:16px; overflow:hidden; }}
.env-row {{ display:flex; padding:8px 18px; border-bottom:1px solid var(--border); }}
.env-row:last-child {{ border-bottom:none; }}
.env-label {{ font-family:var(--mono); font-size:9px; font-weight:700; letter-spacing:2px; color:var(--accent); width:100px; flex-shrink:0; padding-top:2px; }}
.env-val {{ font-size:13px; color:var(--text); word-break:break-word; }}

/* Email body */
.body-label {{ font-family:var(--mono); font-size:10px; font-weight:600; letter-spacing:2px; color:var(--text-muted); padding:10px 0 8px; }}
.body-section {{
    background: linear-gradient(168deg, #1a1f2e 0%, #151a27 40%, #121620 100%);
    border: 1px solid var(--border-bright);
    border-radius: 10px;
    padding: 32px;
    color: #c9d1d9;
    font-size: 14px;
    line-height: 1.7;
    overflow: hidden;
    position: relative;
    box-shadow: inset 0 1px 0 rgba(255,255,255,0.03), 0 4px 24px rgba(0,0,0,0.3);
}}
.body-section::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(34,211,238,0.2), transparent);
}}
.body-section img {{ max-width:100%!important; height:auto!important; filter: brightness(0.92); }}
.body-section table {{ max-width:100%!important; }}
.body-section a {{ color: #60a5fa; text-decoration: underline; text-decoration-color: rgba(96,165,250,0.3); text-underline-offset: 2px; transition: all 0.2s; }}
.body-section a:hover {{ color: #93bbfc; text-decoration-color: rgba(96,165,250,0.7); }}
.body-section td, .body-section th {{ color: #c9d1d9 !important; }}
.body-section p, .body-section div, .body-section span {{ color: inherit; }}

/* IOC lookup badges */
.ioc-wrap {{
    display: inline;
    font-family: var(--mono);
    word-break: break-all;
}}
.ioc-badge {{
    display: inline-block;
    font-family: var(--mono);
    font-size: 8px;
    font-weight: 700;
    letter-spacing: 1px;
    padding: 2px 6px;
    border-radius: 3px;
    margin-left: 6px;
    vertical-align: middle;
    text-decoration: none !important;
    cursor: pointer;
    transition: all 0.15s ease;
}}
.vt-badge {{
    background: rgba(0, 102, 204, 0.15);
    color: #4da6ff;
    border: 1px solid rgba(0, 102, 204, 0.3);
}}
.vt-badge:hover {{
    background: rgba(0, 102, 204, 0.3);
    box-shadow: 0 0 8px rgba(0, 102, 204, 0.3);
    color: #80c0ff;
}}
.us-badge {{
    background: rgba(52, 211, 153, 0.12);
    color: #34d399;
    border: 1px solid rgba(52, 211, 153, 0.25);
}}
.us-badge:hover {{
    background: rgba(52, 211, 153, 0.25);
    box-shadow: 0 0 8px rgba(52, 211, 153, 0.25);
    color: #6ee7b7;
}}

/* Grid helpers */
.row-2 {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }}
.row-2 .widget {{ margin-bottom:0; }}

/* Footer */
.footer {{ font-family:var(--mono); font-size:9px; color:var(--text-muted); text-align:center; padding:16px; letter-spacing:1px; border-top:1px solid var(--border); margin-top:8px; }}

/* Gemini AI */
.gemini-widget {{ border-color: rgba(139, 92, 246, 0.3); }}
.gemini-widget .widget-header {{ color: #a78bfa; }}
.gemini-content {{ padding: 18px; font-size: 13px; line-height: 1.7; color: var(--text); }}
.gemini-content p {{ margin-bottom: 10px; }}
.gemini-content strong {{ color: #c4b5fd; }}
.gemini-h1 {{ font-family: var(--mono); font-size: 14px; font-weight: 700; color: #a78bfa; margin: 16px 0 8px; letter-spacing: 1px; }}
.gemini-h2 {{ font-family: var(--mono); font-size: 12px; font-weight: 600; color: #a78bfa; margin: 14px 0 6px; letter-spacing: 0.5px; }}
.gemini-list {{ margin: 6px 0 12px 20px; padding: 0; }}
.gemini-list li {{ margin-bottom: 4px; color: var(--text); }}

/* Scanline */
body::before {{ content:''; position:fixed; top:0;left:0;right:0;bottom:0; background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px); pointer-events:none; z-index:9999; }}

/* ====== UI/UX ENHANCEMENTS ====== */
html {{ scroll-behavior: smooth; }}

/* Container centering */
.container {{ max-width:1000px; margin:0 auto; width:100%; }}

/* Smooth widget collapse/expand */
.widget-content {{ max-height:2000px; overflow:hidden; transition: max-height 0.4s ease, opacity 0.3s ease; opacity:1; }}
.widget-content.collapsed {{ max-height:0; opacity:0; }}

/* Widget header hover + chevron */
.widget-header {{ transition: background 0.2s ease; position:relative; }}
.widget-header:hover {{ background: linear-gradient(135deg, var(--surface2), rgba(34,211,238,0.06)); }}
.widget-header::after {{ content:'▾'; margin-left:auto; font-size:12px; color:var(--text-muted); transition: transform 0.3s ease; }}
.collapsed-header::after {{ transform: rotate(-90deg); }}
.widget-header:hover .widget-icon {{ transform: rotate(90deg); }}
.widget-icon {{ transition: transform 0.3s ease; display:inline-block; }}

/* Widget entrance animations (interactive only) */
@keyframes fadeInUp {{
    from {{ opacity:0; transform:translateY(24px); }}
    to {{ opacity:1; transform:translateY(0); }}
}}
body.interactive .widget,
body.interactive .envelope {{ opacity:0; transform:translateY(24px); }}
body.interactive .widget.visible,
body.interactive .envelope.visible {{ animation: fadeInUp 0.5s ease forwards; }}

/* Widget hover glow */
.widget {{ transition: border-color 0.3s ease, box-shadow 0.3s ease; }}
.widget:hover {{ border-color: rgba(34,211,238,0.25); box-shadow: 0 0 16px rgba(34,211,238,0.08); }}
.threat-widget:hover {{ border-color: rgba(248,113,113,0.3); box-shadow: 0 0 20px rgba(248,113,113,0.1); }}
.gemini-widget:hover {{ border-color: rgba(139,92,246,0.35); box-shadow: 0 0 20px rgba(139,92,246,0.12); }}
.urgency-widget:hover {{ border-color: rgba(251,191,36,0.3); box-shadow: 0 0 20px rgba(251,191,36,0.1); }}

/* Threat gauge glow */
.gauge-glow {{ position:absolute; inset:-20px; border-radius:50%; opacity:0.4; pointer-events:none; animation: pulseGlow 2.5s ease-in-out infinite alternate; }}
@keyframes pulseGlow {{ from {{ opacity:0.3; transform:scale(0.95); }} to {{ opacity:0.5; transform:scale(1.05); }} }}

/* Section navigation */
.section-nav {{
    position:fixed; right:16px; top:50%; transform:translateY(-50%);
    z-index:9000; display:flex; flex-direction:column; gap:2px;
    background:rgba(17,24,39,0.85); backdrop-filter:blur(12px);
    border:1px solid var(--border-bright); border-radius:10px;
    padding:10px 8px; min-width:44px;
}}
.nav-group {{ margin-bottom:6px; }}
.nav-group:last-child {{ margin-bottom:0; }}
.nav-group-label {{
    font-family:var(--mono); font-size:7px; font-weight:700;
    letter-spacing:2px; text-transform:uppercase; color:var(--text-muted);
    padding:4px 8px 2px; opacity:0.6;
}}
.nav-dot {{
    display:flex; align-items:center; gap:6px; padding:4px 8px;
    text-decoration:none; color:var(--text-dim); border-radius:6px;
    transition: all 0.2s ease; font-size:11px;
}}
.nav-dot:hover {{
    color:var(--accent); background:rgba(34,211,238,0.08);
}}
.nav-dot-icon {{ font-size:8px; transition: transform 0.2s ease; }}
.nav-dot-text {{ font-family:var(--mono); font-size:9px; font-weight:500; letter-spacing:0.5px; white-space:nowrap; }}
.nav-dot.active {{
    color:var(--accent);
    background:rgba(34,211,238,0.1);
}}
.nav-dot.active .nav-dot-icon {{ transform:scale(1.3); text-shadow:0 0 6px var(--accent); }}

/* Copy-to-clipboard buttons */
.copy-btn {{
    width:20px; height:20px; display:inline-flex; align-items:center; justify-content:center;
    background:transparent; border:1px solid var(--border); border-radius:4px;
    color:var(--text-dim); cursor:pointer; opacity:0; transition: all 0.2s ease;
    padding:0; margin-left:4px; vertical-align:middle; position:relative;
}}
.ioc-wrap:hover .copy-btn,
.att-hash:hover .copy-btn {{ opacity:1; }}
.copy-btn:hover {{ background:var(--surface2); color:var(--accent); border-color:var(--accent); }}
.copy-feedback {{
    position:absolute; top:-28px; left:50%; transform:translateX(-50%);
    background:var(--green); color:#0a0e17; font-family:var(--mono); font-size:9px;
    font-weight:700; padding:3px 8px; border-radius:4px; white-space:nowrap;
    animation: fadeInUp 0.2s ease; pointer-events:none; z-index:100;
}}

/* Custom tooltips */
.custom-tooltip {{
    position:fixed; z-index:10001; display:none; opacity:0;
    background:linear-gradient(135deg, #1a2236, #111827);
    border:1px solid var(--border-bright); border-radius:6px;
    padding:6px 10px; font-family:var(--mono); font-size:10px;
    color:var(--text); box-shadow:0 4px 16px rgba(0,0,0,0.5);
    max-width:400px; word-break:break-all; pointer-events:none;
    transition: opacity 0.15s ease;
}}

/* Collapsible email body */
.body-collapse-container {{ position:relative; }}
.body-section.collapsed-body {{ max-height:400px; overflow:hidden; transition: max-height 0.5s ease; }}
.body-fade-overlay {{
    position:absolute; bottom:40px; left:0; right:0; height:120px;
    background:linear-gradient(to bottom, transparent, var(--bg));
    pointer-events:none; z-index:1;
}}
.body-toggle-btn {{
    display:block; width:100%; padding:10px; margin-top:4px;
    background:var(--surface); border:1px solid var(--border);
    border-radius:6px; color:var(--text-dim); font-family:var(--mono);
    font-size:10px; font-weight:600; letter-spacing:1.5px; cursor:pointer;
    transition: all 0.2s ease; text-align:center;
}}
.body-toggle-btn:hover {{ color:var(--accent); border-color:var(--accent); background:rgba(34,211,238,0.05); }}

/* ====== RESPONSIVE DESIGN ====== */

/* Tablet */
@media (max-width: 768px) {{
    .container {{ padding:16px; }}
    .topbar {{ flex-direction:column; gap:8px; padding:12px 16px; text-align:center; }}
    .row-2 {{ grid-template-columns:1fr; }}
    .ip-grid {{ grid-template-columns:1fr; }}
    .ip-main {{ border-right:none; border-bottom:1px solid var(--border); }}
    .sender-grid {{ grid-template-columns:1fr; }}
    .sender-item {{ border-right:none; }}
    .link-table-header, .link-row {{ grid-template-columns:1fr 1fr; }}
    .link-flags {{ grid-column: 1 / -1; }}
    .widget-header {{ padding:10px 14px; font-size:9px; }}
    .threat-content {{ flex-direction:column; padding:16px; gap:16px; }}
    body {{ font-size:12px; }}
    .section-nav .nav-dot-text,
    .section-nav .nav-group-label {{ display:none; }}
    .section-nav {{ padding:8px 6px; min-width:32px; }}
    .nav-dot {{ padding:5px; justify-content:center; }}
    .nav-dot-icon {{ font-size:10px; }}
}}

/* Mobile */
@media (max-width: 480px) {{
    .container {{ padding:12px 10px; }}
    .topbar {{ padding:10px 12px; }}
    body {{ font-size:11px; }}
    .widget {{ border-radius:6px; }}
    .widget-header {{ padding:8px 12px; font-size:8px; }}
    .link-table-header {{ display:none; }}
    .link-row {{
        grid-template-columns:1fr; gap:4px; padding:10px 14px;
        border-left:2px solid var(--border-bright);
    }}
    .link-row > div::before {{ font-family:var(--mono); font-size:8px; font-weight:600; letter-spacing:1px; color:var(--text-muted); display:block; margin-bottom:2px; }}
    .link-display::before {{ content:'DISPLAY'; }}
    .link-href::before {{ content:'URL'; }}
    .link-flags::before {{ content:'FLAGS'; }}
    .env-row, .meta-row {{ flex-direction:column; gap:4px; }}
    .env-label, .meta-label {{ width:auto; }}
    .body-section {{ padding:14px; font-size:12px; }}
    .section-nav .nav-dot-text,
    .section-nav .nav-group-label {{ display:none; }}
    .section-nav {{ right:8px; padding:6px 4px; min-width:28px; border-radius:8px; }}
    .nav-dot {{ padding:4px; }}
    .nav-dot-icon {{ font-size:8px; }}
    .row-2 {{ grid-template-columns:1fr; }}
    .ip-grid {{ grid-template-columns:1fr; }}
    .ip-main {{ border-right:none; border-bottom:1px solid var(--border); }}
    .sender-grid {{ grid-template-columns:1fr; }}
    .sender-item {{ border-right:none; }}
    .gauge-ring {{ width:100px; height:100px; }}
    .gauge-score {{ font-size:30px; }}
}}

/* Print */
@media print {{
    .section-nav {{ display:none; }}
    body::before {{ display:none; }}
    .widget {{ break-inside:avoid; box-shadow:none; }}
}}
</style>
</head>
<body{' class="interactive"' if interactive else ''}>
{nav_html}
<div class="topbar">
    <div>
        <div class="topbar-title">▲ PHISHING EMAIL FORENSIC ANALYSIS</div>
        <div class="topbar-sub">{escape(headers.get('Subject','untitled')[:80])}</div>
    </div>
    <div class="topbar-sub">{datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</div>
</div>
<div class="container">

{threat_gauge_html(threat)}

{gemini_widget_html(analysis.get('gemini') or dict())}

<div class="row-2">
    {sender_analysis_html(analysis['sender'])}
    <div>
        <div class="widget auth-widget" id="nav-auth">
            <div class="widget-header"><span class="widget-icon">◈</span> EMAIL AUTHENTICATION</div>
            <div class="auth-badges">
                {auth_badge_html("SPF", auth["spf"])}
                {auth_badge_html("DKIM", auth["dkim"])}
                {auth_badge_html("DMARC", auth["dmarc"])}
            </div>
        </div>
    </div>
</div>

{link_analysis_html(analysis['links'])}
{urgency_html(analysis['urgency'])}

<div class="row-2">
    {language_html(analysis['language'])}
    {domain_age_html(analysis.get('domain_age') or dict(), analysis['sender'].get('from_domain',''))}
</div>

{attachment_html(analysis['attachments'])}
{ip_widget_html(analysis.get('ip_data'), analysis.get('source_ip', ''))}
{urlscan_html(analysis.get('urlscan') or dict())}
{hop_trace_html(analysis.get('hops', []), ip_geo_map=analysis.get('ip_geo_map', {}))}

{meta_widget}

<div class="envelope" id="nav-envelope">{env_rows}</div>

<div class="body-label">▼ EMAIL BODY (RENDERED)</div>
<div class="body-section" id="nav-body">{body_html}</div>

</div>
<div class="footer">GENERATED BY EML2PNG PHISHING ANALYZER · {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
{interactive_js}
{nav_js}
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# RENDER PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def run_analysis(parsed: dict, do_api: bool = True, do_gemini: bool = False, gemini_model: str = "gemini-2.5-flash") -> dict:
    """Run all analysis modules and API lookups."""
    print("  Analyzing links...")
    links = analyze_links(parsed)

    print("  Analyzing sender...")
    sender = analyze_sender(parsed)

    print("  Scanning urgency patterns...")
    urgency = analyze_urgency(parsed)

    print("  Checking attachments...")
    att = analyze_attachments(parsed)

    print("  Analyzing language...")
    lang = analyze_language(parsed)

    # IP
    ips = extract_ips(parsed["received"])
    source_ip = ips[0] if ips else ""
    ip_data = None
    if source_ip and do_api:
        print(f"  Looking up IP: {source_ip}")
        ip_data = lookup_ip(source_ip)
    elif source_ip:
        ip_data = {"error": "API calls skipped"}

    # Domain age
    domain_age = {}
    from_domain = sender.get("from_domain", "")
    if from_domain and do_api:
        print(f"  Checking domain age: {from_domain}")
        domain_age = lookup_domain_age(from_domain)

    domain_age_days = domain_age.get("age_days") if "error" not in domain_age else None

    # urlscan.io
    urlscan = {}
    suspicious_links = [l for l in links.get("links", []) if l.get("flags")]
    if suspicious_links and do_api and os.environ.get("URLSCAN_API_KEY"):
        first_sus = suspicious_links[0]["href"]
        print(f"  Querying urlscan.io: {first_sus[:60]}...")
        urlscan = lookup_urlscan(first_sus)

    # MXToolbox — validate SPF, DKIM, DMARC
    mx_data = {}
    if from_domain and do_api and os.environ.get("MXTOOLBOX_API_KEY"):
        print(f"  Querying MXToolbox (SPF/DKIM/DMARC): {from_domain}")
        mx_data = lookup_mxtoolbox(from_domain)

        # Enrich auth results with MXToolbox validation
        if "error" not in mx_data:
            auth = parsed["auth"]
            for proto in ("spf", "dkim", "dmarc"):
                mx_check = mx_data.get(proto, {})
                if "error" in mx_check:
                    continue
                mx_status = mx_check.get("status", "")
                # If header-based auth is missing, use MXToolbox result
                if not auth.get(proto) and mx_status:
                    auth[proto] = mx_status
                # If MXToolbox says fail but header says pass, flag the discrepancy
                if mx_status == "fail" and auth.get(proto, "").lower() == "pass":
                    sender["findings"].append(
                        f"MXToolbox {proto.upper()} check failed despite header claiming pass"
                    )
                    sender["flags"].append((f"MXTOOLBOX {proto.upper()} FAIL", "warning"))

    # Hops
    hops = parse_hops(parsed["received"])

    # Geo-lookup all unique public hop IPs
    ip_geo_map = {}
    if do_api:
        hop_ips = set()
        for h in hops:
            hip = h.get("ip", "")
            if hip and not _PRIVATE_RE.match(hip):
                hop_ips.add(hip)
        for hip in hop_ips:
            if hip == source_ip and ip_data and "error" not in ip_data:
                ip_geo_map[hip] = ip_data
            else:
                print(f"  Looking up hop IP: {hip}")
                ip_geo_map[hip] = lookup_ip(hip)

    # Threat score
    print("  Calculating threat score...")
    threat = calculate_threat_score(
        parsed["auth"], sender, links, urgency, att, lang, ip_data, domain_age_days
    )

    # Highlighted body
    print("  Highlighting body...")
    highlighted = highlight_body(parsed["html_body"], urgency.get("positions", []), links)

    # Gemini AI assessment
    gemini_result = {}
    if do_gemini:
        print(f"  Querying Gemini ({gemini_model})...")
        context = build_gemini_context(parsed, {
            "sender": sender, "links": links, "urgency": urgency,
            "attachments": att, "language": lang, "threat": threat,
            "ip_data": ip_data, "source_ip": source_ip, "domain_age": domain_age,
        })
        gemini_result = query_gemini(context, model=gemini_model)
        if "error" in gemini_result:
            print(f"  ⚠ Gemini error: {gemini_result['error']}")
        else:
            print(f"  ✓ Gemini assessment received")
            # Bump threat score if Gemini verdict is phishing
            verdict = parse_gemini_verdict(gemini_result)
            if verdict == "phishing":
                bump = 50
                threat["score"] = min(100, threat["score"] + bump)
                threat["factors"].append(("Gemini AI verdict: PHISHING", bump))
                # Recalculate level based on new score
                s = threat["score"]
                if s >= 70: threat["level"] = "CRITICAL"
                elif s >= 45: threat["level"] = "HIGH"
                elif s >= 25: threat["level"] = "MEDIUM"
                elif s >= 10: threat["level"] = "LOW"
                else: threat["level"] = "CLEAN"
                print(f"  ⚠ Gemini says PHISHING — threat score bumped by +{bump} to {threat['score']}")
            elif verdict == "suspicious":
                bump = 25
                threat["score"] = min(100, threat["score"] + bump)
                threat["factors"].append(("Gemini AI verdict: SUSPICIOUS", bump))
                s = threat["score"]
                if s >= 70: threat["level"] = "CRITICAL"
                elif s >= 45: threat["level"] = "HIGH"
                elif s >= 25: threat["level"] = "MEDIUM"
                elif s >= 10: threat["level"] = "LOW"
                else: threat["level"] = "CLEAN"
                print(f"  ⚠ Gemini says SUSPICIOUS — threat score bumped by +{bump} to {threat['score']}")

    return {
        "links": links,
        "sender": sender,
        "urgency": urgency,
        "attachments": att,
        "language": lang,
        "ip_data": ip_data,
        "source_ip": source_ip,
        "domain_age": domain_age,
        "urlscan": urlscan,
        "mxtoolbox": mx_data,
        "hops": hops,
        "ip_geo_map": ip_geo_map,
        "threat": threat,
        "highlighted_body": highlighted,
        "gemini": gemini_result,
    }


def eml_to_png(
    eml_path: str,
    output_path: str = None,
    width: int = 1000,
    scale: float = 1.5,
    do_api: bool = True,
    emit_html: bool = False,
    do_gemini: bool = False,
    gemini_model: str = "gemini-2.5-flash",
    playwright_ctx=None,
):
    eml_path = Path(eml_path)
    output_path = Path(output_path) if output_path else eml_path.with_suffix(".png")

    print(f"\n{'═'*60}")
    print(f"  FILE: {eml_path.name}")
    print(f"{'═'*60}")

    print("  Parsing email...")
    parsed = parse_eml(str(eml_path))

    analysis = run_analysis(parsed, do_api=do_api, do_gemini=do_gemini, gemini_model=gemini_model)

    print("  Building infographic...")
    html_static = build_full_html(parsed, analysis, interactive=False)

    # Write interactive HTML if requested
    if emit_html:
        html_interactive = build_full_html(parsed, analysis, interactive=True)
        html_out = output_path.with_suffix(".html")
        with open(html_out, "w", encoding="utf-8") as f:
            f.write(html_interactive)
        print(f"  ✓ HTML: {html_out}")

    # Render PNG
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as tmp:
        tmp.write(html_static)
        tmp_path = tmp.name

    try:
        owns_browser = playwright_ctx is None
        if owns_browser:
            pw = sync_playwright().start()
            browser = pw.chromium.launch()
        else:
            pw, browser = playwright_ctx

        page = browser.new_page(viewport={"width": width, "height": 800}, device_scale_factor=scale)
        page.goto(f"file://{tmp_path}", wait_until="networkidle")
        page.screenshot(path=str(output_path), full_page=True)
        page.close()

        if owns_browser:
            browser.close()
            pw.stop()
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    score = analysis['threat']['score']
    level = analysis['threat']['level']
    print(f"  ✓ PNG: {output_path}")
    print(f"  ⬡ THREAT SCORE: {score}/100 [{level}]")

    return str(output_path)


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Forensic Analyzer — generates cyber-infographic PNGs and interactive HTML reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", help=".eml file or directory")
    parser.add_argument("-o", "--output", help="Output path")
    parser.add_argument("--width", type=int, default=1000, help="Viewport width (default: 1000)")
    parser.add_argument("--scale", type=float, default=1.5, help="Scale factor (default: 1.5)")
    parser.add_argument("--html", action="store_true", help="Also emit interactive HTML report")
    parser.add_argument("--gemini", action="store_true", help="Include Gemini AI phishing assessment (requires GEMINI_API_KEY)")
    parser.add_argument("--gemini-model", default="gemini-2.5-flash", help="Gemini model (default: gemini-2.5-flash)")
    parser.add_argument("--no-api", action="store_true", help="Skip all API lookups")
    args = parser.parse_args()

    input_path = Path(args.input)

    if input_path.is_file():
        eml_to_png(
            str(input_path), args.output,
            width=args.width, scale=args.scale,
            do_api=not args.no_api, emit_html=args.html,
            do_gemini=args.gemini, gemini_model=args.gemini_model,
        )

    elif input_path.is_dir():
        eml_files = sorted(input_path.glob("*.eml"))
        if not eml_files:
            sys.exit(f"No .eml files in {input_path}")

        out_dir = Path(args.output) if args.output else input_path / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)

        pw = sync_playwright().start()
        browser = pw.chromium.launch()

        for eml_file in eml_files:
            out_file = out_dir / eml_file.with_suffix(".png").name
            try:
                eml_to_png(
                    str(eml_file), str(out_file),
                    width=args.width, scale=args.scale,
                    do_api=not args.no_api, emit_html=args.html,
                    do_gemini=args.gemini, gemini_model=args.gemini_model,
                    playwright_ctx=(pw, browser),
                )
            except Exception as e:
                print(f"  ✗ {eml_file.name} — {e}")

        browser.close()
        pw.stop()
        print(f"\nDone. Reports in: {out_dir}")
    else:
        sys.exit(f"Not found: {input_path}")


if __name__ == "__main__":
    main()