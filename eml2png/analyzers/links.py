"""Link extraction and analysis."""

import re
from urllib.parse import urlparse

from ..constants import URL_SHORTENERS, SUSPICIOUS_TLDS
from ..deps import BeautifulSoup
from ..utils import check_brand_impersonation, check_homoglyph_domain
from .base import BaseAnalyzer


class LinkAnalyzer(BaseAnalyzer):
    def analyze(self, parsed: dict) -> dict:
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

            if len(href) > 200:
                flags.append(("EXCESSIVE URL LENGTH", "warning"))

            try:
                parsed_url = urlparse(href)
                domain = parsed_url.hostname or ""
                tld = "." + domain.split(".")[-1] if "." in domain else ""
            except Exception:
                domain = ""
                tld = ""
                flags.append(("MALFORMED URL", "critical"))

            display_clean = display.strip().lower()
            if display_clean.startswith("http") or re.match(r"[\w.-]+\.\w{2,}", display_clean):
                try:
                    display_domain = urlparse(display_clean if "://" in display_clean else "http://" + display_clean).hostname or ""
                except Exception:
                    display_domain = ""
                if display_domain and domain and display_domain.lower() != domain.lower():
                    flags.append(("HREF MISMATCH", "critical"))
                    findings.append(f"Link text shows '{display_domain}' but goes to '{domain}'")

            if domain.lower() in URL_SHORTENERS:
                flags.append(("URL SHORTENER", "warning"))
                findings.append(f"Shortened URL via {domain}")

            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
                flags.append(("IP-BASED URL", "critical"))
                findings.append(f"Direct IP address URL: {domain}")

            if tld.lower() in SUSPICIOUS_TLDS:
                flags.append(("SUSPICIOUS TLD", "warning"))

            brand, is_impersonation = check_brand_impersonation(domain)
            if is_impersonation:
                flags.append(("BRAND LOOKALIKE", "critical"))
                findings.append(f"Domain '{domain}' mimics '{brand}'")

            if domain.startswith("xn--"):
                flags.append(("PUNYCODE DOMAIN", "warning"))
                findings.append(f"Internationalized domain (punycode): {domain}")

            normalized_domain, has_homoglyphs = check_homoglyph_domain(domain)
            if has_homoglyphs:
                flags.append(("HOMOGLYPH DOMAIN", "critical"))
                findings.append(f"Domain '{domain}' contains homoglyph characters (normalized: '{normalized_domain}')")

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
