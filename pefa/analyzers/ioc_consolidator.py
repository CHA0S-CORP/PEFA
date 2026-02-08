"""IOC consolidation and threat intelligence enrichment."""

import re

from ..api.ip_lookup import IPLookupClient
from ..api.virustotal import VirusTotalClient
from ..api.abuseipdb import AbuseIPDBClient
from ..api.alienvault import AlienVaultClient


def extract_iocs(parsed: dict, analysis: dict) -> dict:
    """Consolidate all IOCs from parsed email and analysis results."""
    ips = set()
    domains = set()
    urls = set()
    emails = set()
    hashes = set()

    # IPs from Received headers
    for ip in IPLookupClient.extract_ips(parsed.get("received", [])):
        ips.add(ip)

    # X-Originating-IP header
    xip = parsed.get("headers", {}).get("X-Originating-IP", "")
    xip = xip.strip().strip("[]")
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", xip):
        ips.add(xip)

    # Domains from sender analysis
    sender = analysis.get("sender", {})
    for d in [sender.get("from_domain", ""), sender.get("rp_domain", "")]:
        if d:
            domains.add(d.lower())

    # Domains and URLs from link analysis
    for link in analysis.get("links", {}).get("links", []):
        href = link.get("href", "")
        domain = link.get("domain", "")
        if domain:
            domains.add(domain.lower())
        if href and href.startswith("http"):
            urls.add(href)

    # Emails from headers
    headers = parsed.get("headers", {})
    for field in ["From", "Return-Path", "Reply-To"]:
        val = headers.get(field, "")
        addr_match = re.search(r"<([^>]+@[^>]+)>", val)
        addr = addr_match.group(1) if addr_match else val.strip()
        if "@" in addr:
            emails.add(addr.lower())

    # Hashes from attachment analysis
    for att in analysis.get("attachments", {}).get("attachments", []):
        sha256 = att.get("sha256", "")
        md5 = att.get("md5", "")
        if sha256:
            hashes.add(("sha256", sha256, att.get("name", "")))
        if md5:
            hashes.add(("md5", md5, att.get("name", "")))

    return {
        "ips": [{"value": ip, "source": "received headers"} for ip in sorted(ips)],
        "domains": [{"value": d, "source": "email analysis"} for d in sorted(domains)],
        "urls": [{"value": u, "source": "link analysis"} for u in sorted(urls)[:10]],
        "emails": [{"value": e, "source": "email headers"} for e in sorted(emails)],
        "hashes": [{"value": h[1], "type": h[0], "filename": h[2], "source": "attachments"} for h in sorted(hashes)],
    }


def enrich_iocs(iocs: dict, do_api: bool, log_fn=None) -> dict:
    """Enrich consolidated IOCs with threat intelligence from available services."""
    if not do_api:
        iocs["enrichment_summary"] = {"status": "skipped", "services": []}
        return iocs

    def _log(msg):
        if log_fn:
            log_fn(msg)

    services = []
    vt_ok = VirusTotalClient.available()
    abuse_ok = AbuseIPDBClient.available()
    otx_ok = AlienVaultClient.available()

    if vt_ok:
        services.append("virustotal")
    if abuse_ok:
        services.append("abuseipdb")
    if otx_ok:
        services.append("alienvault")

    if not services:
        iocs["enrichment_summary"] = {"status": "no_services", "services": []}
        return iocs

    _log(f"Enriching IOCs via: {', '.join(services)}")

    # Enrich IPs (max 5)
    for entry in iocs["ips"][:5]:
        ip = entry["value"]
        intel = {}
        if vt_ok:
            _log(f"VT lookup IP: {ip}")
            intel["virustotal"] = VirusTotalClient.lookup_ip(ip)
        if abuse_ok:
            _log(f"AbuseIPDB lookup: {ip}")
            intel["abuseipdb"] = AbuseIPDBClient.lookup(ip)
        if otx_ok:
            _log(f"OTX lookup IP: {ip}")
            intel["alienvault"] = AlienVaultClient.lookup_ip(ip)
        entry["threat_intel"] = intel

    # Enrich domains (max 5)
    for entry in iocs["domains"][:5]:
        domain = entry["value"]
        intel = {}
        if vt_ok:
            _log(f"VT lookup domain: {domain}")
            intel["virustotal"] = VirusTotalClient.lookup_domain(domain)
        if otx_ok:
            _log(f"OTX lookup domain: {domain}")
            intel["alienvault"] = AlienVaultClient.lookup_domain(domain)
        entry["threat_intel"] = intel

    # Enrich URLs (max 3)
    for entry in iocs["urls"][:3]:
        url = entry["value"]
        intel = {}
        if vt_ok:
            _log(f"VT lookup URL: {url[:60]}...")
            intel["virustotal"] = VirusTotalClient.lookup_url(url)
        if otx_ok:
            _log(f"OTX lookup URL: {url[:60]}...")
            intel["alienvault"] = AlienVaultClient.lookup_url(url)
        entry["threat_intel"] = intel

    # Enrich hashes (max 5)
    for entry in iocs["hashes"][:5]:
        h = entry["value"]
        intel = {}
        if vt_ok:
            _log(f"VT lookup hash: {h[:16]}...")
            intel["virustotal"] = VirusTotalClient.lookup_hash(h)
        if otx_ok:
            _log(f"OTX lookup hash: {h[:16]}...")
            intel["alienvault"] = AlienVaultClient.lookup_hash(h)
        entry["threat_intel"] = intel

    iocs["enrichment_summary"] = {
        "status": "completed",
        "services": services,
    }
    return iocs
