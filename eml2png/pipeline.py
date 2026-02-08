"""Analysis pipeline orchestrator and PNG rendering."""

import os
import tempfile
from datetime import datetime
from pathlib import Path

from .analyzers import (
    LinkAnalyzer,
    SenderAnalyzer,
    UrgencyAnalyzer,
    AttachmentAnalyzer,
    LanguageAnalyzer,
)
from .api import IPLookupClient, URLScanClient, MXToolboxClient, GeminiClient, WhoisClient
from .constants import PRIVATE_IP_RE
from .deps import require_playwright, sync_playwright
from .highlighting import highlight_body
from .parser import parse_eml
from .sanitize import sanitize_html
from .renderers.page import PageRenderer
from .analyzers.ioc_consolidator import extract_iocs, enrich_iocs
from .scoring import calculate_threat_score
from .utils import convert_to_sender_timezone, resolve_hostname


def _safe_analyze(analyzer, parsed, label, default, log_fn=None):
    """Run an analyzer with error handling, returning default on failure."""
    try:
        return analyzer.analyze(parsed)
    except Exception as e:
        msg = f"\u26a0 {label} failed: {e}"
        if log_fn:
            log_fn(msg)
        else:
            print(f"  {msg}")
        return default


def run_analysis(parsed: dict, do_api: bool = True, do_gemini: bool = False,
                 gemini_model: str = "gemini-2.5-flash") -> dict:
    """Run all analysis modules and API lookups."""
    logs = []

    def _log(msg):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        entry = f"[{ts}] {msg}"
        print(f"  {msg}")
        logs.append(entry)

    _log("Analyzing links...")
    links = _safe_analyze(LinkAnalyzer(), parsed, "Link analysis",
                          {"links": [], "findings": []}, log_fn=_log)

    _log("Analyzing sender...")
    sender = _safe_analyze(SenderAnalyzer(), parsed, "Sender analysis",
                           {"from_display": "", "from_email": "", "from_domain": "",
                            "return_path": "", "rp_domain": "", "reply_to": "",
                            "flags": [], "findings": []}, log_fn=_log)

    _log("Scanning urgency patterns...")
    urgency = _safe_analyze(UrgencyAnalyzer(), parsed, "Urgency analysis",
                            {"matches": [], "positions": [], "unique_count": 0,
                             "total_count": 0, "density": 0, "generic_greeting": False,
                             "counter": {}}, log_fn=_log)

    _log("Checking attachments...")
    att = _safe_analyze(AttachmentAnalyzer(), parsed, "Attachment analysis",
                        {"attachments": []}, log_fn=_log)

    _log("Analyzing language...")
    lang = _safe_analyze(LanguageAnalyzer(), parsed, "Language analysis",
                         {"score": None, "findings": [], "issues": 0}, log_fn=_log)

    # IP
    ips = IPLookupClient.extract_ips(parsed["received"])
    source_ip = ips[0] if ips else ""
    ip_data = None
    if source_ip and do_api:
        _log(f"Looking up IP: {source_ip}")
        ip_data = IPLookupClient.lookup(source_ip)
    elif source_ip:
        ip_data = {"error": "API calls skipped"}

    # Sender local time (convert Date header to sender's timezone from IP geo)
    sender_local_time = None
    if ip_data and "error" not in ip_data and ip_data.get("timezone"):
        date_header = parsed.get("headers", {}).get("Date", "")
        result = convert_to_sender_timezone(date_header, ip_data["timezone"])
        if result:
            sender_local_time = result[0]
            _log(f"Sender local time: {sender_local_time}")

    # Domain age
    domain_age = {}
    from_domain = sender.get("from_domain", "")
    if from_domain and do_api:
        _log(f"Checking domain age: {from_domain}")
        domain_age = WhoisClient.lookup(from_domain)

    domain_age_days = domain_age.get("age_days") if "error" not in domain_age else None

    # urlscan.io
    urlscan = {}
    suspicious_links = [l for l in links.get("links", []) if l.get("flags")]
    if suspicious_links and do_api and os.environ.get("URLSCAN_API_KEY"):
        first_sus = suspicious_links[0]["href"]
        _log(f"Querying urlscan.io: {first_sus[:60]}...")
        urlscan = URLScanClient.lookup(first_sus)

    # MXToolbox
    mx_data = {}
    if from_domain and do_api and os.environ.get("MXTOOLBOX_API_KEY"):
        _log(f"Querying MXToolbox (SPF/DKIM/DMARC): {from_domain}")
        mx_data = MXToolboxClient.lookup(from_domain)

        if "error" not in mx_data:
            auth = parsed["auth"]
            for proto in ("spf", "dkim", "dmarc"):
                mx_check = mx_data.get(proto, {})
                if "error" in mx_check:
                    continue
                mx_status = mx_check.get("status", "")
                if not auth.get(proto) and mx_status:
                    auth[proto] = mx_status
                if mx_status == "fail" and auth.get(proto, "").lower() == "pass":
                    sender["findings"].append(
                        f"MXToolbox {proto.upper()} check failed despite header claiming pass"
                    )
                    sender["flags"].append((f"MXTOOLBOX {proto.upper()} FAIL", "warning"))
                # Add MXToolbox evidence
                ev_key = f"{proto}_evidence"
                if ev_key not in auth:
                    auth[ev_key] = []
                mx_passed = mx_check.get("passed", [])
                mx_failed = mx_check.get("failed", [])
                mx_warnings = mx_check.get("warnings", [])
                if mx_failed:
                    for item in mx_failed[:3]:
                        auth[ev_key].append(f"MXToolbox FAIL: {item}")
                if mx_warnings:
                    for item in mx_warnings[:2]:
                        auth[ev_key].append(f"MXToolbox WARN: {item}")
                if mx_passed and not mx_failed:
                    auth[ev_key].append(f"MXToolbox: {len(mx_passed)} check(s) passed")

    # Hops
    hops = IPLookupClient.parse_hops(parsed["received"])

    # Geo-lookup all unique public hop IPs
    ip_geo_map = {}
    host_geo_map = {}
    if do_api:
        hop_ips = set()
        for h in hops:
            hip = h.get("ip", "")
            if hip and not PRIVATE_IP_RE.match(hip):
                hop_ips.add(hip)
        for hip in hop_ips:
            if hip == source_ip and ip_data and "error" not in ip_data:
                ip_geo_map[hip] = ip_data
            else:
                _log(f"Looking up hop IP: {hip}")
                ip_geo_map[hip] = IPLookupClient.lookup(hip)

        # DNS-resolve hop hostnames and geo-locate for country flags
        resolved_cache = {}
        for h in hops:
            for field in ("from", "by"):
                hostname = h.get(field, "")
                if not hostname or hostname == "—" or hostname in host_geo_map:
                    continue
                if hostname in resolved_cache:
                    rip = resolved_cache[hostname]
                else:
                    rip = resolve_hostname(hostname)
                    resolved_cache[hostname] = rip
                if not rip or PRIVATE_IP_RE.match(rip):
                    continue
                if rip in ip_geo_map:
                    host_geo_map[hostname] = ip_geo_map[rip]
                else:
                    _log(f"Resolving {hostname} → {rip}")
                    geo = IPLookupClient.lookup(rip)
                    ip_geo_map[rip] = geo
                    if "error" not in geo:
                        host_geo_map[hostname] = geo

    # Threat score
    _log("Calculating threat score...")
    threat = calculate_threat_score(
        parsed["auth"], sender, links, urgency, att, lang, ip_data, domain_age_days
    )

    # Sanitize + highlight body
    _log("Sanitizing email body...")
    sanitized = sanitize_html(parsed["html_body"])
    _log("Highlighting body...")
    highlighted = highlight_body(sanitized, urgency.get("positions", []), links)

    # Gemini AI assessment
    gemini_result = {}
    if do_gemini:
        _log(f"Querying Gemini ({gemini_model})...")
        context = GeminiClient.build_context(parsed, {
            "sender": sender, "links": links, "urgency": urgency,
            "attachments": att, "language": lang, "threat": threat,
            "ip_data": ip_data, "source_ip": source_ip, "domain_age": domain_age,
        })
        gemini_result = GeminiClient.query(context, model=gemini_model)
        if "error" in gemini_result:
            _log(f"\u26a0 Gemini error: {gemini_result['error']}")
        else:
            _log("\u2713 Gemini assessment received")
            verdict = GeminiClient.parse_verdict(gemini_result)
            if verdict == "phishing":
                bump = 50
                threat["score"] = min(100, threat["score"] + bump)
                threat["factors"].append(("Gemini AI verdict: PHISHING", bump))
                s = threat["score"]
                if s >= 70: threat["level"] = "CRITICAL"
                elif s >= 45: threat["level"] = "HIGH"
                elif s >= 25: threat["level"] = "MEDIUM"
                elif s >= 10: threat["level"] = "LOW"
                else: threat["level"] = "CLEAN"
                _log(f"\u26a0 Gemini says PHISHING \u2014 threat score bumped by +{bump} to {threat['score']}")
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
                _log(f"\u26a0 Gemini says SUSPICIOUS \u2014 threat score bumped by +{bump} to {threat['score']}")

    # Ensure source IP is in ip_geo_map for consistent flag rendering
    if source_ip and ip_data and "error" not in ip_data and source_ip not in ip_geo_map:
        ip_geo_map[source_ip] = ip_data

    # IOC consolidation + enrichment
    _log("Consolidating IOCs...")
    analysis_parts = {
        "sender": sender, "links": links, "attachments": att,
    }
    iocs = extract_iocs(parsed, analysis_parts)
    ioc_total = sum(len(iocs[k]) for k in ("ips", "domains", "urls", "emails", "hashes"))
    _log(f"Found {ioc_total} IOC indicators")

    # Geo-lookup any IOC IPs not already in ip_geo_map (e.g. X-Originating-IP)
    if do_api:
        for entry in iocs.get("ips", []):
            ioc_ip = entry["value"]
            if ioc_ip not in ip_geo_map and not PRIVATE_IP_RE.match(ioc_ip):
                _log(f"Looking up IOC IP: {ioc_ip}")
                ip_geo_map[ioc_ip] = IPLookupClient.lookup(ioc_ip)

    if do_api and ioc_total > 0:
        iocs = enrich_iocs(iocs, do_api, _log)

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
        "host_geo_map": host_geo_map,
        "threat": threat,
        "highlighted_body": highlighted,
        "gemini": gemini_result,
        "sender_local_time": sender_local_time,
        "iocs": iocs,
        "logs": logs,
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
    require_playwright()

    eml_path = Path(eml_path)
    output_path = Path(output_path) if output_path else eml_path.with_suffix(".png")

    print(f"\n{'='*60}")
    print(f"  FILE: {eml_path.name}")
    print(f"{'='*60}")

    print("  Parsing email...")
    parsed = parse_eml(str(eml_path))

    analysis = run_analysis(parsed, do_api=do_api, do_gemini=do_gemini, gemini_model=gemini_model)

    renderer = PageRenderer()

    print("  Building infographic...")
    html_static = renderer.build(parsed, analysis, interactive=False)

    if emit_html:
        html_interactive = renderer.build(parsed, analysis, interactive=True)
        html_out = output_path.with_suffix(".html")
        with open(html_out, "w", encoding="utf-8") as f:
            f.write(html_interactive)
        print(f"  \u2713 HTML: {html_out}")

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
    print(f"  \u2713 PNG: {output_path}")
    print(f"  \u2b21 THREAT SCORE: {score}/100 [{level}]")

    return str(output_path)
