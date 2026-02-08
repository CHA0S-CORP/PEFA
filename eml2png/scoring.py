"""Phishing threat score calculation."""

LINK_FLAG_WEIGHTS = {
    "HREF MISMATCH": 10,
    "BRAND LOOKALIKE": 10,
    "HOMOGLYPH DOMAIN": 10,
    "IP-BASED URL": 8,
    "JAVASCRIPT URI": 8,
    "DATA URI": 8,
    "MALFORMED URL": 6,
    "URL SHORTENER": 3,
    "SUSPICIOUS TLD": 3,
    "EXCESSIVE URL LENGTH": 3,
    "PUNYCODE DOMAIN": 2,
    "MIME MISMATCH": 8,
    "DANGEROUS MIME TYPE": 8,
}


def calculate_threat_score(auth, sender, links, urgency, attachments, language, ip_data, domain_age_days) -> dict:
    """Calculate overall phishing threat score 0-100."""
    score = 0
    factors = []

    # Auth failures (max 20)
    auth_pts = 0
    if auth.get("spf", "").lower() in ("fail", "softfail"):
        auth_pts += 10; factors.append(("SPF failure", 10))
    if auth.get("dkim", "").lower() == "fail":
        auth_pts += 5; factors.append(("DKIM failure", 5))
    if auth.get("dmarc", "").lower() == "fail":
        auth_pts += 5; factors.append(("DMARC failure", 5))
    if not auth.get("spf") and not auth.get("dkim") and not auth.get("dmarc"):
        auth_pts += 8; factors.append(("No authentication", 8))
    score += min(auth_pts, 20)

    # Sender (max 20)
    sender_pts = 0
    for flag, _ in sender.get("flags", []):
        if "SPOOFING" in flag or "IMPERSONATION" in flag:
            sender_pts += 12; factors.append((flag, 12)); break
    for flag, _ in sender.get("flags", []):
        if "HOMOGLYPH" in flag:
            sender_pts += 12; factors.append((flag, 12)); break
    for flag, _ in sender.get("flags", []):
        if "REPLY-TO MISMATCH" in flag:
            sender_pts += 8; factors.append((flag, 8)); break
    for flag, _ in sender.get("flags", []):
        if "RETURN-PATH MISMATCH" in flag:
            sender_pts += 4; factors.append((flag, 4)); break
    score += min(sender_pts, 20)

    # Links (max 25) — weighted per flag type, deduplicated
    seen_flags = set()
    link_pts = 0
    for link in links.get("links", []):
        for flag_name, _ in link.get("flags", []):
            if flag_name not in seen_flags:
                seen_flags.add(flag_name)
                weight = LINK_FLAG_WEIGHTS.get(flag_name, 4)
                link_pts += weight
    link_pts = min(25, link_pts)
    if link_pts:
        score += link_pts; factors.append((f"Link flags: {', '.join(sorted(seen_flags))}", link_pts))

    # Urgency (max 15)
    urgency_pts = 0
    u_count = urgency.get("unique_count", 0)
    if u_count >= 5:
        urgency_pts += 15; factors.append(("Heavy urgency language", 15))
    elif u_count >= 3:
        urgency_pts += 10; factors.append(("Moderate urgency language", 10))
    elif u_count >= 1:
        urgency_pts += 5; factors.append(("Some urgency language", 5))

    if urgency.get("generic_greeting"):
        urgency_pts += 3; factors.append(("Generic greeting", 3))
    score += min(urgency_pts, 15)

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
    domain_age_pts = 0
    if domain_age_days is not None and domain_age_days < 30:
        domain_age_pts += 10; factors.append((f"Domain age: {domain_age_days} days", 10))
    elif domain_age_days is not None and domain_age_days < 90:
        domain_age_pts += 5; factors.append((f"Domain age: {domain_age_days} days", 5))
    score += min(domain_age_pts, 10)

    # Negative scoring for benign indicators
    spf_pass = auth.get("spf", "").lower() == "pass"
    dkim_pass = auth.get("dkim", "").lower() == "pass"
    dmarc_pass = auth.get("dmarc", "").lower() == "pass"
    if spf_pass and dkim_pass and dmarc_pass:
        score -= 5; factors.append(("All auth (SPF+DKIM+DMARC) passing", -5))
    if domain_age_days is not None and domain_age_days > 1095:  # >3 years
        score -= 3; factors.append((f"Established domain ({domain_age_days} days)", -3))

    score = max(0, min(100, score))

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
