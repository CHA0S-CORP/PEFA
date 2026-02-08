"""Google Gemini AI phishing assessment client."""

import os
import re

from ..deps import req_lib
from ..parser import extract_plain_text
from ..utils import fmt_bytes
from .base import BaseAPIClient


class GeminiClient(BaseAPIClient):
    @staticmethod
    def query(context: str, model: str = "gemini-2.5-flash") -> dict:
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

        if not re.match(r'^[a-zA-Z0-9._-]+$', model):
            return {"error": "invalid model name"}

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

        except Exception:
            return {"error": "Gemini API request failed"}

    @staticmethod
    def parse_verdict(gemini_result: dict) -> str:
        text = gemini_result.get("text", "")
        if not text:
            return ""
        m = re.search(r"VERDICT[:\s*]+\*{0,2}\s*(phishing|suspicious|legitimate)", text, re.I)
        if m:
            return m.group(1).lower()
        return ""

    @staticmethod
    def build_context(parsed: dict, analysis: dict) -> str:
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
