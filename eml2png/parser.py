"""Email parsing — extracts headers, bodies, inline images, and attachments."""

import base64
import email
import email.policy
import hashlib
import re

from .deps import BeautifulSoup


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
                    "content_type": ct,
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
