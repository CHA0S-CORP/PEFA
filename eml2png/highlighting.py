"""Email body highlighting — injects visual indicators for urgency keywords and suspicious links."""

import html
import re
from urllib.parse import urlparse

from .constants import URGENCY_PATTERNS
from .deps import BeautifulSoup


def highlight_body(html_body: str, urgency_positions: list, link_analysis: dict) -> str:
    """Inject highlight styles into the email HTML body."""
    if not html_body:
        return html_body

    flagged_links = {}
    for link in link_analysis.get("links", []):
        if link.get("flags"):
            domain = link.get("domain", "").lower()
            flag_labels = [f[0] for f in link["flags"]]
            flagged_links[domain] = flag_labels

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
        function esc(s) { var d = document.createElement('div'); d.appendChild(document.createTextNode(s)); return d.innerHTML; }
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
                    + '<div style="color:#94a3b8;">Pattern: <span style="color:#fbbf24;">' + esc(label) + '</span></div>'
                    + '<div style="color:#64748b;font-size:10px;margin-top:3px;">Urgency/pressure language used in phishing</div>');
            });
            el.addEventListener('mouseleave', hidePopup);
        });
        document.querySelectorAll('.phish-hl-link-warn').forEach(function(el) {
            el.addEventListener('mouseenter', function(e) {
                var flags = el.getAttribute('data-flags') || 'SUSPICIOUS';
                var href = el.getAttribute('data-real-href') || el.getAttribute('href') || '';
                showPopup(e, '<div style="font-size:9px;font-weight:700;letter-spacing:1.5px;color:#f87171;margin-bottom:4px;">SUSPICIOUS LINK</div>'
                    + '<div style="color:#94a3b8;">Flags: <span style="color:#f87171;">' + esc(flags) + '</span></div>'
                    + (href ? '<div style="color:#64748b;font-size:10px;margin-top:3px;word-break:break-all;">Destination: ' + esc(href.substring(0,120)) + '</div>' : ''));
            });
            el.addEventListener('mouseleave', hidePopup);
        });
    })();
    </script>
    """

    modified = style_inject + html_body

    for pattern, label, *_ in URGENCY_PATTERNS:
        safe_label = html.escape(label, quote=True)
        modified = re.sub(
            f"(>)([^<]*?)({pattern})([^<]*?)(<)",
            lambda m: f'{m.group(1)}{m.group(2)}<span class="phish-hl-urgency" data-threat="{safe_label}" title="\u26a0 {safe_label}">{m.group(3)}</span>{m.group(4)}{m.group(5)}',
            modified,
            flags=re.I,
        )

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
                badge.string = "\u26a0 SUSPICIOUS"
                a.append(badge)
        modified = str(soup)

    return modified
