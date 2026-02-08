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
        position: relative;
    }
    .phish-hl-urgency:hover {
        background: rgba(251,191,36,0.35);
        box-shadow: 0 0 16px rgba(251,191,36,0.4);
    }
    .phish-hl-urgency:hover::after {
        content: "\u26A0 " attr(data-threat);
        position: absolute;
        bottom: 100%;
        left: 0;
        margin-bottom: 6px;
        background: linear-gradient(135deg, #1e1032, #1a0a2e);
        border: 1px solid rgba(139,92,246,0.5);
        border-radius: 6px;
        padding: 8px 12px;
        font-family: monospace;
        font-size: 11px;
        color: #fbbf24;
        white-space: nowrap;
        max-width: 300px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.5), 0 0 20px rgba(139,92,246,0.15);
        z-index: 10000;
        pointer-events: none;
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
    .phish-hl-link-warn:hover::after {
        content: "\u26A0 " attr(data-flags);
        position: absolute;
        bottom: 100%;
        left: 0;
        margin-bottom: 6px;
        background: linear-gradient(135deg, #1e1032, #1a0a2e);
        border: 1px solid rgba(248,113,113,0.5);
        border-radius: 6px;
        padding: 8px 12px;
        font-family: monospace;
        font-size: 11px;
        color: #f87171;
        white-space: nowrap;
        max-width: 300px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.5), 0 0 20px rgba(248,113,113,0.15);
        z-index: 10000;
        pointer-events: none;
    }
    .phish-hl-active {
        outline: 2px solid rgba(34,211,238,0.8) !important;
        outline-offset: 3px;
        box-shadow: 0 0 16px rgba(34,211,238,0.3) !important;
    }
    .phish-link-badge {
        display: inline-block;
        font-size: 9px;
        font-family: monospace;
        font-weight: 700;
        background: linear-gradient(135deg, #dc2626, #b91c1c);
        color: white;
        padding: 3px 8px;
        border-radius: 3px;
        margin-left: 5px;
        vertical-align: middle;
        letter-spacing: 0.8px;
        text-transform: uppercase;
        box-shadow: 0 2px 6px rgba(220,38,38,0.3);
        animation: phish-link-pulse 2s ease-in-out infinite;
    }
    </style>
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


def _parse_gemini_for_tooltips(gemini_result: dict) -> dict:
    """Extract verdict, confidence, and model from a Gemini result for tooltip display."""
    info: dict = {}
    text = gemini_result.get("text", "")
    model = gemini_result.get("model", "")
    if model:
        info["model"] = model
    if not text:
        return info
    m = re.search(r"\*{0,2}VERDICT\*{0,2}[:\s]*\*{0,2}\s*(phishing|suspicious|legitimate)", text, re.I)
    if m:
        info["verdict"] = m.group(1).upper()
    m = re.search(r"\*{0,2}CONFIDENCE\*{0,2}[:\s]*\*{0,2}\s*(\d{1,3})%?", text, re.I)
    if m:
        info["confidence"] = m.group(1) + "%"
    m = re.search(r"\*{0,2}ATTACK TECHNIQUE\*{0,2}[:\s]*\*{0,2}\s*(.+?)(?:\n|$)", text, re.I)
    if m:
        technique = m.group(1).strip().rstrip("*").strip()
        if technique.lower() != "n/a":
            info["technique"] = technique[:80]
    return info


def get_highlight_popup_js(gemini_result: dict | None = None) -> str:
    """Return JS that sets up highlight popups with optional LLM references.

    Runs in the parent page context and accesses the iframe's contentDocument
    (allowed because the iframe uses ``allow-same-origin``).  When *gemini_result*
    is provided, each tooltip includes the LLM verdict, confidence, and model.
    """
    llm_info = _parse_gemini_for_tooltips(gemini_result) if gemini_result else {}

    # Build the LLM reference HTML snippet used in tooltips (CSS classes)
    if llm_info.get("verdict"):
        verdict = llm_info["verdict"]
        verdict_class = {"PHISHING": "popup-llm-verdict-red", "SUSPICIOUS": "popup-llm-verdict-amber", "LEGITIMATE": "popup-llm-verdict-green"}.get(verdict, "")
        confidence = llm_info.get("confidence", "")
        model = llm_info.get("model", "Gemini")
        technique = llm_info.get("technique", "")

        llm_line = (
            "'<div class=\"popup-llm\">"
            f"<div class=\"popup-llm-label\">LLM ASSESSMENT ({html.escape(model, quote=True)})</div>"
            "<div class=\"popup-detail\">Verdict: "
            f"<span class=\"popup-llm-verdict {verdict_class}\">{html.escape(verdict, quote=True)}</span>"
        )
        if confidence:
            llm_line += f" ({html.escape(confidence, quote=True)} confidence)"
        llm_line += "</div>"
        if technique:
            llm_line += (
                "<div class=\"popup-detail\">Technique: "
                f"<span class=\"popup-llm-technique\">{html.escape(technique, quote=True)}</span></div>"
            )
        llm_line += "</div>'"
    else:
        llm_line = "''"

    return (
        "(function(){\n"
        "    var iframe = document.querySelector('.body-section iframe');\n"
        "    if (!iframe) return;\n"
        f"    var llmRef = {llm_line};\n"
        "    function setup() {\n"
        "        var doc = iframe.contentDocument || iframe.contentWindow.document;\n"
        "        if (!doc || !doc.body) return;\n"
        "        var popup = document.createElement('div');\n"
        "        popup.id = 'phish-popup-el';\n"
        "        document.body.appendChild(popup);\n"
        "        var hideTimer = null;\n"
        "        function esc(s) { var d = document.createElement('div'); d.appendChild(document.createTextNode(s)); return d.innerHTML; }\n"
        "        function showPopup(rect, html) {\n"
        "            if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }\n"
        "            popup.innerHTML = html;\n"
        "            popup.style.display = 'block';\n"
        "            popup.style.opacity = '0';\n"
        "            popup.style.transform = 'translateY(4px)';\n"
        "            var iframeRect = iframe.getBoundingClientRect();\n"
        "            var scrollTop = 0;\n"
        "            try { scrollTop = doc.documentElement.scrollTop || doc.body.scrollTop || 0; } catch(e) {}\n"
        "            var x = iframeRect.left + rect.left;\n"
        "            var y = iframeRect.top + (rect.bottom - scrollTop) + 6;\n"
        "            if (x + 340 > window.innerWidth) x = window.innerWidth - 350;\n"
        "            if (x < 4) x = 4;\n"
        "            if (y + 200 > window.innerHeight) y = iframeRect.top + (rect.top - scrollTop) - popup.offsetHeight - 6;\n"
        "            popup.style.left = x + 'px';\n"
        "            popup.style.top = y + 'px';\n"
        "            requestAnimationFrame(function() {\n"
        "                popup.style.opacity = '1';\n"
        "                popup.style.transform = 'translateY(0)';\n"
        "            });\n"
        "        }\n"
        "        function hidePopup() {\n"
        "            popup.style.opacity = '0';\n"
        "            popup.style.transform = 'translateY(4px)';\n"
        "            hideTimer = setTimeout(function() { popup.style.display = 'none'; }, 150);\n"
        "        }\n"
        "        doc.querySelectorAll('.phish-hl-urgency').forEach(function(el) {\n"
        "            el.addEventListener('mouseenter', function() {\n"
        "                var label = el.getAttribute('data-threat') || el.getAttribute('title') || '';\n"
        "                showPopup(el.getBoundingClientRect(),\n"
        "                    '<div class=\"popup-type popup-type-urgency\">SOCIAL ENGINEERING</div>'\n"
        "                    + '<div class=\"popup-detail\">Pattern: <span class=\"popup-type-urgency\">' + esc(label) + '</span></div>'\n"
        "                    + '<div class=\"popup-sub\">Urgency/pressure language used in phishing</div>'\n"
        "                    + llmRef);\n"
        "            });\n"
        "            el.addEventListener('mouseleave', hidePopup);\n"
        "        });\n"
        "        doc.querySelectorAll('.phish-hl-link-warn').forEach(function(el) {\n"
        "            el.addEventListener('mouseenter', function() {\n"
        "                var flags = el.getAttribute('data-flags') || 'SUSPICIOUS';\n"
        "                var href = el.getAttribute('data-real-href') || el.getAttribute('href') || '';\n"
        "                showPopup(el.getBoundingClientRect(),\n"
        "                    '<div class=\"popup-type popup-type-link\">SUSPICIOUS LINK</div>'\n"
        "                    + '<div class=\"popup-detail\">Flags: <span class=\"popup-type-link\">' + esc(flags) + '</span></div>'\n"
        "                    + (href ? '<div class=\"popup-sub\" style=\"word-break:break-all;\">Destination: ' + esc(href.substring(0,120)) + '</div>' : '')\n"
        "                    + llmRef);\n"
        "            });\n"
        "            el.addEventListener('mouseleave', hidePopup);\n"
        "        });\n"
        # --- Highlight navigation toolbar ---
        "        var highlights = Array.from(doc.querySelectorAll('.phish-hl-urgency, .phish-hl-link-warn'));\n"
        "        if (highlights.length > 0) {\n"
        "            var bodyWidget = document.querySelector('.body-widget');\n"
        "            if (bodyWidget) {\n"
        "                var navBar = document.createElement('div');\n"
        "                navBar.className = 'hl-nav-bar';\n"
        "                navBar.innerHTML = '<span class=\"hl-nav-label\">HIGHLIGHTS</span>'\n"
        "                    + '<button class=\"hl-nav-btn\" data-dir=\"prev\">&lsaquo;</button>'\n"
        "                    + '<span class=\"hl-nav-counter\"><span class=\"hl-nav-current\">0</span> / ' + highlights.length + '</span>'\n"
        "                    + '<button class=\"hl-nav-btn\" data-dir=\"next\">&rsaquo;</button>';\n"
        "                bodyWidget.appendChild(navBar);\n"
        "                var curIdx = -1;\n"
        "                function goToHighlight(idx) {\n"
        "                    if (highlights.length === 0) return;\n"
        "                    if (curIdx >= 0 && curIdx < highlights.length) highlights[curIdx].classList.remove('phish-hl-active');\n"
        "                    curIdx = ((idx % highlights.length) + highlights.length) % highlights.length;\n"
        "                    var el = highlights[curIdx];\n"
        "                    el.classList.add('phish-hl-active');\n"
        "                    el.scrollIntoView({behavior:'smooth', block:'center'});\n"
        "                    navBar.querySelector('.hl-nav-current').textContent = (curIdx + 1);\n"
        # Auto-expand collapsed body
        "                    var bodySection = bodyWidget.querySelector('.body-section');\n"
        "                    if (bodySection && bodySection.classList.contains('collapsed-body')) {\n"
        "                        var toggleBtn = bodyWidget.querySelector('.body-toggle-btn');\n"
        "                        if (toggleBtn) toggleBtn.click();\n"
        "                    }\n"
        "                }\n"
        "                navBar.querySelector('[data-dir=\"next\"]').addEventListener('click', function() { goToHighlight(curIdx + 1); });\n"
        "                navBar.querySelector('[data-dir=\"prev\"]').addEventListener('click', function() { goToHighlight(curIdx - 1); });\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "    if (iframe.contentDocument && iframe.contentDocument.readyState === 'complete') {\n"
        "        setup();\n"
        "    } else {\n"
        "        iframe.addEventListener('load', setup);\n"
        "    }\n"
        "})();\n"
    )
