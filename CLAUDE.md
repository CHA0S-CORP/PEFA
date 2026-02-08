# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**eml2png** — a single-file Python CLI tool (`convert.py`) that converts `.eml` files into cyber-infographic PNGs and interactive HTML reports. It performs forensic analysis of phishing indicators including link analysis, sender spoofing detection, urgency language scanning, attachment threat assessment, authentication checks, delivery path tracing, domain age lookup, and an overall phishing threat score (0–100).

## Setup

```bash
pip3 install playwright requests python-whois beautifulsoup4
playwright install chromium
```

## Usage

```bash
python3 convert.py input.eml                          # PNG output
python3 convert.py input.eml --html                    # also emit interactive HTML
python3 convert.py input.eml --gemini                  # include Gemini AI assessment
python3 convert.py input.eml --gemini-model gemini-2.5-pro
python3 convert.py input.eml --no-api                  # skip all API calls
python3 convert.py ./emails/ -o ./reports/             # batch mode
python3 convert.py input.eml --width 1100 --scale 2   # custom viewport
```

## Optional API Keys (env vars)

- `GEMINI_API_KEY` — Google Gemini AI assessment
- `URLSCAN_API_KEY` — urlscan.io intelligence
- `MXTOOLBOX_API_KEY` — SPF/DKIM/DMARC validation

## Architecture

The entire tool is in `convert.py` (~2180 lines), organized into these sections:

1. **Constants** (lines ~70–160): Suspicious TLDs, URL shorteners, dangerous extensions, urgency regex patterns, generic greetings, homoglyph mappings, known brand names for lookalike detection.

2. **Email Parsing** (`parse_eml`, ~167): Parses `.eml` via Python's `email` module. Extracts headers, auth results (SPF/DKIM/DMARC), HTML/text body, inline images (CID replacement), and attachments with hashes.

3. **Analysis Modules** (~250–600):
   - `analyze_links` — Extracts URLs from HTML, flags mismatches (display text vs href), URL shorteners, IP-based URLs, suspicious TLDs, brand lookalikes, punycode, javascript/data URIs.
   - `analyze_sender` — Detects display name spoofing, return-path mismatches, reply-to mismatches, domain impersonation.
   - `analyze_urgency` — Regex-based scan for social engineering language (28 patterns) and generic greetings.
   - `analyze_attachments` — Flags dangerous extensions, macro-enabled files, double extensions, archives.
   - `analyze_language` — Heuristic language quality scoring (mixed charsets, spacing, capitalization).
   - `calculate_threat_score` — Weighted composite score (0–100) from all analysis modules.

4. **API Integrations** (~607–915): IP geolocation (ip-api.com), urlscan.io search, MXToolbox SPF/DKIM/DMARC validation, Gemini AI phishing assessment, WHOIS domain age lookup, delivery path hop parsing.

5. **IOC Linking** (~920–995): Generates VirusTotal and urlscan.io lookup links for URLs, domains, IPs, and email addresses.

6. **Body Highlighting** (`highlight_body`, ~1001): Injects CSS/JS into the email HTML body to visually highlight urgency keywords and flag suspicious links with interactive popups.

7. **HTML Template** (~1150–1895): Widget-based infographic renderer. Each analysis section has a dedicated `*_html()` function that returns an HTML widget. `build_full_html()` assembles all widgets into a complete dark-themed page with CSS variables, gauge animations, and grid layout.

8. **Render Pipeline** (~1900–2120): `run_analysis()` orchestrates all analysis modules and API calls. `eml_to_png()` builds HTML and uses Playwright to screenshot it as PNG. Batch mode reuses a single browser instance.

9. **CLI** (`main`, ~2127): argparse-based entry point with single-file and directory batch modes.

## Key Design Patterns

- All optional dependencies (`requests`, `beautifulsoup4`, `python-whois`) are guarded by try/except imports with graceful fallbacks.
- Playwright is the only hard dependency beyond stdlib (used for HTML-to-PNG rendering).
- API calls are controlled by `--no-api` flag; each API integration checks for its own env var.
- Threat score is a weighted composite: auth (max 20) + sender (max 20) + links (max 25) + urgency (max 15) + attachments (max 10) + language (max 5) + domain age (max 10). Gemini can bump by +25 or +50.
- The HTML output uses CSS custom properties (`--bg`, `--accent`, etc.) for consistent theming.
