# PEFA — Phishing Email Forensic Analyzer

A Python CLI tool that converts `.eml` files into cyber-infographic PNGs and interactive HTML reports. PEFA performs automated forensic analysis of phishing indicators and produces a composite threat score (0–100) backed by multiple detection engines and optional threat intelligence APIs.

## Features

- **Threat Scoring** — Weighted 0–100 composite score across 7 categories with 5 severity levels (Clean / Low / Medium / High / Critical)
- **Link Analysis** — HREF mismatches, brand lookalikes, homoglyph domains, IP-based URLs, URL shorteners, suspicious TLDs, JavaScript/data URIs
- **Sender Spoofing Detection** — Display name spoofing, Return-Path/Reply-To mismatches, domain impersonation, homoglyph characters
- **Urgency Language Scanning** — 24 social-engineering pressure patterns, generic greeting detection, keyword density scoring
- **Attachment Threat Assessment** — 40+ dangerous extensions, macro-enabled documents, double extensions, MIME mismatches, file hashing (MD5/SHA256)
- **Authentication Checks** — SPF, DKIM, and DMARC validation from headers (with optional MXToolbox deep validation)
- **Delivery Path Tracing** — Full email hop trace with IP geolocation per relay
- **Domain Age Lookup** — WHOIS-based registration date and age risk assessment
- **Language Quality Analysis** — Mixed-script detection, entropy analysis, zero-width characters, irregular spacing
- **IOC Extraction** — Consolidated Indicators of Compromise (IPs, domains, URLs, emails, hashes) with optional enrichment
- **AI Assessment** — Optional Google Gemini analysis with verdict, confidence score, attack classification, and recommended actions
- **Interactive HTML Reports** — Collapsible sections, scroll-spy navigation, copy-to-clipboard, animated threat gauge, tooltips
- **Batch Processing** — Analyze entire directories of `.eml` files with a single command
- **Web UI** — Browser-based upload interface with live analysis (no Playwright needed client-side)

## Installation

```bash
pip install playwright requests python-whois beautifulsoup4 nh3 legacy-cgi
playwright install chromium
```

Or install from the project directly:

```bash
pip install .
playwright install chromium
```

Requires Python 3.10+.

## Quick Start

```bash
# Analyze a single email → PNG infographic
pefa input.eml

# Also generate an interactive HTML report
pefa input.eml --html

# Include Gemini AI assessment
pefa input.eml --gemini

# Skip all external API calls (fully offline)
pefa input.eml --no-api

# Batch process a directory
pefa ./emails/ -o ./reports/

# Launch the web UI
pefa --web --port 8080
```

Or run as a module:

```bash
python3 -m pefa input.eml
```

## CLI Reference

```
usage: pefa [-h] [--web] [--port PORT] [-o OUTPUT] [--width WIDTH]
            [--scale SCALE] [--html] [--gemini]
            [--gemini-model MODEL] [--no-api]
            [input]

positional arguments:
  input                 .eml file or directory of .eml files

options:
  -o, --output          Output path for generated reports
  --web                 Start browser-based web UI
  --port                Web server port (default: 8080)
  --width               Viewport width in pixels (default: 1000)
  --scale               Device scale factor (default: 1.5)
  --html                Emit interactive HTML report alongside PNG
  --gemini              Include Gemini AI assessment
  --gemini-model        Gemini model to use (default: gemini-2.5-flash)
  --no-api              Skip all external API lookups
```

## Threat Scoring

PEFA calculates a composite threat score from 0 to 100 using weighted categories:

| Category | Max Points | What It Measures |
|---|---|---|
| Authentication | 20 | SPF, DKIM, DMARC failures |
| Sender | 20 | Spoofing, homoglyphs, header mismatches |
| Links | 25 | HREF mismatches, brand lookalikes, IP URLs, shorteners |
| Urgency | 15 | Pressure language patterns, generic greetings |
| Attachments | 10 | Dangerous extensions, macros, double extensions |
| Language | 5 | Mixed scripts, entropy anomalies, quality issues |
| Domain Age | 10 | Newly registered or young domains |

Passing all authentication checks and having an established domain (3+ years) applies negative scoring. Gemini AI verdicts can add up to +50 additional points.

**Threat Levels:**

| Level | Score |
|---|---|
| Critical | 70–100 |
| High | 45–69 |
| Medium | 25–44 |
| Low | 10–24 |
| Clean | 0–9 |

## API Integrations

All API integrations are optional. PEFA works fully offline with `--no-api`. Each integration checks for its own environment variable and silently skips if unavailable.

| Service | Environment Variable | Purpose |
|---|---|---|
| Google Gemini | `GEMINI_API_KEY` | AI-powered phishing assessment |
| urlscan.io | `URLSCAN_API_KEY` | Domain reputation intelligence |
| MXToolbox | `MXTOOLBOX_API_KEY` | SPF/DKIM/DMARC deep validation |
| VirusTotal | `VIRUSTOTAL_API_KEY` | IOC reputation lookups |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP abuse reports |
| AlienVault OTX | `ALIENVAULT_API_KEY` | Threat intelligence enrichment |
| ip-api.com | *(none — free tier)* | IP geolocation |
| WHOIS | *(none — uses python-whois)* | Domain age lookup |

```bash
export GEMINI_API_KEY="your-key-here"
export URLSCAN_API_KEY="your-key-here"
```

## Architecture

```
.eml file → parser.py → pipeline.run_analysis() → PageRenderer.build() → Playwright → .png/.html
```

```
pefa/
├── cli.py                  # CLI argument parsing and entry point
├── parser.py               # .eml parsing and header extraction
├── pipeline.py             # Analysis orchestrator
├── scoring.py              # Weighted threat score calculation
├── highlighting.py         # Email body highlighting (urgency keywords, suspicious links)
├── constants.py            # TLDs, shorteners, extensions, regex patterns, homoglyphs
├── deps.py                 # Centralized optional dependency imports
├── analyzers/
│   ├── links.py            # LinkAnalyzer — URL and domain analysis
│   ├── sender.py           # SenderAnalyzer — spoofing and impersonation
│   ├── urgency.py          # UrgencyAnalyzer — pressure language patterns
│   ├── attachments.py      # AttachmentAnalyzer — file threat assessment
│   ├── language.py         # LanguageAnalyzer — text quality and encoding
│   └── ioc_consolidator.py # IOC extraction and enrichment
├── api/
│   ├── ip_lookup.py        # IP geolocation (ip-api.com)
│   ├── gemini.py           # Google Gemini AI assessment
│   ├── urlscan.py          # urlscan.io domain reputation
│   ├── mxtoolbox.py        # SPF/DKIM/DMARC validation
│   ├── whois_client.py     # Domain WHOIS lookup
│   ├── virustotal.py       # VirusTotal IOC lookup
│   ├── abuseipdb.py        # AbuseIPDB IP reputation
│   └── alienvault.py       # AlienVault OTX intelligence
├── renderers/
│   ├── page.py             # Full HTML page assembly
│   └── widgets/            # 13 analysis section widgets
└── templates/
    ├── css/                # Dark theme, interactive styling
    └── js/                 # Section navigation, animations, interactivity
```

## Output

**PNG mode** (default) produces a single infographic image containing all analysis sections: threat gauge, sender analysis, authentication status, link flags, urgency patterns, attachments, domain age, delivery path, IP geolocation, and the rendered email body in a sandboxed frame.

**HTML mode** (`--html`) additionally produces an interactive report with collapsible sections, scroll-spy navigation, animated gauges, copy-to-clipboard for IOCs, and download/print buttons.

**Web UI** (`--web`) serves a browser-based interface for uploading `.eml` files and viewing analysis results interactively without needing Playwright installed on the client.

## Sample Emails

The `samples/` directory contains 15 example phishing emails (419 scams, social engineering, impersonation) for testing:

```bash
pefa samples/
```

## License

See [pyproject.toml](pyproject.toml) for package metadata.
