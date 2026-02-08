# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**eml2png** (being renamed to **pefa**) — a Python CLI tool that converts `.eml` files into cyber-infographic PNGs and interactive HTML reports. It performs forensic analysis of phishing indicators including link analysis, sender spoofing detection, urgency language scanning, attachment threat assessment, authentication checks, delivery path tracing, domain age lookup, IOC enrichment, and an overall phishing threat score (0–100).

**Note on naming**: The package directory is `eml2png/` but `pyproject.toml` and internal module references (entry point, template loader) use `pefa`. The `python3 -m eml2png` invocation works because the directory is named `eml2png`; the installed entry point `pefa` comes from `pyproject.toml`.

## Setup

```bash
pip3 install -e .                    # installs all deps from pyproject.toml
playwright install chromium
```

Dependencies: `beautifulsoup4`, `requests`, `python-whois`, `playwright`, `legacy-cgi`, `nh3`.

## Usage

```bash
python3 -m eml2png input.eml                          # PNG output
python3 -m eml2png input.eml --html                    # also emit interactive HTML
python3 -m eml2png input.eml --gemini                  # include Gemini AI assessment
python3 -m eml2png input.eml --gemini-model gemini-2.5-pro
python3 -m eml2png input.eml --no-api                  # skip all API calls
python3 -m eml2png ./emails/ -o ./reports/             # batch mode
python3 -m eml2png input.eml --width 1100 --scale 2   # custom viewport
python3 -m eml2png --web                               # browser-based web UI (no Playwright needed)
python3 -m eml2png --web --port 9090                   # web UI on custom port
```

## Optional API Keys (env vars)

- `GEMINI_API_KEY` — Google Gemini AI assessment
- `URLSCAN_API_KEY` — urlscan.io intelligence
- `MXTOOLBOX_API_KEY` — SPF/DKIM/DMARC validation
- `VIRUSTOTAL_API_KEY` — VirusTotal IOC enrichment
- `ABUSEIPDB_API_KEY` — AbuseIPDB IP reputation

## Architecture

The tool is organized as the `eml2png/` package with five subsystems:

### Data Flow

```
.eml file → parser.py → pipeline.run_analysis() → PageRenderer.build() → Playwright → .png
```

`pipeline.py` is the orchestrator. It calls all analyzers, API clients, IOC consolidation, scoring, and highlighting, then hands the result dict to `PageRenderer` which assembles HTML from widgets + CSS/JS templates, and Playwright screenshots it to PNG.

### Analyzers (`analyzers/`)

All extend `BaseAnalyzer` (ABC) with a single `analyze(parsed: dict) -> dict` method. Five implementations: `LinkAnalyzer`, `SenderAnalyzer`, `UrgencyAnalyzer`, `AttachmentAnalyzer`, `LanguageAnalyzer`. `ioc_consolidator.py` is a standalone module (not a BaseAnalyzer subclass) that consolidates IOCs from all analysis results and enriches them via threat intel APIs. Each analyzer returns a plain dict (not dataclasses) for backwards compatibility with the rendering layer.

### API Clients (`api/`)

Seven extend `BaseAPIClient` (ABC) which provides static `_get()`/`_post()` HTTP helpers: `IPLookupClient`, `URLScanClient`, `MXToolboxClient`, `GeminiClient`, `VirusTotalClient`, `AbuseIPDBClient`, `AlienVaultClient`. `WhoisClient` is standalone (uses `python-whois` library, not `requests`). All clients check for their dependency/API key and return `{"error": ...}` on failure.

### Renderers (`renderers/`)

Widget classes extend `Widget` (ABC) with `nav_id`/`nav_label`/`nav_group` attributes and `render(analysis, parsed) -> str`. `PageRenderer` owns the widget list, loads CSS/JS via `importlib.resources` from `templates/`, and assembles the full HTML page. Interactive mode adds collapse/expand, gauge animations, copy-to-clipboard, tooltips, and section navigation.

### Web UI (`web.py`)

A standalone HTTP server (`--web` flag) that serves a drag-and-drop upload page, runs the analysis pipeline, and returns the interactive HTML report — no Playwright required. Uses stdlib `http.server`.

### Key Modules

- **`deps.py`** — Centralized `try/except` imports for optional dependencies (`requests`, `beautifulsoup4`, `python-whois`, `nh3`). All other modules import from here.
- **`constants.py`** — Suspicious TLDs, URL shorteners, dangerous extensions, urgency regex patterns, homoglyph map, known brand names, private IP regex.
- **`scoring.py`** — Weighted composite threat score: auth (max 20) + sender (max 20) + links (max 25) + urgency (max 15) + attachments (max 10) + language (max 5) + domain age (max 10). Gemini can bump +25/+50.
- **`sanitize.py`** — HTML sanitization for email body content. Uses `nh3` if available, falls back to conservative regex stripping. Defense against stored XSS.
- **`highlighting.py`** — Injects CSS/JS into the email HTML body to highlight urgency keywords and flag suspicious links with interactive popups.
- **`utils.py`** — Brand impersonation detection, homoglyph checking, timezone conversion, hostname resolution.
- **`templates/`** — CSS and JS extracted as real files, loaded via `importlib.resources`. `base.css` has core dark theme; `interactive.css` adds nav/tooltips/responsive; `interactive.js` handles widget interactivity; `navigation.js` handles scroll-spy. **Important**: the template loader in `templates/__init__.py` references `pefa.templates` as the package path.

### Design Decisions

- All optional dependencies guarded in `deps.py` with graceful fallbacks (e.g., BeautifulSoup → regex fallback for HTML parsing, nh3 → regex strip for sanitization).
- Playwright is the only hard dependency beyond stdlib (not needed for `--web` mode).
- API calls controlled by `--no-api` flag; each integration checks its own env var.
- `parse_eml()`, `calculate_threat_score()`, `highlight_body()` are free functions (stateless, no polymorphism benefit).
- Batch mode reuses a single Playwright browser instance via `playwright_ctx` parameter.
- `models.py` defines typed dataclasses but the pipeline currently uses plain dicts for widget compatibility.
