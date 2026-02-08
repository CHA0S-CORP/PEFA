# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**eml2png** — a Python CLI tool that converts `.eml` files into cyber-infographic PNGs and interactive HTML reports. It performs forensic analysis of phishing indicators including link analysis, sender spoofing detection, urgency language scanning, attachment threat assessment, authentication checks, delivery path tracing, domain age lookup, and an overall phishing threat score (0–100).

## Setup

```bash
pip3 install playwright requests python-whois beautifulsoup4
playwright install chromium
```

## Usage

```bash
python3 -m eml2png input.eml                          # PNG output
python3 -m eml2png input.eml --html                    # also emit interactive HTML
python3 -m eml2png input.eml --gemini                  # include Gemini AI assessment
python3 -m eml2png input.eml --gemini-model gemini-2.5-pro
python3 -m eml2png input.eml --no-api                  # skip all API calls
python3 -m eml2png ./emails/ -o ./reports/             # batch mode
python3 -m eml2png input.eml --width 1100 --scale 2   # custom viewport
```

## Optional API Keys (env vars)

- `GEMINI_API_KEY` — Google Gemini AI assessment
- `URLSCAN_API_KEY` — urlscan.io intelligence
- `MXTOOLBOX_API_KEY` — SPF/DKIM/DMARC validation

## Architecture

The tool is organized as the `eml2png/` package with four subsystems:

### Data Flow

```
.eml file → parser.py → pipeline.run_analysis() → PageRenderer.build() → Playwright → .png
```

`pipeline.py` is the orchestrator. It calls all analyzers, API clients, scoring, and highlighting, then hands the result dict to `PageRenderer` which assembles HTML from widgets + CSS/JS templates, and Playwright screenshots it to PNG.

### Analyzers (`analyzers/`)

All extend `BaseAnalyzer` (ABC) with a single `analyze(parsed: dict) -> dict` method. Five implementations: `LinkAnalyzer`, `SenderAnalyzer`, `UrgencyAnalyzer`, `AttachmentAnalyzer`, `LanguageAnalyzer`. Each returns a plain dict (not dataclasses) for backwards compatibility with the rendering layer.

### API Clients (`api/`)

Four extend `BaseAPIClient` (ABC) which provides static `_get()`/`_post()` HTTP helpers: `IPLookupClient`, `URLScanClient`, `MXToolboxClient`, `GeminiClient`. `WhoisClient` is standalone (uses `python-whois` library, not `requests`). All clients check for their dependency/API key and return `{"error": ...}` on failure.

### Renderers (`renderers/`)

12 widget classes extend `Widget` (ABC) with `nav_id`/`nav_label`/`nav_group` attributes and `render(analysis, parsed) -> str`. `PageRenderer` owns the widget list, loads CSS/JS via `importlib.resources` from `templates/`, and assembles the full HTML page. Interactive mode adds collapse/expand, gauge animations, copy-to-clipboard, tooltips, and section navigation.

### Key Modules

- **`deps.py`** — Centralized `try/except` imports for optional dependencies (`requests`, `beautifulsoup4`, `python-whois`). All other modules import from here.
- **`constants.py`** — Suspicious TLDs, URL shorteners, dangerous extensions, urgency regex patterns, homoglyph map, known brand names, private IP regex.
- **`scoring.py`** — Weighted composite threat score: auth (max 20) + sender (max 20) + links (max 25) + urgency (max 15) + attachments (max 10) + language (max 5) + domain age (max 10). Gemini can bump +25/+50.
- **`highlighting.py`** — Injects CSS/JS into the email HTML body to highlight urgency keywords and flag suspicious links with interactive popups.
- **`templates/`** — CSS and JS extracted as real files, loaded via `importlib.resources`. `base.css` has core dark theme; `interactive.css` adds nav/tooltips/responsive; `interactive.js` handles widget interactivity; `navigation.js` handles scroll-spy.

### Design Decisions

- All optional dependencies guarded in `deps.py` with graceful fallbacks (e.g., BeautifulSoup → regex fallback for HTML parsing).
- Playwright is the only hard dependency beyond stdlib.
- API calls controlled by `--no-api` flag; each integration checks its own env var.
- `parse_eml()`, `calculate_threat_score()`, `highlight_body()` are free functions (stateless, no polymorphism benefit).
- Batch mode reuses a single Playwright browser instance via `playwright_ctx` parameter.
- `models.py` defines typed dataclasses but the pipeline currently uses plain dicts for widget compatibility.
