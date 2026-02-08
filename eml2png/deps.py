"""Centralized optional dependency imports with graceful fallbacks."""

import sys

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

try:
    import requests as req_lib
except ImportError:
    req_lib = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    import whois as whois_lib
except ImportError:
    whois_lib = None


def require_playwright():
    """Exit with install instructions if Playwright is not available."""
    if sync_playwright is None:
        sys.exit("pip3 install playwright && playwright install chromium")
