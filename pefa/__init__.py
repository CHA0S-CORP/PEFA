"""pefa — Phishing Email Forensic Analyzer."""

__version__ = "1.0.0"

from .parser import parse_eml
from .pipeline import run_analysis, eml_to_png
from .cli import main

__all__ = ["parse_eml", "run_analysis", "eml_to_png", "main", "__version__"]
