"""Template loading utilities for CSS and JS assets."""

import importlib.resources


def _read_asset(subdir: str, filename: str) -> str:
    """Read a text asset from the templates directory."""
    ref = importlib.resources.files("pefa.templates") / subdir / filename
    return ref.read_text(encoding="utf-8")


def load_css(filename: str) -> str:
    return _read_asset("css", filename)


def load_js(filename: str) -> str:
    return _read_asset("js", filename)
