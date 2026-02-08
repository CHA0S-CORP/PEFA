"""HTML sanitization for email body content — defense against stored XSS."""

import re

from .deps import nh3_lib

# Tags safe for email body rendering
ALLOWED_TAGS = {
    # Structure
    "div", "span", "p", "br", "hr", "blockquote", "pre", "code",
    "section", "article", "header", "footer", "main", "aside", "nav",
    # Headings
    "h1", "h2", "h3", "h4", "h5", "h6",
    # Text formatting
    "b", "i", "em", "strong", "u", "s", "strike", "del", "ins",
    "sub", "sup", "small", "big", "mark", "abbr", "cite", "q",
    "var", "kbd", "samp", "dfn", "tt", "wbr",
    # Lists
    "ul", "ol", "li", "dl", "dt", "dd",
    # Tables
    "table", "thead", "tbody", "tfoot", "tr", "td", "th",
    "caption", "col", "colgroup",
    # Links & images
    "a", "img",
    # Legacy formatting (common in emails)
    "font", "center",
    # Style (scoped inside iframe)
    "style",
}

# Attributes allowed per-tag (or "*" for all tags)
ALLOWED_ATTRIBUTES = {
    "*": {"class", "id", "style", "title", "dir", "lang", "align", "valign"},
    "a": {"href", "target", "name"},
    "img": {"src", "alt", "width", "height", "border"},
    "font": {"color", "size", "face"},
    "table": {"width", "height", "border", "cellpadding", "cellspacing",
              "bgcolor", "background"},
    "td": {"width", "height", "colspan", "rowspan", "bgcolor", "background"},
    "th": {"width", "height", "colspan", "rowspan", "bgcolor", "background"},
    "tr": {"bgcolor", "background"},
    "col": {"span", "width"},
    "colgroup": {"span", "width"},
    "ol": {"start", "type"},
    "li": {"value"},
    # Highlighting data attributes (used by highlight_body)
    "span": {"data-threat", "data-flags", "data-real-href"},
}

ALLOWED_URL_SCHEMES = {"http", "https", "mailto", "data"}

# Link rel attribute for safety
LINK_REL = "noopener noreferrer nofollow"


def sanitize_html(html_body: str) -> str:
    """Sanitize email body HTML, stripping dangerous elements.

    Uses nh3 if available, otherwise falls back to a conservative
    regex strip that removes all HTML tags.
    """
    if not html_body:
        return html_body

    if nh3_lib is not None:
        result = _sanitize_with_nh3(html_body)
    else:
        result = _fallback_strip(html_body)

    # Defense-in-depth: strip any <script> that survived (e.g. inside
    # preserved <style> blocks where the parser treats them as raw text).
    result = re.sub(
        r"<\s*script\b[^>]*>.*?</\s*script\s*>",
        "", result, flags=re.I | re.DOTALL,
    )
    result = re.sub(
        r"<\s*/?\s*script\b[^>]*/?\s*>",
        "", result, flags=re.I,
    )
    return result


def _sanitize_with_nh3(html_body: str) -> str:
    """Sanitize using the nh3 library."""
    return nh3_lib.clean(
        html_body,
        tags=ALLOWED_TAGS,
        clean_content_tags={"script"},
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes=ALLOWED_URL_SCHEMES,
        link_rel=LINK_REL,
    )


def _fallback_strip(html_body: str) -> str:
    """Fallback: strip all tags except basic safe ones via regex.

    This is intentionally conservative — better to lose formatting
    than to allow XSS.
    """
    # Remove script/style/iframe blocks entirely (content and tags)
    html_body = re.sub(
        r"<\s*(script|iframe|object|embed|form|svg|math|canvas|base|meta)\b[^>]*>.*?</\s*\1\s*>",
        "", html_body, flags=re.I | re.DOTALL,
    )
    # Remove self-closing dangerous tags
    html_body = re.sub(
        r"<\s*/?\s*(script|iframe|object|embed|form|input|svg|math|canvas|base|meta)\b[^>]*/?\s*>",
        "", html_body, flags=re.I,
    )
    # Remove event handlers from remaining tags
    html_body = re.sub(r"\bon\w+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", "", html_body, flags=re.I)
    # Remove javascript: URLs
    html_body = re.sub(r"href\s*=\s*[\"']?\s*javascript:", 'href="', html_body, flags=re.I)
    html_body = re.sub(r"src\s*=\s*[\"']?\s*javascript:", 'src="', html_body, flags=re.I)
    return html_body
