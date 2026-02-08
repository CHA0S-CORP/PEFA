"""Rendering subsystem — widgets, IOC helpers, and page assembly."""

from .page import PageRenderer
from .ioc import (
    vt_url_link, vt_domain_link, vt_ip_link,
    urlscan_domain_link, urlscan_url_link,
    ioc_url_html, ioc_email_html, ioc_ip_html,
)

__all__ = [
    "PageRenderer",
    "vt_url_link", "vt_domain_link", "vt_ip_link",
    "urlscan_domain_link", "urlscan_url_link",
    "ioc_url_html", "ioc_email_html", "ioc_ip_html",
]
