"""Widget classes for rendering analysis sections."""

from .threat_gauge import ThreatGaugeWidget
from .auth import AuthWidget
from .links import LinkAnalysisWidget
from .sender import SenderWidget
from .urgency import UrgencyWidget
from .attachments import AttachmentWidget
from .language import LanguageWidget
from .domain_age import DomainAgeWidget
from .urlscan import URLScanWidget
from .gemini import GeminiWidget
from .ip_intel import IPIntelWidget
from .hop_trace import HopTraceWidget
from .ioc_lookup import IOCLookupWidget

__all__ = [
    "ThreatGaugeWidget",
    "AuthWidget",
    "LinkAnalysisWidget",
    "SenderWidget",
    "UrgencyWidget",
    "AttachmentWidget",
    "LanguageWidget",
    "DomainAgeWidget",
    "URLScanWidget",
    "GeminiWidget",
    "IPIntelWidget",
    "HopTraceWidget",
    "IOCLookupWidget",
]
