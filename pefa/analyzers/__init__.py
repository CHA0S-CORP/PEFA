"""Analysis modules for phishing detection."""

from .base import BaseAnalyzer
from .links import LinkAnalyzer
from .sender import SenderAnalyzer
from .urgency import UrgencyAnalyzer
from .attachments import AttachmentAnalyzer
from .language import LanguageAnalyzer

__all__ = [
    "BaseAnalyzer",
    "LinkAnalyzer",
    "SenderAnalyzer",
    "UrgencyAnalyzer",
    "AttachmentAnalyzer",
    "LanguageAnalyzer",
]
