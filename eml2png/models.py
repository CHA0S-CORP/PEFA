"""Typed dataclasses for all analysis result types."""

from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Optional


@dataclass
class ParsedEmail:
    headers: dict = field(default_factory=dict)
    received: list = field(default_factory=list)
    auth: dict = field(default_factory=dict)
    dkim_signature: str = ""
    html_body: Optional[str] = None
    text_body: Optional[str] = None
    attachments: list = field(default_factory=list)
    raw_msg: Optional[EmailMessage] = None


@dataclass
class LinkFlag:
    label: str
    severity: str  # "critical" or "warning"


@dataclass
class AnalyzedLink:
    href: str
    display: str
    domain: str = ""
    flags: list = field(default_factory=list)  # list of (label, severity) tuples


@dataclass
class LinkAnalysis:
    links: list = field(default_factory=list)  # list of AnalyzedLink dicts
    findings: list = field(default_factory=list)


@dataclass
class SenderAnalysis:
    from_display: str = ""
    from_email: str = ""
    from_domain: str = ""
    return_path: str = ""
    rp_domain: str = ""
    reply_to: str = ""
    flags: list = field(default_factory=list)  # list of (label, severity) tuples
    findings: list = field(default_factory=list)


@dataclass
class UrgencyMatch:
    start: int
    end: int
    label: str
    text: str


@dataclass
class UrgencyAnalysis:
    matches: list = field(default_factory=list)
    positions: list = field(default_factory=list)
    unique_count: int = 0
    total_count: int = 0
    density: float = 0.0
    generic_greeting: bool = False
    counter: dict = field(default_factory=dict)


@dataclass
class AttachmentInfo:
    name: str = ""
    type: str = ""
    size: int = 0
    md5: str = ""
    sha256: str = ""
    ext: str = ""
    flags: list = field(default_factory=list)


@dataclass
class AttachmentAnalysis:
    attachments: list = field(default_factory=list)


@dataclass
class LanguageAnalysis:
    score: Optional[int] = None
    findings: list = field(default_factory=list)
    issues: int = 0
    note: str = ""


@dataclass
class ThreatScore:
    score: int = 0
    level: str = "CLEAN"
    factors: list = field(default_factory=list)  # list of (description, points) tuples
