"""All constant sets, lists, dicts, and regex patterns."""

import re

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc",
    ".click", ".link", ".site", ".online", ".icu", ".buzz", ".fun",
    ".monster", ".rest", ".cam", ".surf", ".best", ".cyou", ".cfd",
    ".stream", ".download", ".win", ".loan", ".racing", ".review",
    ".date", ".trade", ".bid", ".life", ".store", ".tech", ".space",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "bl.ink", "short.io", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "lnkd.in", "qr.ae",
    "t.ly", "v.gd", "s.id", "dub.sh", "surl.li",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd",
    ".ps1", ".msi", ".dll", ".com", ".pif", ".wsf", ".wsh", ".cpl",
    ".iso", ".img", ".vhd", ".vhdx",
    ".html", ".htm", ".hta", ".svg",
    ".lnk", ".url", ".reg",
    ".app", ".dmg", ".pkg", ".deb", ".rpm", ".sh", ".command", ".apk",
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}

URGENCY_PATTERNS = [
    (r"\bimmediate(?:ly)?\s+action\b", "immediate action"),
    (r"\burgent(?:ly)?\b", "urgent"),
    (r"\bexpir(?:es?|ing|ed|ation)\b", "expiration"),
    (r"\bsuspend(?:ed)?\b", "suspended"),
    (r"\bverif(?:y|ication)\b", "verify"),
    (r"\bconfirm\s+(?:your|identity|account)\b", "confirm identity"),
    (r"\bunauthori[sz]ed\b", "unauthorized"),
    (r"\bsecurity\s+alert\b", "security alert"),
    (r"\bwithin\s+\d+\s*(?:hour|day|minute)\b", "time pressure"),
    (r"\byour\s+account\s+(?:has been|will be|is)\b", "account threat"),
    (r"\bclick\s+here\b", "click here"),
    (r"\bact\s+now\b", "act now"),
    (r"\blimited\s+time\b", "limited time"),
    (r"\bfailure\s+to\b", "failure to"),
    (r"\bfinal\s+(?:notice|warning|reminder)\b", "final notice"),
    (r"\block(?:ed)?\s+out\b", "locked out"),
    (r"\bdeactivat(?:e|ed|ion)\b", "deactivation"),
    (r"\bunusual\s+(?:activity|sign.?in|login)\b", "unusual activity"),
    (r"\brestr(?:ict|ained)\b", "restricted"),
    (r"\bpenalt(?:y|ies)\b", "penalty"),
    (r"\blegal\s+action\b", "legal action"),
    (r"\bdo\s+not\s+ignore\b", "do not ignore"),
    (r"\brequired\s+(?:action|update|verification)\b", "required action"),
    (r"\bwe\s+(?:noticed|detected)\b", "we detected"),
    (r"\bsomeone\s+(?:tried|attempted)\b", "someone attempted"),
]

GENERIC_GREETINGS = [
    r"\bdear\s+(?:customer|user|client|member|sir|madam|valued|account\s+holder|friend|recipient|subscriber)\b",
    r"\bhello\s+(?:customer|user|client|member|there)\b",
    r"\bto\s+whom\s+it\s+may\s+concern\b",
    r"\bdear\s+(?:sir|madam)\b",
    r"\bhi\s+there\b",
    r"\bgreetings\b",
]

HOMOGLYPH_MAP = {
    "a": ["а", "ɑ", "α"],
    "c": ["с", "ϲ"],
    "d": ["ԁ", "ɗ"],
    "e": ["е", "ε", "ё"],
    "g": ["ɡ"],
    "h": ["һ"],
    "i": ["і", "ι", "1", "l"],
    "j": ["ј"],
    "k": ["κ"],
    "l": ["1", "i", "ⅼ", "ⅰ"],
    "m": ["rn", "ⅿ"],
    "n": ["ո"],
    "o": ["о", "ο", "0"],
    "p": ["р", "ρ"],
    "q": ["ԛ"],
    "s": ["ѕ", "ꜱ"],
    "t": ["τ"],
    "u": ["υ", "ս"],
    "v": ["ν", "ⅴ"],
    "w": ["ω", "vv", "ⅳ"],
    "x": ["х", "χ"],
    "y": ["у", "γ"],
    "z": ["ᴢ"],
}

KNOWN_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix", "facebook",
    "instagram", "linkedin", "twitter", "chase", "wellsfargo", "bankofamerica",
    "citibank", "usps", "fedex", "ups", "dhl", "irs", "costco", "walmart",
    "target", "bestbuy", "ebay", "dropbox", "icloud", "outlook", "yahoo",
    "docusign", "adobe", "zoom", "slack", "stripe", "shopify", "coinbase",
    "github", "aws", "azure", "salesforce", "okta", "atlassian",
    "whatsapp", "telegram", "venmo", "cashapp", "binance", "metamask",
]

PRIVATE_IP_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fe80|fc00|fd00)"
)
