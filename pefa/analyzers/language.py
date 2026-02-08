"""Language quality analysis."""

import math
import re
from collections import Counter

from ..parser import extract_plain_text
from .base import BaseAnalyzer

ZERO_WIDTH_CHARS = set("\u200b\u200c\u200d\u200e\u200f"
                       "\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u202f"
                       "\ufeff")


class LanguageAnalyzer(BaseAnalyzer):
    def analyze(self, parsed: dict) -> dict:
        text = extract_plain_text(parsed)
        if not text or len(text) < 50:
            return {"score": None, "findings": [], "note": "insufficient text"}

        findings = []
        issues = 0
        total_sentences = len(re.split(r'[.!?]+', text))

        if re.search(r'[\u0400-\u04FF]', text) and re.search(r'[a-zA-Z]', text):
            findings.append("Mixed Cyrillic and Latin characters detected")
            issues += 3

        if re.search(r'[a-zA-Z]  +[a-zA-Z]', text):
            cnt = len(re.findall(r'[a-zA-Z]  +[a-zA-Z]', text))
            if cnt > 2:
                findings.append(f"Irregular spacing ({cnt} instances)")
                issues += 1

        article_omissions = len(re.findall(r'\b(?:please|kindly)\s+(?:click|verify|confirm|update|provide)\b', text, re.I))
        if article_omissions > 1:
            findings.append("Imperative phrasing without articles (possible non-native)")
            issues += 1

        words = text.split()
        caps_words = sum(1 for w in words if w.isupper() and len(w) > 2)
        if caps_words > 5:
            findings.append(f"Excessive capitalization ({caps_words} ALL-CAPS words)")
            issues += 1

        # Shannon entropy check
        if len(text) > 200:
            freq = Counter(text)
            length = len(text)
            entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
            if entropy > 5.5:
                findings.append(f"High character entropy ({entropy:.2f}) — possible encoded/obfuscated content")
                issues += 1
            elif entropy < 2.5:
                findings.append(f"Low character entropy ({entropy:.2f}) — highly repetitive content")
                issues += 1

        # Zero-width / hidden character detection
        zw_count = sum(1 for ch in text if ch in ZERO_WIDTH_CHARS)
        if zw_count > 0:
            findings.append(f"Hidden zero-width characters detected ({zw_count} instances)")
            issues += 2

        score = max(0, 100 - min(issues * 12, 60))

        return {"score": score, "findings": findings, "issues": issues}
