"""Urgency and social engineering language scanning."""

import re
from collections import Counter

from ..constants import URGENCY_PATTERNS, GENERIC_GREETINGS
from ..parser import extract_plain_text
from .base import BaseAnalyzer


NEGATION_TOKENS = {"not", "no", "don't", "dont", "never", "can't", "cant",
                    "won't", "wont", "isn't", "isnt", "wasn't", "wasnt",
                    "shouldn't", "shouldnt", "wouldn't", "wouldnt",
                    "didn't", "didnt", "doesn't", "doesnt", "neither", "nor"}

# Patterns that use negation as a pressure tactic — do NOT filter these out
NEGATION_EXEMPT_LABELS = {"do not ignore"}


class UrgencyAnalyzer(BaseAnalyzer):
    @staticmethod
    def _is_negated(text: str, match_start: int) -> bool:
        """Check if the 5 words preceding match_start contain a negation token."""
        preceding = text[:match_start].split()[-5:]
        return any(w.strip(".,;:!?") in NEGATION_TOKENS for w in preceding)

    def analyze(self, parsed: dict) -> dict:
        text = (extract_plain_text(parsed) or "").lower()
        matches = []
        positions = []

        for pattern, label in URGENCY_PATTERNS:
            for m in re.finditer(pattern, text, re.I):
                if label not in NEGATION_EXEMPT_LABELS and self._is_negated(text, m.start()):
                    continue
                matches.append(label)
                positions.append({"start": m.start(), "end": m.end(), "label": label, "text": m.group()})

        generic_greeting = False
        for pattern in GENERIC_GREETINGS:
            if re.search(pattern, text, re.I):
                generic_greeting = True
                break

        density = len(matches) / max(len(text.split()), 1) * 100

        return {
            "matches": matches,
            "positions": positions,
            "unique_count": len(set(matches)),
            "total_count": len(matches),
            "density": round(density, 2),
            "generic_greeting": generic_greeting,
            "counter": dict(Counter(matches)),
        }
