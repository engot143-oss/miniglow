"""Guardrail checks (Layer 6).

Two jobs:
1. BLOCK text that looks like credentials, patient identifiers, SSNs or card numbers.
   Matched values are never echoed back or stored - only the category names.
2. FLAG task text that implies buying or sending something, so the task needs
   Eric's explicit approval before it can be started.

These are simple pattern checks. They reduce accidents; they are not a
guarantee. Eric stays the final authority.
"""

from __future__ import annotations

import re

BLOCK_PATTERNS = {
    "credential": [
        re.compile(r"(?i)\b(password|passwd|pwd|passphrase|api[_ -]?key|secret|token|bearer)\b\s*[:=]\s*\S+"),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        re.compile(r"\bya29\.[A-Za-z0-9_-]{20,}\b"),
    ],
    "ssn": [re.compile(r"\b\d{3}-\d{2}-\d{4}\b")],
    "patient_identifier": [
        re.compile(r"(?i)\b(mrn|medical record number|patient name|patient id|dob|date of birth)\b\s*[:#=]"),
    ],
}

CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,16}\b")

APPROVAL_PATTERNS = [
    re.compile(r"(?i)\b(buy|purchase|checkout|check out|place an order|pay for|pay the)\b"),
    re.compile(r"(?i)\bsend\b[^.\n]{0,30}\b(email|e-mail|message|text|dm|invite|reply)\b"),
    re.compile(r"(?i)\b(publish|post to|submit the form)\b"),
]


class GuardrailViolation(Exception):
    """Raised when text contains something that must not be stored."""

    def __init__(self, categories):
        self.categories = sorted(set(categories))
        super().__init__(
            "Blocked by guardrails (" + ", ".join(self.categories) + "). "
            "Remove the sensitive content and try again. The matched text was not saved."
        )


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def find_violations(text: str) -> list[str]:
    found = []
    for category, patterns in BLOCK_PATTERNS.items():
        if any(p.search(text) for p in patterns):
            found.append(category)
    for m in CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 16 and _luhn_ok(digits):
            found.append("card_number")
            break
    return found


def check_text(*texts: str) -> None:
    """Raise GuardrailViolation if any text contains blocked content."""
    cats: list[str] = []
    for t in texts:
        if t:
            cats.extend(find_violations(t))
    if cats:
        raise GuardrailViolation(cats)


def needs_approval(*texts: str) -> bool:
    """True if the text suggests buying/sending/publishing."""
    joined = "\n".join(t for t in texts if t)
    return any(p.search(joined) for p in APPROVAL_PATTERNS)
