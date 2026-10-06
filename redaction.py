"""Detect and mask personal secrets before they reach the model or the database.

The spec requires OTPs, PINs, NIKs, and card numbers to be redacted before
processing. This is the single implementation both the LLM middleware and the
tool handlers use, so "what the model saw" and "what was stored" cannot drift
apart.

Masking is keyword-anchored: a bare number is only masked when it sits next to
a word that makes it a secret (``otp``, ``pin``, ``kode verifikasi``...). That
keeps amounts and account numbers — the evidence a scam check is made of —
readable, while a real OTP pasted by the user never leaves the machine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CARD_RE = re.compile(r"(?<!\d)(?:\d{4}[\s-]){3}\d{4}(?!\d)")
_NIK_RE = re.compile(r"(?<!\d)\d{16}(?!\d)")

_OTP_ANCHOR = r"\b(?:otp|kode\s+otp|kode\s+verifikasi|kode\s+rahasia|kode\s+sms)\b"
_PIN_ANCHOR = r"\bpin\b"

_OTP_RE = re.compile(_OTP_ANCHOR + r"[^\d\n]{0,40}?(?<!\d)(?P<digits>\d{4,8})(?!\d)", re.IGNORECASE)
_PIN_RE = re.compile(_PIN_ANCHOR + r"[^\d\n]{0,40}?(?<!\d)(?P<digits>\d{4,8})(?!\d)", re.IGNORECASE)

MARKER_CARD = "[REDACTED_CARD]"
MARKER_NIK = "[REDACTED_NIK]"
MARKER_OTP = "[REDACTED_OTP]"
MARKER_PIN = "[REDACTED_PIN]"


@dataclass
class RedactionResult:
    text: str
    findings: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.findings)


def redact_text(text: str) -> RedactionResult:
    """Mask secrets in ``text``. Idempotent; safe on empty input."""
    result = RedactionResult(text=text or "")
    if not result.text:
        return result

    for pattern, marker, kind in (
        (_CARD_RE, MARKER_CARD, "card"),
        (_NIK_RE, MARKER_NIK, "nik"),
    ):
        result.text, count = _replace(pattern, result.text, marker)
        result.findings.extend([kind] * count)

    for pattern, marker, kind in (
        (_OTP_RE, MARKER_OTP, "otp"),
        (_PIN_RE, MARKER_PIN, "pin"),
    ):
        result.text, count = _replace_anchored(pattern, result.text, marker)
        result.findings.extend([kind] * count)

    return result


def redact(text: str) -> str:
    """Convenience wrapper returning only the masked text."""
    return redact_text(text).text


def _replace(pattern: re.Pattern[str], text: str, marker: str) -> tuple[str, int]:
    count = 0

    def repl(_match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return marker

    return pattern.sub(repl, text), count


def _replace_anchored(pattern: re.Pattern[str], text: str, marker: str) -> tuple[str, int]:
    count = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return match.group(0).replace(match.group("digits"), marker)

    return pattern.sub(repl, text), count
