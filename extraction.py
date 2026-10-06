"""Deterministic entity extraction: URLs, phones, accounts, and text signals.

Everything the scoring engine consumes starts here. The rules are simple and
inspectable on purpose — when Scampi says "the domain is 5 days old", that
fact must have come from a regex this file can be tested against, not from a
model's impression.

Input is defanged first (``[.]``, ``hxxp``, `` dot ``), because the messages
users forward are exactly the ones written to defeat naive link scanners.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

from .domains import registrable_domain

#: Extensions that must never read as a TLD (``undangan.apk`` is a file).
FILE_EXT_IGNORED = frozenset(
    {
        "jpg", "jpeg", "png", "gif", "webp", "bmp", "svg",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "zip", "rar", "7z", "tar", "gz", "apk",
        "mp3", "mp4", "avi", "mov", "mkv", "csv", "txt",
    }
)

_SCHEME_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]]+", re.IGNORECASE)
_BARE_RE = re.compile(
    r"(?<![\w@.\-/])"
    r"([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?" r"(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)+)"
    r"(/[^\s<>\"'()\[\]]*)?",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?62|0)[\s.-]?8[1-9](?:[\s.-]?\d){6,11}(?!\d)")
_DIGIT_RUN_RE = re.compile(r"(?<!\d)\d(?:[\s.-]?\d){6,20}(?!\d)")
_APK_RE = re.compile(r"\.apk\b", re.IGNORECASE)
_TLD_RE = re.compile(r"[a-z]{2,24}")

#: Context words that make a bare digit run an account number candidate.
ACCOUNT_KEYWORDS = (
    "rekening", "no rek", "norek", "nomor rek", "transfer", "bayar",
    "pembayaran", "atas nama", "a.n", "a/n", "va ", "virtual account",
    "setor", "kirim ke", "menabung",
)

_DEFANG_PATTERNS = (
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\bhxxp", re.IGNORECASE), "http"),
    (re.compile(r"\s+dot\s+", re.IGNORECASE), "."),
)


@dataclass(frozen=True)
class Url:
    raw: str
    host: str
    registrable: str
    path: str = ""
    scheme: str = ""


@dataclass(frozen=True)
class Phone:
    raw: str
    normalized: str


@dataclass(frozen=True)
class Account:
    raw: str
    normalized: str
    bank: str = ""
    context: str = ""


@dataclass
class Extracted:
    text: str = ""
    urls: list[Url] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    phones: list[Phone] = field(default_factory=list)
    accounts: list[Account] = field(default_factory=list)
    pressure_markers: list[str] = field(default_factory=list)
    otp_matches: list[str] = field(default_factory=list)
    apk: bool = False


def defang(text: str) -> str:
    """Undo the common ways forwarded scam links are written to evade scanners."""
    out = text or ""
    for pattern, repl in _DEFANG_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def normalize(text: str) -> str:
    """Casefolded, whitespace-collapsed text for keyword matching."""
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def find_urls(text: str) -> list[Url]:
    urls, _spans = _find_urls_with_spans(text)
    return urls


def _find_urls_with_spans(text: str) -> tuple[list[Url], list[tuple[int, int]]]:
    text = defang(text)
    results: list[Url] = []
    spans: list[tuple[int, int]] = []

    for match in _SCHEME_RE.finditer(text):
        raw = _strip_trailing(match.group(0))
        host = _host_from_raw(raw)
        if not host:
            continue
        spans.append(match.span())
        results.append(_make_url(raw, host))

    for match in _BARE_RE.finditer(text):
        if _overlaps(match.span(), spans):
            continue
        raw = _strip_trailing(match.group(0))
        host = _host_from_raw(raw)
        if not _looks_like_domain(host):
            continue
        spans.append(match.span())
        results.append(_make_url(raw, host))

    seen = set()
    unique: list[Url] = []
    for url in results:
        key = (url.host, url.path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(url)
    return unique, spans


def find_phones(text: str) -> list[Phone]:
    phones: list[Phone] = []
    seen = set()
    for match in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if digits.startswith("62"):
            normalized = "+" + digits
        elif digits.startswith("0"):
            normalized = "+62" + digits[1:]
        else:
            continue
        if not 9 <= len(digits) <= 15:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        phones.append(Phone(raw=match.group(0).strip(), normalized=normalized))
    return phones


def find_accounts(
    text: str,
    blocked_spans: Sequence[tuple[int, int]],
    bank_lookup: Callable[[str], str] | None = None,
) -> list[Account]:
    """Digit runs (8-20 digits) that look like transfer targets, not noise.

    A run qualifies only when a bank/e-wallet name or an account keyword sits
    within ~70 characters of it. That is what keeps order numbers, dates, and
    amounts out.
    """
    if bank_lookup is None:
        from . import allowlist

        bank_lookup = allowlist.find_bank_in_text

    results: list[Account] = []
    seen = set()
    for match in _DIGIT_RUN_RE.finditer(text):
        if _overlaps(match.span(), blocked_spans):
            continue
        normalized = re.sub(r"\D", "", match.group(0))
        if not 8 <= len(normalized) <= 20:
            continue
        start, end = match.span()
        context = text[max(0, start - 70) : end + 70]
        context_lower = context.lower()
        bank = bank_lookup(context) or ""
        keyword_hit = any(keyword in context_lower for keyword in ACCOUNT_KEYWORDS)
        if not (bank or keyword_hit):
            continue
        key = (normalized, bank)
        if key in seen:
            continue
        seen.add(key)
        results.append(
            Account(raw=match.group(0).strip(), normalized=normalized, bank=bank, context=context.strip())
        )
    return results


def find_otp_request(
    normalized_text: str,
    keywords: Sequence[str],
    verbs: Sequence[str],
    negations: Sequence[str],
) -> list[str]:
    """Phrases where someone is being asked to hand over a secret.

    A verb inside a warning (``jangan bagikan``) must not count, so each verb
    hit is discarded when a negation sits immediately before it. Verbs inside
    other words (``dikirim`` containing ``kirim``) are ignored by boundary.
    """
    hits: list[str] = []
    for verb in verbs:
        pattern = re.compile(r"(?<![a-z])" + re.escape(verb) + r"(?![a-z])")
        for match in pattern.finditer(normalized_text):
            before = normalized_text[max(0, match.start() - 25) : match.start()]
            if any(negation in before for negation in negations):
                continue
            window = normalized_text[max(0, match.start() - 45) : match.end() + 45]
            for keyword in keywords:
                if keyword in window:
                    hits.append(f"{keyword} … {verb}")
                    break
    return list(dict.fromkeys(hits))


def analyze(
    text: str,
    rules: object | None = None,
    bank_lookup: Callable[[str], str] | None = None,
) -> Extracted:
    """Run the full offline extraction pass over one input text."""
    if rules is None:
        from . import rules as rules_mod

        rules = rules_mod.load()

    defanged = defang(text or "")
    normalized = normalize(defanged)

    urls, url_spans = _find_urls_with_spans(defanged)
    phones = find_phones(defanged)
    phone_spans = [match.span() for match in _PHONE_RE.finditer(defanged)]
    accounts = find_accounts(defanged, url_spans + phone_spans, bank_lookup=bank_lookup)

    pressure = [marker for marker in rules.pressure_markers if marker in normalized]
    otp_matches = find_otp_request(normalized, rules.otp_keywords, rules.request_verbs, rules.negations)

    apk = any(url.path.lower().endswith(".apk") for url in urls) or (
        bool(urls) and bool(_APK_RE.search(defanged))
    )

    domains: list[str] = []
    for url in urls:
        if url.registrable and url.registrable not in domains:
            domains.append(url.registrable)

    return Extracted(
        text=normalized,
        urls=urls,
        domains=domains,
        phones=phones,
        accounts=accounts,
        pressure_markers=pressure,
        otp_matches=otp_matches,
        apk=apk,
    )


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #

def _strip_trailing(raw: str) -> str:
    return raw.strip().rstrip(".,;:!?'\")]}>")


def _host_from_raw(raw: str) -> str:
    candidate = raw if "://" in raw else f"//{raw}"
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return ""
    host = (parts.netloc or "").split("@")[-1].strip().lower()
    if ":" in host:
        host = host.split(":")[0]
    return host.strip(".")


def _looks_like_domain(host: str) -> bool:
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if not _TLD_RE.fullmatch(tld):
        return False
    return tld not in FILE_EXT_IGNORED


def _make_url(raw: str, host: str) -> Url:
    candidate = raw if "://" in raw else f"//{raw}"
    parts = urlsplit(candidate)
    scheme = parts.scheme if "://" in raw else ""
    clean_host = host[4:] if host.startswith("www.") else host
    return Url(
        raw=raw,
        host=clean_host,
        registrable=registrable_domain(clean_host),
        path=parts.path or "",
        scheme=scheme,
    )


def _overlaps(span: tuple[int, int], spans: Sequence[tuple[int, int]]) -> bool:
    start, end = span
    return any(not (end <= other_start or start >= other_end) for other_start, other_end in spans)
