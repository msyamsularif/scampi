"""The official-domain allowlist and brand matching.

Principle 2 of the spec: a curated official-domain allowlist is the anchor.
This module knows which entities exist (banks, e-wallets, couriers,
marketplaces, government, utilities, messaging) and answers three questions
without any network access:

- which known entities does this text claim?
- is this domain one of the entity's official domains?
- does this domain merely resemble the entity — a brand token glued to a
  foreign domain, or an edit distance away from the official one?

A few aliases are common Indonesian words (``DANA``, the e-wallet). Those are
matched case-sensitively so a sentence about "dana darurat" never claims the
brand.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .domains import levenshtein, registrable_domain

logger = logging.getLogger(__name__)

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "data" / "allowlist.yaml"

#: Aliases that are ordinary Indonesian words; match them case-sensitively so
#: "dana darurat" or "si jago" never claims the brands.
WEAK_ALIASES = frozenset({"dana", "jago"})

_BANK_CATEGORIES = frozenset({"bank", "ewallet"})


@dataclass(frozen=True)
class Entry:
    entity: str
    category: str
    aliases: tuple[str, ...]
    domains: tuple[str, ...]


class Allowlist:
    def __init__(self, entries: Sequence[Entry]) -> None:
        self.entries: tuple[Entry, ...] = tuple(entries)
        index: list[tuple[str, Entry]] = []
        for entry in self.entries:
            for alias in entry.aliases:
                index.append((alias, entry))
        # Longest aliases first so "Bank BCA" wins over "BCA" for reporting.
        index.sort(key=lambda pair: len(pair[0]), reverse=True)
        self._alias_index = tuple(index)
        self._pattern_cache: dict[str, re.Pattern[str]] = {}

    # ------------------------------------------------------------------ #
    # Text -> claimed entities
    # ------------------------------------------------------------------ #

    def find_brands(self, text: str) -> list[Entry]:
        if not text:
            return []
        lowered = text.lower()
        found: list[Entry] = []
        for alias, entry in self._alias_index:
            if entry in found:
                continue
            if self._alias_matches(alias, lowered, text):
                found.append(entry)
        return found

    def _alias_matches(self, alias: str, lowered: str, original: str) -> bool:
        if alias.lower() in WEAK_ALIASES:
            pattern = self._pattern(alias, flags=0)
            return bool(pattern.search(original))
        pattern = self._pattern(alias, flags=re.IGNORECASE)
        return bool(pattern.search(lowered))

    def _pattern(self, alias: str, flags: int) -> re.Pattern[str]:
        key = f"{flags}:{alias}"
        pattern = self._pattern_cache.get(key)
        if pattern is None:
            body = re.escape(alias)
            pattern = re.compile(rf"(?<![a-z0-9]){body}(?![a-z0-9])", flags)
            self._pattern_cache[key] = pattern
        return pattern

    # ------------------------------------------------------------------ #
    # Domain -> official / resembling
    # ------------------------------------------------------------------ #

    def is_official(self, host: str, entry: Entry) -> bool:
        host = (host or "").lower().strip(".")
        return any(host == domain or host.endswith("." + domain) for domain in entry.domains)

    def brand_token_in_domain(self, host: str, entry: Entry) -> str:
        """Return the brand slug found inside the domain, or ``""``.

        Token-prefix match only (``bca-klik`` -> ``bca``, ``jne-resi`` ->
        ``jne``); a slug buried mid-token (``bakabca``) does not count, which
        keeps Indonesian words from tripping it.
        """
        tokens = [token for token in re.split(r"[^a-z0-9]+", (host or "").lower()) if token]
        for alias in entry.aliases:
            slug = re.sub(r"[^a-z0-9]", "", alias.lower())
            if len(slug) < 3:
                continue
            for token in tokens:
                if token == slug or token.startswith(slug) or token.endswith(slug):
                    return slug
        return ""

    def closest_official(self, host: str, entry: Entry, max_distance: int = 2) -> str:
        """Official domain within ``max_distance`` edits, or ``""``."""
        registrable = registrable_domain(host)
        best = ""
        best_distance = max_distance + 1
        for domain in entry.domains:
            distance = levenshtein(registrable, domain)
            if distance < best_distance:
                best = domain
                best_distance = distance
        return best if best_distance <= max_distance else ""


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

_cache: tuple[tuple[str, int, int], Allowlist] | None = None


def load(path: Path | None = None) -> Allowlist:
    resolved = Path(path) if path else DEFAULT_PATH
    try:
        stat = resolved.stat()
        stamp = (str(resolved), stat.st_mtime_ns, stat.st_size)
    except OSError:
        logger.warning("scampi: allowlist.yaml missing; brand checks disabled (%s)", resolved)
        return Allowlist([])

    global _cache
    if _cache is not None and _cache[0] == stamp:
        return _cache[1]

    entries = _read_entries(resolved)
    allowlist = Allowlist(entries)
    _cache = (stamp, allowlist)
    return allowlist


def default() -> Allowlist:
    return load()


def find_bank_in_text(text: str) -> str:
    """First bank/e-wallet brand mentioned in ``text`` (for account hints)."""
    if not text:
        return ""
    for entry in default().find_brands(text):
        if entry.category in _BANK_CATEGORIES:
            return entry.entity
    return ""


def _read_entries(path: Path) -> list[Entry]:
    try:
        import yaml  # type: ignore
    except ImportError:  # pragma: no cover
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception:
        logger.warning("scampi: allowlist.yaml failed to parse (%s)", path, exc_info=True)
        return []

    raw_entries = (data or {}).get("entries")
    if not isinstance(raw_entries, list):
        logger.warning("scampi: allowlist.yaml has no entries list (%s)", path)
        return []

    entries: list[Entry] = []
    for item in raw_entries:
        if not isinstance(item, dict):
            continue
        entity = str(item.get("entity") or "").strip()
        category = str(item.get("category") or "").strip().lower()
        aliases = tuple(str(a).strip() for a in item.get("aliases") or [] if str(a).strip())
        domains = tuple(str(d).strip().lower() for d in item.get("domains") or [] if str(d).strip())
        if not entity or not domains:
            logger.warning("scampi: allowlist entry skipped (missing entity/domains): %r", item)
            continue
        entries.append(Entry(entity=entity, category=category, aliases=aliases, domains=domains))
    return entries
