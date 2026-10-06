"""Curated scoring inputs: weights, thresholds, and keyword lists.

Data lives in ``data/rules.yaml`` so curation does not require a code change.
A built-in copy of the defaults keeps the plugin answering even if that file
is missing or malformed — with the same values, so behavior never silently
changes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "data" / "rules.yaml"

DEFAULTS: dict[str, Any] = {
    "weights": {
        "blocklist_hit": 8.0,
        "apk_link": 7.0,
        "account_confirmed": 7.0,
        "brand_mismatch": 5.0,
        "typosquat": 5.0,
        "young_domain": 5.0,
        "otp_pin_request": 5.0,
        "pattern_match_strong": 4.0,
        "account_reported": 3.0,
        "pattern_match_medium": 2.0,
        "pressure_language": 2.0,
        "risky_tld": 1.5,
        "url_shortener": 1.5,
    },
    "thresholds": {"caution": 3.0, "scam": 6.0},
    "risky_tlds": [
        "xyz", "top", "icu", "click", "site", "online", "live", "link", "sbs",
        "rest", "monster", "store", "buzz", "club", "vip", "work", "lol", "best",
        "cyou", "quest", "bar", "cfd", "boats",
    ],
    "shorteners": [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
        "rebrand.ly", "shorturl.at", "rb.gy", "surl.li", "lnkd.in",
    ],
    "pressure_markers": [
        "segera", "sekarang juga", "hari ini juga", "batas waktu", "terakhir",
        "hangus", "diblokir", "dibekukan", "terblokir", "ditangguhkan",
        "menunggak", "denda", "pemutusan", "suspend", "diblok",
        "melanggar", "tersangka", "kasus hukum", "jangan beritahu",
        "rahasiakan", "urgent", "mendesak", "24 jam", "sebelum jam",
        "konsekuensi", "tindakan hukum", "kartu anda akan",
    ],
    "otp_keywords": [
        "otp", "kode otp", "kode verifikasi", "kode rahasia", "kode sms",
        "token", "cvv", "cvc", "pin",
    ],
    "request_verbs": [
        "kirim", "kirimkan", "berikan", "masukkan", "isi", "balas",
        "sebutkan", "tulis", "share", "serahkan", "baca kode",
    ],
    "negations": [
        "jangan", "jgn", "tidak", "tdk", "never", "do not", "don't", "hindari",
    ],
}


@dataclass(frozen=True)
class Rules:
    weights: dict[str, float]
    thresholds: dict[str, float]
    risky_tlds: list[str]
    shorteners: list[str]
    pressure_markers: list[str]
    otp_keywords: list[str]
    request_verbs: list[str]
    negations: list[str]


_cache: tuple[tuple[str, int, int], Rules] | None = None


def load(path: Path | None = None) -> Rules:
    """Load rules, merged over the built-in defaults."""
    resolved = Path(path) if path else DEFAULT_PATH
    try:
        stat = resolved.stat()
        stamp = (str(resolved), stat.st_mtime_ns, stat.st_size)
    except OSError:
        return _from_mapping({}, source=str(resolved), found=False)

    global _cache
    if _cache is not None and _cache[0] == stamp:
        return _cache[1]

    data = _read_yaml(resolved)
    if data is None:
        logger.warning("scampi: rules.yaml unreadable; built-in defaults in use (%s)", resolved)
        data = {}
    rules = _from_mapping(data, source=str(resolved), found=True)
    _cache = (stamp, rules)
    return rules


def _read_yaml(path: Path) -> dict[str, Any] | None:
    try:
        import yaml  # type: ignore
    except ImportError:  # pragma: no cover
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception:
        logger.debug("rules.yaml failed to parse", exc_info=True)
        return None
    return data if isinstance(data, dict) else None


def _from_mapping(data: dict[str, Any], *, source: str, found: bool) -> Rules:
    weights = dict(DEFAULTS["weights"])
    for key, value in _as_mapping(data.get("weights")).items():
        try:
            weights[key] = float(value)
        except (TypeError, ValueError):
            logger.warning("scampi: weight %r is not a number; default kept (%s)", key, source)

    thresholds = dict(DEFAULTS["thresholds"])
    for key, value in _as_mapping(data.get("thresholds")).items():
        try:
            thresholds[key] = float(value)
        except (TypeError, ValueError):
            logger.warning("scampi: threshold %r is not a number; default kept (%s)", key, source)

    def listed(name: str) -> list[str]:
        value = data.get(name)
        if value is None:
            return list(DEFAULTS[name])
        return _as_str_list(value, name=name, source=source)

    return Rules(
        weights=weights,
        thresholds=thresholds,
        risky_tlds=listed("risky_tlds"),
        shorteners=listed("shorteners"),
        pressure_markers=listed("pressure_markers"),
        otp_keywords=listed("otp_keywords"),
        request_verbs=listed("request_verbs"),
        negations=listed("negations"),
    )


def _as_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_str_list(value: Any, *, name: str, source: str) -> list[str]:
    if isinstance(value, list):
        out = [str(item).strip().lower() for item in value if str(item).strip()]
        if out:
            return out
    logger.warning("scampi: %s is not a non-empty list; default kept (%s)", name, source)
    return list(DEFAULTS[name])
