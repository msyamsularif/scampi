"""Curated scam-pattern database: loading, validation, and deterministic matching.

Patterns live as YAML files under ``data/patterns/``. A pattern matches when
every one of its keyword groups has at least one term present in the
normalized message text — no model, no embeddings, fully testable. Strength
(``strong``/``medium``) becomes the weight the match contributes to the score.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_DIR = Path(__file__).resolve().parents[2] / "data" / "patterns"

REQUIRED_FIELDS = ("id", "name", "description", "red_flags", "match", "correct_response")
_STRENGTHS = ("strong", "medium")
_STRENGTH_ORDER = {"strong": 0, "medium": 1}


@dataclass(frozen=True)
class Pattern:
    id: str
    name: str
    description: str
    red_flags: tuple[str, ...]
    groups: tuple[tuple[str, ...], ...]
    strength: str
    impersonated_entities: tuple[str, ...]
    correct_response: tuple[str, ...]
    sources: tuple[str, ...]
    last_reviewed_at: str
    path: Path


@dataclass(frozen=True)
class PatternMatch:
    pattern: Pattern
    terms: tuple[str, ...]


def load_patterns(directory: Path | None = None) -> list[Pattern]:
    """Load every valid pattern, sorted by file name. Invalid ones are skipped."""
    resolved = Path(directory) if directory else DEFAULT_DIR
    if not resolved.is_dir():
        logger.warning("scampi: pattern directory missing (%s)", resolved)
        return []

    patterns: list[Pattern] = []
    for path in sorted(resolved.glob("*.yaml")):
        data = _read_yaml(path)
        if data is None:
            logger.warning("scampi: pattern %s skipped (unreadable)", path.name)
            continue
        errors = validate(data)
        if errors:
            logger.warning("scampi: pattern %s skipped: %s", path.name, "; ".join(errors))
            continue
        patterns.append(_to_pattern(data, path))
    return patterns


def validate(data: Any) -> list[str]:
    """Return a list of problems; empty means the pattern is loadable."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["pattern is not a mapping"]

    for field in REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"missing field: {field}")
    if errors:
        return errors

    for field in ("id", "name", "description"):
        if not str(data.get(field) or "").strip():
            errors.append(f"{field} must be a non-empty string")

    red_flags = data.get("red_flags")
    if not isinstance(red_flags, list) or len(red_flags) < 2:
        errors.append("red_flags must be a list with at least 2 entries")

    correct = data.get("correct_response")
    if not isinstance(correct, list) or not [c for c in correct if str(c).strip()]:
        errors.append("correct_response must be a non-empty list")

    match = data.get("match")
    if not isinstance(match, dict):
        errors.append("match must be a mapping")
    else:
        strength = str(match.get("strength") or "").strip().lower()
        if strength not in _STRENGTHS:
            errors.append(f"match.strength must be one of {_STRENGTHS}")
        groups = match.get("groups")
        if not isinstance(groups, list) or not groups:
            errors.append("match.groups must be a non-empty list")
        else:
            for index, group in enumerate(groups):
                if not isinstance(group, list) or not [t for t in group if str(t).strip()]:
                    errors.append(f"match.groups[{index}] must be a non-empty list of terms")

    return errors


def match(patterns: Sequence[Pattern], normalized_text: str) -> list[PatternMatch]:
    """All matching patterns, strongest first, then by id for stability."""
    if not normalized_text:
        return []
    matches: list[PatternMatch] = []
    for pattern in patterns:
        terms: list[str] = []
        matched = True
        for group in pattern.groups:
            found = next((term for term in group if term in normalized_text), None)
            if found is None:
                matched = False
                break
            terms.append(found)
        if matched:
            matches.append(PatternMatch(pattern=pattern, terms=tuple(terms)))
    matches.sort(key=lambda item: (_STRENGTH_ORDER.get(item.pattern.strength, 2), item.pattern.id))
    return matches


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #

def _read_yaml(path: Path) -> dict[str, Any] | None:
    try:
        import yaml  # type: ignore
    except ImportError:  # pragma: no cover
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception:
        logger.debug("pattern %s failed to parse", path, exc_info=True)
        return None
    return data if isinstance(data, dict) else None


def _to_pattern(data: dict[str, Any], path: Path) -> Pattern:
    match_block = data["match"]
    groups = tuple(
        tuple(str(term).strip().lower() for term in group if str(term).strip())
        for group in match_block["groups"]
    )
    return Pattern(
        id=str(data["id"]).strip(),
        name=str(data["name"]).strip(),
        description=str(data["description"]).strip(),
        red_flags=tuple(str(flag).strip() for flag in data["red_flags"] if str(flag).strip()),
        groups=groups,
        strength=str(match_block["strength"]).strip().lower(),
        impersonated_entities=tuple(
            str(entity).strip() for entity in data.get("impersonated_entities") or []
        ),
        correct_response=tuple(str(item).strip() for item in data["correct_response"] if str(item).strip()),
        sources=tuple(str(item).strip() for item in data.get("sources") or []),
        last_reviewed_at=str(data.get("last_reviewed_at") or "").strip(),
        path=path,
    )
