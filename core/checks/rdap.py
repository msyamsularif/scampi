"""RDAP domain-age lookups — the keyless source.

Queried through ``rdap.org``'s bootstrap redirect. Network trouble is never
fatal: every failure returns a status the verdict can surface as "source
unreachable" instead of silently changing the score.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

RDAP_URL = "https://rdap.org/domain/{domain}"
USER_AGENT = "scampi/1.0.0 (+https://github.com/msyamsularif/scampi)"


@dataclass
class DomainAge:
    status: str  # ok | not_found | unreachable | error | unknown
    domain: str
    age_days: int | None = None
    registered_at: str | None = None
    detail: str = ""


def fetch_domain_age(domain: str, timeout: float = 4.0) -> DomainAge:
    request = urllib.request.Request(
        RDAP_URL.format(domain=domain),
        headers={"Accept": "application/rdap+json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return DomainAge(status="not_found", domain=domain, detail="HTTP 404")
        return DomainAge(status="unreachable", domain=domain, detail=f"HTTP {exc.code}")
    except Exception as exc:  # URLError, timeout, TLS...
        return DomainAge(status="unreachable", domain=domain, detail=exc.__class__.__name__)

    try:
        data = json.loads(payload or "{}")
    except json.JSONDecodeError:
        return DomainAge(status="error", domain=domain, detail="invalid JSON")

    registered_at = _registration_date(data)
    if registered_at is None:
        return DomainAge(status="unknown", domain=domain, detail="no registration event")

    age_days = max(0, (datetime.now(timezone.utc) - registered_at).days)
    return DomainAge(
        status="ok",
        domain=domain,
        age_days=age_days,
        registered_at=registered_at.isoformat(timespec="seconds"),
    )


def _registration_date(data: dict[str, Any]) -> datetime | None:
    events = data.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        if str(event.get("eventAction") or "").strip().lower() != "registration":
            continue
        parsed = _parse_date(event.get("eventDate"))
        if parsed is not None:
            return parsed
    return None


def _parse_date(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
