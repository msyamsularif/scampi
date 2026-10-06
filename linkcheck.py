"""Network checks: Google Safe Browsing, URLhaus, and RDAP, with timeouts.

Design rules from the spec:

- never open an unknown link locally (no SSRF): URLs are only ever sent as
  *data* to Google's and abuse.ch's APIs;
- every source runs with its own timeout and fails in isolation;
- the verdict states which sources were skipped or unreachable instead of
  pretending they came back clean;
- results are cached, so a repeated check does not burn quota.

Returns raw findings plus per-source status; scoring lives in the caller.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import Any

from . import store

logger = logging.getLogger(__name__)

USER_AGENT = "scampi-hermes-plugin/0.1 (+https://github.com/msyamsularif/scampi-hermes-plugin)"

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"

_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


class ProviderError(RuntimeError):
    """A provider call failed. ``status`` is one of the source-status values."""

    def __init__(self, status: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


def check_network(urls: Iterable[Any], domains: Iterable[str], settings: dict[str, Any], conn: Any) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    sources: list[dict[str, str]] = []
    notes: list[str] = []

    if not bool(settings.get("network_enabled", True)):
        sources.append(
            {"source": "network", "status": "disabled", "detail": "Pemeriksaan jaringan dimatikan."}
        )
        return {"findings": findings, "sources": sources, "notes": notes}

    timeout = float(settings.get("network_timeout_seconds", 4.0))
    ttl = int(settings.get("cache_ttl_hours", 24))
    max_items = max(1, int(settings.get("max_domains_per_check", 3)))

    url_list = list(dict.fromkeys(url.raw for url in urls))[:max_items]
    domain_list = list(dict.fromkeys(domain for domain in domains if domain))[:max_items]

    if url_list:
        _safe_browsing(url_list, timeout, ttl, conn, findings, sources, notes)
        _urlhaus(url_list, timeout, ttl, conn, findings, sources, notes)
    if domain_list:
        _rdap(domain_list, timeout, ttl, conn, findings, sources, notes)

    return {"findings": findings, "sources": sources, "notes": notes}


# --------------------------------------------------------------------------- #
# Google Safe Browsing (single batched call)
# --------------------------------------------------------------------------- #

def _safe_browsing(urls, timeout, ttl, conn, findings, sources, notes) -> None:
    api_key = os.environ.get("SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        sources.append(
            {
                "source": "safe_browsing",
                "status": "skipped_no_key",
                "detail": "SAFE_BROWSING_API_KEY belum diisi.",
            }
        )
        notes.append(
            "Google Safe Browsing tidak aktif (API key belum diisi), jadi link tidak dicek ke daftar blokir Google."
        )
        return

    results: dict[str, dict[str, Any] | None] = {}
    for url in urls:
        cached = store.cache_get(conn, f"sb:{url}", ttl)
        if isinstance(cached, dict):
            results[url] = cached

    missing = [url for url in urls if url not in results]
    error: ProviderError | None = None
    if missing:
        body = {
            "client": {"clientId": "scampi-hermes-plugin", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": _THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url} for url in missing],
            },
        }
        try:
            data = _http_post_json(SAFE_BROWSING_URL.format(key=api_key), body, timeout)
            matches = data.get("matches") or []
            hit_map: dict[str, str] = {}
            for match in matches:
                if not isinstance(match, dict):
                    continue
                entry = match.get("threat") or {}
                hit_map[str(entry.get("url") or "")] = str(match.get("threatType") or "")
            for url in missing:
                result = {"hit": url in hit_map, "threat": hit_map.get(url, "")}
                results[url] = result
                store.cache_set(conn, f"sb:{url}", result)
        except ProviderError as exc:
            error = exc

    if error is not None and not results:
        sources.append({"source": "safe_browsing", "status": error.status, "detail": error.detail})
        notes.append(f"Google Safe Browsing tidak terjangkau saat pengecekan ({error.detail}).")
        return

    hits = 0
    for url in urls:
        result = results.get(url)
        if result and result.get("hit"):
            hits += 1
            findings.append(
                {"kind": "safe_browsing", "url": url, "threat": result.get("threat", "")}
            )

    checked = len([url for url in urls if url in results])
    sources.append(
        {
            "source": "safe_browsing",
            "status": "ok" if error is None else "partial",
            "detail": f"{checked} link diperiksa, {hits} terindikasi.",
        }
    )
    if error is not None:
        notes.append(
            f"Google Safe Browsing gagal untuk sebagian link ({error.detail}); hasil lain tetap dipakai."
        )


# --------------------------------------------------------------------------- #
# URLhaus (per URL)
# --------------------------------------------------------------------------- #

def _urlhaus(urls, timeout, ttl, conn, findings, sources, notes) -> None:
    auth_key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if not auth_key:
        sources.append(
            {"source": "urlhaus", "status": "skipped_no_key", "detail": "URLHAUS_AUTH_KEY belum diisi."}
        )
        notes.append(
            "URLhaus tidak aktif (Auth-Key belum diisi), jadi link tidak dicek ke daftar malware abuse.ch."
        )
        return

    hits = 0
    failures = 0
    for url in urls:
        cached = store.cache_get(conn, f"urlhaus:{url}", ttl)
        if cached is None:
            try:
                data = _http_post_form(URLHAUS_URL, {"url": url}, timeout, headers={"Auth-Key": auth_key})
            except ProviderError as exc:
                failures += 1
                logger.debug("urlhaus lookup failed for %s: %s", url, exc.detail)
                continue
            query_status = str(data.get("query_status") or "")
            if query_status == "ok":
                detail = "/".join(
                    part for part in (str(data.get("threat") or ""), str(data.get("url_status") or "")) if part
                )
                cached = {"hit": True, "detail": detail}
            elif query_status == "no_results":
                cached = {"hit": False, "detail": ""}
            else:
                cached = {"hit": None, "detail": query_status or "unknown"}
            store.cache_set(conn, f"urlhaus:{url}", cached)

        if isinstance(cached, dict) and cached.get("hit") is True:
            hits += 1
            findings.append({"kind": "urlhaus", "url": url, "detail": str(cached.get("detail") or "")})

    if failures and failures == len(urls):
        sources.append({"source": "urlhaus", "status": "unreachable", "detail": f"{failures} lookup gagal."})
        notes.append("URLhaus tidak terjangkau saat pengecekan.")
        return

    sources.append(
        {
            "source": "urlhaus",
            "status": "ok" if not failures else "partial",
            "detail": f"{len(urls)} link diperiksa, {hits} terindikasi.",
        }
    )
    if failures:
        notes.append(f"URLhaus gagal untuk {failures} link; hasil lain tetap dipakai.")


# --------------------------------------------------------------------------- #
# RDAP (per registrable domain)
# --------------------------------------------------------------------------- #

def _rdap(domains, timeout, ttl, conn, findings, sources, notes) -> None:
    from . import rdap

    ok = 0
    missing = 0
    failures = 0
    for domain in domains:
        cached = store.cache_get(conn, f"rdap:{domain}", ttl)
        if not isinstance(cached, dict):
            result = rdap.fetch_domain_age(domain, timeout)
            cached = {
                "status": result.status,
                "age_days": result.age_days,
                "registered_at": result.registered_at,
                "detail": result.detail,
            }
            if result.status in ("ok", "not_found"):
                store.cache_set(conn, f"rdap:{domain}", cached)

        status = cached.get("status")
        if status == "ok":
            ok += 1
            findings.append(
                {"kind": "domain_age", "domain": domain, "age_days": cached.get("age_days")}
            )
        elif status == "not_found":
            missing += 1
            notes.append(
                f"Domain {domain} tidak ditemukan di RDAP — bisa jadi domain baru atau belum aktif."
            )
        else:
            failures += 1

    if failures and failures == len(domains):
        sources.append({"source": "rdap", "status": "unreachable", "detail": f"{failures} lookup gagal."})
        notes.append("RDAP (umur domain) tidak terjangkau saat pengecekan.")
        return

    detail = f"{len(domains)} domain diperiksa"
    if missing:
        detail += f", {missing} tidak ditemukan"
    sources.append({"source": "rdap", "status": "ok" if not failures else "partial", "detail": detail + "."})
    if failures:
        notes.append(f"RDAP gagal untuk {failures} domain; hasil lain tetap dipakai.")


# --------------------------------------------------------------------------- #
# HTTP helpers (monkeypatched by tests)
# --------------------------------------------------------------------------- #

def _http_post_json(url: str, body: dict[str, Any], timeout: float, headers: dict[str, str] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    merged = {"Content-Type": "application/json"}
    merged.update(headers or {})
    return _request_json("POST", url, data=data, timeout=timeout, headers=merged)


def _http_post_form(url: str, form: dict[str, str], timeout: float, headers: dict[str, str] | None = None) -> dict[str, Any]:
    data = urllib.parse.urlencode(form).encode("utf-8")
    merged = {"Content-Type": "application/x-www-form-urlencoded"}
    merged.update(headers or {})
    return _request_json("POST", url, data=data, timeout=timeout, headers=merged)


def _request_json(method: str, url: str, *, data: bytes | None, timeout: float, headers: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(
        url, data=data, method=method, headers={"User-Agent": USER_AGENT, **headers}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ProviderError("not_found", "HTTP 404") from exc
        raise ProviderError("unreachable", f"HTTP {exc.code}") from exc
    except Exception as exc:  # URLError, timeout, TLS...
        raise ProviderError("unreachable", exc.__class__.__name__) from exc

    try:
        parsed = json.loads(payload or "{}")
    except json.JSONDecodeError as exc:
        raise ProviderError("error", "invalid JSON") from exc
    return parsed if isinstance(parsed, dict) else {}
