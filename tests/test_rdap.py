"""RDAP parsing paths with a fake urlopen."""

from __future__ import annotations

import io
import json
import urllib.error

from scampi.core.checks import rdap


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
        return False


def _with_payload(monkeypatch, payload):
    body = json.dumps(payload).encode("utf-8")
    monkeypatch.setattr(rdap.urllib.request, "urlopen", lambda request, timeout: _FakeResponse(body))


def test_fetch_age_ok(monkeypatch):
    _with_payload(
        monkeypatch,
        {"events": [{"eventAction": "registration", "eventDate": "2026-09-30T00:00:00Z"}]},
    )
    result = rdap.fetch_domain_age("fresh.xyz")
    assert result.status == "ok"
    assert result.age_days is not None
    assert result.age_days >= 0
    assert result.registered_at is not None


def test_fetch_not_found(monkeypatch):
    def raiser(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 404, "not found", {}, None)

    monkeypatch.setattr(rdap.urllib.request, "urlopen", raiser)
    assert rdap.fetch_domain_age("nope.xyz").status == "not_found"


def test_fetch_unreachable(monkeypatch):
    def raiser(request, timeout):
        raise OSError("timed out")

    monkeypatch.setattr(rdap.urllib.request, "urlopen", raiser)
    assert rdap.fetch_domain_age("x.xyz").status == "unreachable"


def test_fetch_no_registration_event(monkeypatch):
    _with_payload(monkeypatch, {"events": []})
    assert rdap.fetch_domain_age("x.xyz").status == "unknown"


def test_fetch_invalid_json(monkeypatch):
    body = b"not json"
    monkeypatch.setattr(rdap.urllib.request, "urlopen", lambda request, timeout: _FakeResponse(body))
    assert rdap.fetch_domain_age("x.xyz").status == "error"


def test_parse_date_variants():
    assert rdap._parse_date("2026-01-01T00:00:00Z") is not None
    assert rdap._parse_date("2026-01-01") is not None
    assert rdap._parse_date("") is None
    assert rdap._parse_date("garbage") is None
