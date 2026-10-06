"""Provider adapters with mocked HTTP; degradation paths."""

from __future__ import annotations

from scampi.core.checks import linkcheck


class _Url:
    def __init__(self, raw, host):
        self.raw = raw
        self.host = host


def test_disabled_short_circuits(conn, base_settings):
    settings = dict(base_settings, network_enabled=False)
    result = linkcheck.check_network([_Url("https://x.xyz/", "x.xyz")], ["x.xyz"], settings, conn)
    assert result["sources"][0]["status"] == "disabled"
    assert result["findings"] == []


def test_safe_browsing_hit_and_cache(conn, base_settings, monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")
    calls = {"n": 0}

    def fake_post(url, body, timeout, headers=None):
        calls["n"] += 1
        return {"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "https://bad.xyz/"}}]}

    monkeypatch.setattr(linkcheck, "_http_post_json", fake_post)
    settings = dict(base_settings, network_enabled=True)

    result = linkcheck.check_network([_Url("https://bad.xyz/", "bad.xyz")], [], settings, conn)
    assert any(finding["kind"] == "safe_browsing" for finding in result["findings"])
    assert result["sources"][0]["status"] == "ok"
    assert calls["n"] == 1

    again = linkcheck.check_network([_Url("https://bad.xyz/", "bad.xyz")], [], settings, conn)
    assert calls["n"] == 1  # served from cache
    assert any(finding["kind"] == "safe_browsing" for finding in again["findings"])


def test_safe_browsing_missing_key_degrades(conn, base_settings):
    settings = dict(base_settings, network_enabled=True)
    result = linkcheck.check_network([_Url("https://x.xyz/", "x.xyz")], [], settings, conn)
    source = next(item for item in result["sources"] if item["source"] == "safe_browsing")
    assert source["status"] == "skipped_no_key"
    assert any("Safe Browsing" in note for note in result["notes"])


def test_safe_browsing_unreachable_is_stated(conn, base_settings, monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "k")

    def fail(*args, **kwargs):
        raise linkcheck.ProviderError("unreachable", "TimeoutError")

    monkeypatch.setattr(linkcheck, "_http_post_json", fail)
    settings = dict(base_settings, network_enabled=True)
    result = linkcheck.check_network([_Url("https://x.xyz/", "x.xyz")], [], settings, conn)
    source = next(item for item in result["sources"] if item["source"] == "safe_browsing")
    assert source["status"] == "unreachable"
    assert any("tidak terjangkau" in note for note in result["notes"])


def test_urlhaus_hit(conn, base_settings, monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "k")

    def fake_form(url, form, timeout, headers=None):
        return {"query_status": "ok", "threat": "malware_download", "url_status": "online"}

    monkeypatch.setattr(linkcheck, "_http_post_form", fake_form)
    settings = dict(base_settings, network_enabled=True)
    result = linkcheck.check_network([_Url("https://bad.xyz/", "bad.xyz")], [], settings, conn)
    assert any(finding["kind"] == "urlhaus" for finding in result["findings"])


def test_urlhaus_all_failures_reported(conn, base_settings, monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "k")

    def fail(*args, **kwargs):
        raise linkcheck.ProviderError("unreachable", "TimeoutError")

    monkeypatch.setattr(linkcheck, "_http_post_form", fail)
    settings = dict(base_settings, network_enabled=True)
    result = linkcheck.check_network([_Url("https://bad.xyz/", "bad.xyz")], [], settings, conn)
    source = next(item for item in result["sources"] if item["source"] == "urlhaus")
    assert source["status"] == "unreachable"


def test_rdap_domain_age_finding(conn, base_settings, monkeypatch):
    from scampi.core.checks import rdap

    monkeypatch.setattr(
        rdap,
        "fetch_domain_age",
        lambda domain, timeout: rdap.DomainAge(status="ok", domain=domain, age_days=5),
    )
    settings = dict(base_settings, network_enabled=True)
    result = linkcheck.check_network([], ["fresh.xyz"], settings, conn)
    finding = next(item for item in result["findings"] if item["kind"] == "domain_age")
    assert finding["age_days"] == 5
