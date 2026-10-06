"""Typed snapshot of the plugin settings, read once per tool call.

One place resolves every knob from :mod:`runtime` so the analysis code never
touches settings keys directly and a missing key always lands on the same
documented default as ``plugin.yaml``.
"""

from __future__ import annotations

from typing import Any

from . import runtime


def load() -> dict[str, Any]:
    return {
        "announce_skill": runtime.setting_bool("announce_skill", True),
        "redact_before_llm": runtime.setting_bool("redact_before_llm", True),
        "network_enabled": runtime.setting_bool("network_enabled", True),
        "caution_threshold": runtime.setting_float("caution_threshold", 3.0),
        "scam_threshold": runtime.setting_float("scam_threshold", 6.0),
        "young_domain_days": runtime.setting_int("young_domain_days", 30),
        "report_confirm_reporters": runtime.setting_int("report_confirm_reporters", 3),
        "report_confirm_evidence": runtime.setting_int("report_confirm_evidence", 1),
        "report_decay_days": runtime.setting_int("report_decay_days", 180),
        "retention_days": runtime.setting_int("retention_days", 90),
        "rate_limit_checks_per_hour": runtime.setting_int("rate_limit_checks_per_hour", 20),
        "rate_limit_reports_per_day": runtime.setting_int("rate_limit_reports_per_day", 10),
        "cache_ttl_hours": runtime.setting_int("cache_ttl_hours", 24),
        "network_timeout_seconds": runtime.setting_float("network_timeout_seconds", 4.0),
        "max_domains_per_check": runtime.setting_int("max_domains_per_check", 3),
    }
