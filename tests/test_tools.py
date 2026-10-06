"""Tool handlers: JSON contract, rate limiting, persistence."""

from __future__ import annotations

import json

from scampi import store, tools


def _load(result):
    return json.loads(result)


def test_check_returns_payload_with_check_id(conn):
    payload = _load(tools.scampi_check({"text": "Akun BCA diblokir, verifikasi di bca-verifikasi.xyz"}))
    assert payload["ok"] is True
    assert payload["verdict"] == "likely_scam"
    assert payload["check_id"]
    assert payload["plugin"]["name"] == "scampi"

    row = conn.execute("SELECT verdict FROM checks WHERE id=?", (payload["check_id"],)).fetchone()
    assert row is not None
    assert row["verdict"] == "likely_scam"


def test_check_requires_input():
    payload = _load(tools.scampi_check({}))
    assert payload["ok"] is False
    assert "minimal" in payload["error"].lower()


def test_check_non_dict_args_are_tolerated():
    payload = _load(tools.scampi_check(None))
    assert payload["ok"] is False


def test_check_rate_limit(monkeypatch):
    monkeypatch.setenv("SCAMPI_RATE_LIMIT_CHECKS_PER_HOUR", "1")
    first = _load(tools.scampi_check({"text": "cek bca-klik-promo.xyz"}))
    assert first["ok"] is True
    second = _load(tools.scampi_check({"text": "cek bca-klik-promo.xyz lagi"}))
    assert second["ok"] is False
    assert second["error_code"] == "rate_limited"
    assert second["retry_after_seconds"] > 0


def test_report_dedup_and_redaction(conn):
    result = _load(
        tools.scampi_report(
            {
                "entity_type": "account",
                "value": "1234567890",
                "bank": "BCA",
                "note": "otp 112233 dikirim ke mereka",
            }
        )
    )
    assert result["ok"] is True
    assert result["masked_value"] == "****7890"
    assert result["status"] == "unverified"

    duplicate = _load(tools.scampi_report({"entity_type": "account", "value": "1234567890"}))
    assert duplicate["duplicate"] is True

    stored = conn.execute("SELECT note FROM reports ORDER BY id DESC LIMIT 1").fetchone()
    assert "112233" not in stored["note"]


def test_report_rejects_invalid_value():
    payload = _load(tools.scampi_report({"entity_type": "account", "value": "12"}))
    assert payload["ok"] is False


def test_feedback_requires_boolean():
    ok = _load(tools.scampi_feedback({"accurate": True, "check_id": "abc"}))
    assert ok["ok"] is True and ok["recorded"] is True
    bad = _load(tools.scampi_feedback({"accurate": "yes"}))
    assert bad["ok"] is False


def test_feedback_is_persisted(conn):
    tools.scampi_feedback({"accurate": False, "check_id": "xyz", "verdict": "likely_scam"})
    row = conn.execute("SELECT accurate, check_id FROM feedback ORDER BY id DESC LIMIT 1").fetchone()
    assert row["accurate"] == 0
    assert row["check_id"] == "xyz"


def test_store_module_uses_isolated_db(conn):
    # Guard rail: the fixture's database is the one the tools write to.
    tools.scampi_check({"text": "halo"})
    count = conn.execute("SELECT COUNT(*) AS n FROM checks").fetchone()["n"]
    assert count >= 1
    assert store.runtime.db_path().name == "scampi.db"
