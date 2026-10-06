"""Report DB: normalization, dedup, thresholds, decay, moderation."""

from __future__ import annotations

import pytest
from scampi.core.store import reports


def _settings(**overrides):
    config = {
        "report_confirm_reporters": 3,
        "report_confirm_evidence": 1,
        "report_decay_days": 180,
    }
    config.update(overrides)
    return config


def test_normalize_value_validation():
    assert reports.normalize_value("account", "1234-5678-9012") == "123456789012"
    with pytest.raises(reports.ReportError):
        reports.normalize_value("account", "123")
    with pytest.raises(reports.ReportError):
        reports.normalize_value("bogus", "x")
    assert reports.normalize_value("phone", "0812-3456-7890") == "+6281234567890"
    assert reports.normalize_value("url", "https://bca-klik.xyz/path") == "bca-klik.xyz"
    assert reports.normalize_value("domain", "sub.bca-klik.xyz") == "bca-klik.xyz"


def test_submit_dedup_same_reporter(conn):
    first = reports.submit(conn, entity_type="account", value="1234567890", reporter_hash="r1", settings=_settings())
    assert first["duplicate"] is False
    second = reports.submit(conn, entity_type="account", value="1234567890", reporter_hash="r1", settings=_settings())
    assert second["duplicate"] is True
    assert second["report_id"] == first["report_id"]


def test_thresholds_between_statuses(conn):
    settings = _settings()
    for index, reporter in enumerate(("r1", "r2", "r3")):
        reports.submit(
            conn,
            entity_type="account",
            value="555000111",
            reporter_hash=reporter,
            evidence_refs=["bukti.jpg"] if index == 0 else None,
            settings=settings,
        )
    summary = reports.entity_summary(conn, "account", "555000111", settings)
    assert summary["status"] == "confirmed"
    assert summary["reporters"] == 3

    reports.submit(conn, entity_type="account", value="555000222", reporter_hash="r1", settings=settings)
    assert reports.entity_summary(conn, "account", "555000222", settings)["status"] == "unverified"
    assert reports.entity_summary(conn, "account", "999000999", settings)["status"] == "none"


def test_decay_excludes_old_reports(conn):
    settings = _settings(report_decay_days=30)
    reports.submit(conn, entity_type="phone", value="081234567890", reporter_hash="r1", settings=settings)
    conn.execute("UPDATE reports SET created_at='2020-01-01T00:00:00+00:00'")
    summary = reports.entity_summary(conn, "phone", "+6281234567890", settings)
    assert summary["status"] == "none"


def test_moderation_and_listing(conn):
    result = reports.submit(
        conn, entity_type="domain", value="bca-klik.xyz", reporter_hash="r1", settings=_settings()
    )
    assert reports.set_status(conn, result["report_id"], "disputed") is True
    with pytest.raises(reports.ReportError):
        reports.set_status(conn, result["report_id"], "bogus")

    listed = reports.list_reports(conn, limit=5)
    assert listed[0]["masked_value"] == "bca-klik.xyz"
    assert listed[0]["status"] == "disputed"


def test_status_note_language_policy():
    note = reports.status_note(
        "account", {"status": "confirmed", "reporters": 3, "last_report": "2026-10-01"}
    )
    assert "pernah dilaporkan" in note
    assert "penipu" not in note.lower()

    empty = reports.status_note("account", {"status": "none"})
    assert "bukan berarti aman" in empty


def test_note_redaction_and_evidence_cap(conn):
    result = reports.submit(
        conn,
        entity_type="account",
        value="777888999",
        reporter_hash="r1",
        note="kode otp saya 445566 dipakai mereka",
        evidence_refs=[f"f{index}.jpg" for index in range(10)],
        settings=_settings(),
    )
    report = reports.get_report(conn, result["report_id"])
    assert "445566" not in report["note"]
    assert len(report["evidence"]) == 5
