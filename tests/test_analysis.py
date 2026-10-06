"""Core orchestration: verdicts assembled from signals, fully offline."""

from __future__ import annotations

from scampi.core.checks import analysis
from scampi.core.store import reports


def _run(text, conn, settings):
    return analysis.run_check({"text": text}, settings, conn)


def test_bank_phishing_is_scam(conn, base_settings):
    payload = _run("Akun BCA Anda diblokir. Verifikasi segera: bca-verifikasi.xyz", conn, base_settings)
    assert payload["verdict"] == "likely_scam"
    assert payload["score"] >= 6
    assert len(payload["reasons"]) >= 2
    assert payload["actions"]
    assert "bukan keputusan hukum" in payload["disclaimer"]
    codes = {reason["code"] for reason in payload["reasons"]}
    assert "brand_mismatch" in codes
    assert payload["pattern_matches"]
    assert payload["pattern_matches"][0]["id"] == "bank-akun-diblokir"


def test_legit_promo_no_red_flags(conn, base_settings):
    payload = _run("BCA: transaksi Rp250.000 di Tokopedia berhasil. Cek di klikbca.com", conn, base_settings)
    assert payload["verdict"] == "no_red_flags"
    assert payload["reasons"] == []
    assert any("bukan jaminan aman" in note for note in payload["notes"])
    assert payload["actions"]


def test_account_confirmed_signal_and_entity_info(conn, base_settings):
    for reporter in ("r1", "r2", "r3"):
        reports.submit(
            conn,
            entity_type="account",
            value="1234567890",
            reporter_hash=reporter,
            evidence_refs=["bukti.jpg"],
            bank="BCA",
            settings=base_settings,
        )
    payload = _run("transfer ke rekening BCA 1234567890 a.n. Budi", conn, base_settings)
    codes = {reason["code"] for reason in payload["reasons"]}
    assert "account_confirmed" in codes
    entity = next(item for item in payload["entities"] if item["type"] == "account")
    assert entity["status"] == "confirmed"
    assert entity["masked"] == "****7890"
    assert entity["reported"] is True


def test_no_reports_is_not_safe(conn, base_settings):
    payload = _run("transfer ke rekening BCA 1111222233 a.n. Siti", conn, base_settings)
    entity = next(item for item in payload["entities"] if item["type"] == "account")
    assert entity["status"] == "none"
    assert "bukan berarti aman" in entity["note"]


def test_defanged_note(conn, base_settings):
    payload = _run("cek bca-klik-promo[.]xyz sekarang", conn, base_settings)
    assert any("disamarkan" in note for note in payload["notes"])


def test_network_disabled_is_stated(conn, base_settings):
    payload = _run("cek bca-klik-promo.xyz", conn, base_settings)
    assert payload["sources"][0]["source"] == "network"
    assert payload["sources"][0]["status"] == "disabled"


def test_network_signals_via_stub(conn, base_settings, monkeypatch):
    stub = {
        "findings": [
            {"kind": "safe_browsing", "url": "https://bca-klik-promo.xyz/", "threat": "SOCIAL_ENGINEERING"},
            {"kind": "domain_age", "domain": "bca-klik-promo.xyz", "age_days": 4},
        ],
        "sources": [{"source": "safe_browsing", "status": "ok", "detail": "1 link diperiksa."}],
        "notes": [],
    }
    monkeypatch.setattr(analysis.linkcheck, "check_network", lambda *a, **k: stub)
    settings = dict(base_settings, network_enabled=True)
    payload = _run("cek https://bca-klik-promo.xyz/", conn, settings)
    codes = {reason["code"] for reason in payload["reasons"]}
    assert {"blocklist_hit", "young_domain"} <= codes
    assert payload["verdict"] == "likely_scam"


def test_pressure_requires_two_markers(conn, base_settings):
    payload = _run("Mohon segera diisi ya", conn, base_settings)
    assert "pressure_language" not in {reason["code"] for reason in payload["reasons"]}


def test_explicit_account_without_context_keywords(conn, base_settings):
    payload = analysis.run_check(
        {"account_number": "9988776655", "bank": "Mandiri"}, base_settings, conn
    )
    assert payload["extracted"]["accounts"][0]["masked"] == "****6655"
