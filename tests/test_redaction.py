"""Redaction unit tests: secrets masked, everything else untouched."""

from __future__ import annotations

from scampi.core.checks import redaction


def test_nik_masked():
    result = redaction.redact_text("NIK saya 3171234567890001")
    assert "3171234567890001" not in result.text
    assert redaction.MARKER_NIK in result.text
    assert "nik" in result.findings


def test_card_grouped_masked():
    result = redaction.redact_text("kartu 4111 1111 1111 1111 saya")
    assert "4111 1111 1111 1111" not in result.text
    assert redaction.MARKER_CARD in result.text


def test_otp_masked_only_next_to_keyword():
    result = redaction.redact_text("kode OTP Anda 998877. Jangan bagikan.")
    assert "998877" not in result.text
    assert redaction.MARKER_OTP in result.text


def test_otp_not_touched_without_digits():
    result = redaction.redact_text("masukkan kode OTP Anda di aplikasi")
    assert result.text == "masukkan kode OTP Anda di aplikasi"
    assert not result.changed


def test_pin_masked():
    result = redaction.redact_text("PIN kartu saya 4321")
    assert "4321" not in result.text
    assert redaction.MARKER_PIN in result.text


def test_amounts_and_account_numbers_survive():
    text = "transfer Rp1.000.000 ke rekening 1234567890 a.n. Budi"
    result = redaction.redact_text(text)
    assert result.text == text


def test_idempotent():
    once = redaction.redact_text("otp 112233")
    twice = redaction.redact_text(once.text)
    assert once.text == twice.text
    assert not twice.changed


def test_empty_input():
    result = redaction.redact_text("")
    assert result.text == ""
    assert not result.changed
