"""Official-domain allowlist and brand matching."""

from __future__ import annotations

from scampi import allowlist


def test_find_brands_boundary():
    found = {entry.entity for entry in allowlist.default().find_brands("Akun BCA Anda diblokir")}
    assert "BCA" in found


def test_weak_alias_case_sensitive():
    instance = allowlist.default()
    assert {entry.entity for entry in instance.find_brands("dana darurat saya menipis")} == set()
    assert "DANA" in {entry.entity for entry in instance.find_brands("Top up DANA murah")}


def test_is_official_subdomain():
    instance = allowlist.default()
    bca = next(entry for entry in instance.entries if entry.entity == "BCA")
    assert instance.is_official("klikbca.com", bca)
    assert instance.is_official("m.klikbca.com", bca)
    assert not instance.is_official("klik-bca.xyz", bca)


def test_brand_token_in_domain():
    instance = allowlist.default()
    bca = next(entry for entry in instance.entries if entry.entity == "BCA")
    assert instance.brand_token_in_domain("bca-klik-promo.xyz", bca) == "bca"
    assert instance.brand_token_in_domain("klikbca-secure.com", bca) == "bca"
    assert instance.brand_token_in_domain("kabar.xyz", bca) == ""


def test_closest_official_typo():
    instance = allowlist.default()
    bca = next(entry for entry in instance.entries if entry.entity == "BCA")
    assert instance.closest_official("bcaa.co.id", bca) == "bca.co.id"
    assert instance.closest_official("totally-other.example", bca) == ""


def test_find_bank_in_text():
    assert allowlist.find_bank_in_text("transfer ke rekening BCA") == "BCA"
    assert allowlist.find_bank_in_text("tidak ada nama bank di sini") == ""
