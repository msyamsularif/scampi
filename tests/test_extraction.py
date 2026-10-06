"""Extraction unit tests: URLs, phones, accounts, and text signals."""

from __future__ import annotations

from scampi import extraction, rules


def test_find_urls_scheme_and_bare():
    text = "Cek https://klik-bca.xyz/login dan bca-klik-promo.xyz/undangan ya"
    urls = extraction.find_urls(text)
    hosts = [url.host for url in urls]
    assert "klik-bca.xyz" in hosts
    assert "bca-klik-promo.xyz" in hosts


def test_find_urls_defanged():
    urls = extraction.find_urls("linknya bca-klik-promo[.]xyz/undangan")
    assert urls[0].host == "bca-klik-promo.xyz"
    assert urls[0].registrable == "bca-klik-promo.xyz"


def test_find_urls_strips_trailing_punctuation():
    urls = extraction.find_urls("buka bca.co.id.")
    assert urls[0].host == "bca.co.id"


def test_find_urls_ignores_emails_and_files():
    urls = extraction.find_urls("kirim ke admin@example.com dan lampiran undangan.apk")
    assert urls == []


def test_find_urls_apk_path():
    urls = extraction.find_urls("https://karir-kerja.xyz/app.apk")
    assert urls[0].path == "/app.apk"


def test_find_phones_normalizes():
    phones = extraction.find_phones("hubungi 0812-3456-7890 atau +62 813 9999 8888")
    assert "+6281234567890" in [phone.normalized for phone in phones]
    assert "+6281399998888" in [phone.normalized for phone in phones]


def test_find_accounts_requires_context():
    assert extraction.find_accounts("pesanan nomor 12345678 selesai", []) == []
    found = extraction.find_accounts("transfer ke rekening BCA 1234567890", [])
    assert found and found[0].normalized == "1234567890"
    assert found[0].bank == "BCA"


def test_find_accounts_skips_digits_inside_urls():
    text = "cek https://bca-klik-promo.xyz/1234567890 ya"
    urls = extraction.find_urls(text)
    spans = [(text.index(url.raw), text.index(url.raw) + len(url.raw)) for url in urls]
    assert extraction.find_accounts(text, spans) == []


def test_otp_request_detection():
    loaded = rules.load()
    hits = extraction.find_otp_request(
        "bapak/ibu kirim screenshot otp sekarang", loaded.otp_keywords, loaded.request_verbs, loaded.negations
    )
    assert hits


def test_otp_request_ignores_warnings_and_embedded_verbs():
    loaded = rules.load()
    warnings = (
        "jangan bagikan otp kepada siapa pun",
        "petugas tidak akan pernah berikan kode otp",
        "kode otp sudah dikirim ke nomor anda",
    )
    for text in warnings:
        hits = extraction.find_otp_request(text, loaded.otp_keywords, loaded.request_verbs, loaded.negations)
        assert hits == [], text


def test_analyze_end_to_end():
    loaded = rules.load()
    extracted = extraction.analyze(
        "Akun BCA Anda diblokir. Verifikasi segera: bca-verifikasi.xyz. Jangan beritahu siapa pun.",
        rules=loaded,
        bank_lookup=lambda _text: "",
    )
    assert extracted.domains == ["bca-verifikasi.xyz"]
    assert "diblokir" in extracted.pressure_markers
    assert "segera" in extracted.pressure_markers
    assert extracted.apk is False


def test_analyze_detects_apk():
    loaded = rules.load()
    extracted = extraction.analyze("Unduh file apk di karir-kerja.xyz/app.apk", rules=loaded, bank_lookup=lambda _t: "")
    assert extracted.apk is True
