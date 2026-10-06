"""Bahasa Indonesia verdict text: labels, reasons, actions, disclaimer.

The model renders the final reply, but every persuasive sentence it may use
originates here or in the tool payload. Nothing about the verdict is left for
the model to invent — that is the load-bearing rule of the whole product.
"""

from __future__ import annotations

from collections.abc import Sequence

from .scoring import VERDICT_CAUTION, VERDICT_NONE, VERDICT_SCAM

VERDICT_LABELS: dict[str, str] = {
    VERDICT_NONE: "✅ Tidak ditemukan tanda bahaya",
    VERDICT_CAUTION: "⚠️ Perlu hati-hati",
    VERDICT_SCAM: "🚨 Kemungkinan besar penipuan",
}

DISCLAIMER = (
    "Ini penilaian otomatis dari sinyal yang tersedia — bukan keputusan hukum. "
    '"Tidak ditemukan tanda bahaya" bukan jaminan bahwa pesan itu aman.'
)

_BASE_ACTIONS: dict[str, list[str]] = {
    VERDICT_SCAM: [
        "Jangan klik tautan atau memasukkan data apa pun.",
        "Jangan transfer uang ke rekening/nomor ini.",
        "Kalau sudah terlanjur klik atau transfer, segera hubungi call center resmi bank/instansi terkait.",
        "Laporkan melalui kanal resmi (mis. OJK 157 atau aduan Komdigi).",
    ],
    VERDICT_CAUTION: [
        "Jangan terburu-buru — tunda dulu sampai terverifikasi.",
        "Cek lewat kanal resmi: aplikasi/situs resmi atau call center resmi yang kamu tahu sendiri.",
        "Jangan pernah membagikan OTP, PIN, atau data kartu ke siapa pun.",
    ],
    VERDICT_NONE: [
        "Tetap waspada — belum ada sinyal yang dikenali, tapi ini bukan jaminan aman.",
        "Jangan pernah membagikan OTP/PIN meskipun yang mengirim mengaku dari bank.",
    ],
}

_LABEL_TEMPLATES = {
    "blocklist_hit": "Link terdaftar di daftar blokir {source_name}",
    "apk_link": "Link mengarah ke file APK (aplikasi yang dipasang manual)",
    "account_confirmed": "{kind} pernah dilaporkan {reporters} pengguna independen dengan bukti",
    "account_reported": "{kind} pernah dilaporkan {reporters} pengguna (belum terverifikasi penuh)",
    "brand_mismatch": "Mengaku {entity}, tetapi domain yang dipakai bukan domain resmi",
    "typosquat": "Domain menyerupai {official} (kemungkinan typosquatting)",
    "young_domain": "Domain baru berumur {days} hari",
    "otp_pin_request": "Meminta OTP/PIN/data rahasia",
    "pattern_match": "Cocok dengan pola penipuan yang dikenal: {name}",
    "pressure_language": "Bahasa mendesak/ancaman khas penipuan ({markers})",
    "risky_tld": "Memakai domain dengan akhiran berisiko ('.{tld}')",
    "url_shortener": "Link dipendekkan sehingga tujuan aslinya tersembunyi",
}


def verdict_label(verdict: str) -> str:
    return VERDICT_LABELS.get(verdict, verdict)


def reason_label(code: str, **kwargs: object) -> str:
    template = _LABEL_TEMPLATES.get(code, code)
    try:
        return template.format(**kwargs)
    except (KeyError, IndexError):  # pragma: no cover - template/data mismatch
        return template


def actions_for(verdict: str, pattern_responses: Sequence[Sequence[str]] = (), cap: int = 6) -> list[str]:
    """Pattern-specific guidance first, then the verdict's base actions."""
    actions: list[str] = []
    for response in pattern_responses[:1]:
        actions.extend(str(item) for item in response)
    actions.extend(_BASE_ACTIONS.get(verdict, _BASE_ACTIONS[VERDICT_CAUTION]))

    out: list[str] = []
    seen = set()
    for action in actions:
        text = action.strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        out.append(text)
        if len(out) >= cap:
            break
    return out


def reasons_payload(signals: Sequence[object]) -> list[dict[str, object]]:
    """Serializable reasons, heaviest first, from scoring signals."""
    ordered = sorted(signals, key=lambda signal: signal.weight, reverse=True)
    return [
        {
            "code": signal.code,
            "label": signal.label,
            "detail": signal.detail,
            "weight": signal.weight,
            "source": signal.source,
        }
        for signal in ordered
    ]
