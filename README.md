# Scampi 🦐 — Scam detector for Indonesia, as a Hermes Agent plugin

Scampi menerima pesan yang dicurigai, link, nomor rekening, nomor telepon, atau
screenshot, lalu menjawab dengan **penilaian risiko + alasan yang bisa
diverifikasi + langkah yang disarankan**, dalam Bahasa Indonesia.

Verdict-nya **bukan** dari perasaan model: ia dihitung dari bukti teknis
(daftar blokir, umur domain via RDAP, typosquatting, allowlist domain resmi),
basis pola penipuan Indonesia yang dikurasi, dan laporan komunitas.
**Aturan yang memutuskan; model yang mengekstrak dan menjelaskan.**

## Fitur (MVP v1)

| ID | Fitur |
|---|---|
| F1 | Cek pesan teks (termasuk pesan diteruskan) |
| F2 | Cek link: Google Safe Browsing, URLhaus, umur domain (RDAP), heuristik lokal |
| F3 | Cek screenshot (via vision Hermes → transkripsi → F1) |
| F4 | Cek rekening/nomor: basis laporan komunitas ("pernah dilaporkan", bukan "penipu") |
| F5 | Verdict 3 tingkat — tidak ditemukan tanda bahaya / perlu hati-hati / kemungkinan besar penipuan |
| F6 | Panduan tindakan per pola penipuan |
| F7 | Lapor penipuan (dengan referensi bukti) |
| F8 | Feedback akurasi verdict lewat bahasa natural |

## Cara verdict dibentuk

Setiap sinyal menyumbang bobot (lihat `data/rules.yaml`); totalnya jatuh ke
ambang batas yang bisa diatur:

| Sinyal | Bobot |
|---|---|
| Link terdaftar di daftar blokir (Safe Browsing / URLhaus) | 8 |
| Link mengarah ke file APK | 7 |
| Rekening/nomor dilaporkan ≥3 pengguna independen + bukti | 7 |
| Mengaku brand, domain bukan milik resmi / typosquatting | 5 |
| Domain berumur < 30 hari | 5 |
| Meminta OTP/PIN/data kartu | 5 |
| Cocok pola penipuan kuat | 4 |
| Pernah dilaporkan (belum terverifikasi) | 3 |
| Bahasa mendesak/ancaman (2+ penanda) | 2 |
| TLD berisiko / URL shortener | 1.5 |

Ambang default: **≥3 perlu hati-hati**, **≥6 kemungkinan besar penipuan**.
Semua bisa dikalibrasi ulang lewat harness evaluasi (lihat
`docs/curation-runbook.md`).

## Kebutuhan

- **Hermes Agent** (mendukung directory plugin)
- **Python 3.9+**
- Opsional: `SAFE_BROWSING_API_KEY` (Google) dan `URLHAUS_AUTH_KEY` (abuse.ch).
  Tanpa keduanya, cek link tetap jalan (RDAP + heuristik lokal) dan verdict
  menyatakan sumber mana yang di-skip — plugin tidak pernah pura-pura "bersih".

## Instalasi

```bash
hermes plugins install <owner>/<repo>
```

Atau, dari checkout lokal:

```bash
./install.sh
```

Setelah terpasang: isi kunci opsional (lihat `docs/credentials.md`), lalu cek
`/scampi status` di chat atau `hermes scampi status` di terminal.

## Contoh penggunaan

- **Pesan diteruskan:** user meneruskan SMS "Akun BCA Anda diblokir..." →
  Scampi menjawab verdict + alasan + tindakan.
- **Link:** `bca-klik-promo.xyz` → domain bukan milik BCA, umur domain, status
  daftar blokir.
- **Rekening:** nomor rekening + bank → "pernah dilaporkan N pengguna
  (terakhir ...)" atau "belum pernah dilaporkan — bukan berarti aman".
- **Screenshot:** user kirim foto SMS penipuan → model mentranskripsi, Scampi
  menilai.
- **Lapor:** "saya mau lapor nomor ini" → `scampi_report` → status
  "belum terverifikasi".

## Privasi (ringkas)

- Isi pesan **tidak disimpan** setelah analisis; tabel `checks` hanya menyimpan
  hash + verdict.
- OTP/PIN/NIK/nomor kartu di-redaksi sebelum payload dikirim ke LLM
  (middleware `llm_request`) dan sebelum catatan disimpan.
- Identitas pelapor disimpan sebagai HMAC; retensi bukti otomatis
  (default 90 hari). Detail: `docs/privacy-retention.md`.

## Pengembangan

```bash
python3 -m venv .venv
.venv/bin/pip install pytest pyyaml ruff
.venv/bin/python -m pytest          # 105 tes
.venv/bin/ruff check .
```

Evaluasi korpus berlabel (JSONL: `{"text": ..., "label": "scam"|"legit"}`):

```bash
hermes scampi eval run --dataset tests/fixtures/scam_messages.jsonl
```

Metrik seed corpus saat ini: **scam recall 100% (20/20), false positive 0%
(0/20)**.

## Struktur

```
plugin.yaml            Manifest Hermes (tools, hooks, settings, env opsional)
__init__.py            register(ctx): tools, hooks, middleware, commands, skill
analysis.py            Orkestrasi: ekstraksi → sinyal → skor → payload verdict
extraction.py          URL/telepon/rekening/penanda teks (deterministik)
redaction.py           Redaksi OTP/PIN/NIK/kartu (satu implementasi bersama)
allowlist.py           Cocokkan brand vs domain resmi (typosquat & mismatch)
patterns.py            Muat/validasi/match pola penipuan YAML
scoring.py, verdict.py Bobot, ambang, teks verdict Bahasa Indonesia
store.py, reports.py   SQLite: laporan, bukti, feedback, cache, rate limit
linkcheck.py, rdap.py  Provider jaringan dengan timeout + degradasi
hooks.py               Skill pointer, audit, middleware redaksi
commands.py, eval.py   /scampi status + CLI operator + harness evaluasi
data/                   rules.yaml, allowlist.yaml, patterns/*.yaml
skills/scampi/          SKILL.md + referensi (template, nada, glosarium)
tests/                  105 tes + korpus 20 scam / 20 legit
docs/                  Instalasi, konfigurasi, kredensial, kurasi, privasi, ops
```

## Lisensi

MIT — lihat `LICENSE`.
