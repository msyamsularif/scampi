# Privasi & retensi

## Yang disimpan

| Data           | Disimpan di             | Isi                                                                 |
| -------------- | ----------------------- | ------------------------------------------------------------------- |
| Riwayat cek    | tabel `checks`          | **hash** input + verdict + skor + waktu (tanpa isi pesan)           |
| Laporan        | tabel `reports`         | entitas ternormalisasi, bank, hash pelapor (HMAC), pattern, catatan |
| Bukti          | tabel `report_evidence` | **referensi** (nama file/link) — isi file tidak dibaca              |
| Feedback       | tabel `feedback`        | check_id, verdict, akurasi, catatan teredaksi                       |
| Cache provider | `link_cache`            | hasil RDAP/Safe Browsing/URLhaus (TTL 24 jam)                       |
| Rate limit     | `rate_limits`           | key identitas, bucket, jendela, hitungan                            |

Isi pesan mentah **tidak pernah** disimpan; pencocokan laporan memakai nilai
ternormalisasi (digit rekening / domain registrable).

## Redaksi (dua lapis)

1. **Sebelum LLM** — middleware `llm_request` menimpa payload keluar:
   OTP, PIN, NIK (16 digit), dan nomor kartu (pola 4-4-4-4) diganti marker
   `[REDACTED_*]`. Bisa dimatikan (`redact_before_llm: false`) hanya untuk
   debug.
2. **Sebelum simpan** — `sanitize_note` men-redaksi catatan laporan dan
   memotong panjangnya.

Angka rekening dan nominal sengaja **tidak** diredaksi — itu bukti yang
diperiksa. Masking tampilan (`****7890`) dipakai di semua keluaran.

## Identitas

- Pelapor disimpan sebagai **HMAC-SHA256** dari kunci acak per-profil; kunci
  di plugin state. Identitas asli tidak pernah masuk basis data.
- Rate limit memakai identitas milik host (user/session) — lihat
  `core/store/identity.py`; fallback per-sesi bila host tidak mengekspos user id.
- Catatan: riwayat percakapan Hermes sendiri diatur oleh konfigurasi host —
  plugin tidak mengubah retensi sesi host.

## Retensi

`hermes scampi retention purge [--days N]` (default `retention_days: 90`)
menghapus:

- baris `report_evidence` lebih tua dari N hari;
- baris `checks` dan `feedback` lebih tua dari N hari;
- **catatan** pada laporan lama (baris laporan tetap, sebagai nilai komunitas);
- cache kedaluwarsa dan jendela rate limit lama;
- file di `plugin-data/scampi/evidence/` lebih tua dari N hari.

Jalur "hapus data saya": operator menjalankan
`hermes scampi retention purge --days 0` (menghapus semua artefak yang
tunduk retensi), lalu menghapus baris laporan spesifik bila diminta —
dilakukan manual oleh operator, bukan oleh model.

## Kepatuhan

- Review terhadap UU PDP dan risiko pencemaran nama baik (defamasi)
  **wajib** sebelum peluncuran publik — konsultasikan ke ahli hukum
  (catatan spec §11).
- Setiap verdict memuat disclaimer "penilaian otomatis, bukan keputusan
  hukum"; label entitas memakai "pernah dilaporkan".
- Kanal sengketa: pemilik entitas dapat menyanggah; operator mengubah status
  laporan menjadi `disputed`, tanpa mengungkap identitas pelapor.
