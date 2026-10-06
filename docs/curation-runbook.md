# Runbook kurasi

Panduan untuk operator Scampi: menambah pola, memutakhirkan allowlist,
mengubah bobot, dan mengkalibrasi ambang.

## Pola penipuan (`data/patterns/*.yaml`)

Setiap file satu pola. Skema:

```yaml
id: undangan-pernikahan-apk # unik, huruf kecil, tanda hubung
name: "Undangan pernikahan berisi APK"
description: >- # bagaimana modus bekerja (2-3 baris)
  ...
red_flags: # >= 2, bahasa pengguna
  - "..."
match:
  groups: # SEMUA grup harus punya >= 1 istilah yang cocok
    - ["undangan", "invitation"]
    - ["apk", "aplikasi", "instal"]
  strength: strong # strong (4.0) | medium (2.0)
impersonated_entities: [] # brand yang sering ditiru (opsional)
correct_response: # >= 1 langkah konkret (dipakai verdict)
  - "..."
sources: # asal pola (media/aduan/laporan)
  - "..."
last_reviewed_at: "2026-10-06" # perbarui setiap review
```

Aturan penulisan grup:

- Istilah dicek sebagai substring pada teks ternormalisasi (huruf kecil).
- Pilih kombinasi yang **spesifik modus**, bukan kata umum: grup2
  `["gagal", "tertahan"]` jauh lebih baik daripada `["cek", "link"]` yang
  menabrak pesan sah.
- Uji tiap perubahan terhadap korpus: `hermes scampi eval run --dataset ...`.

Validasi:

```bash
hermes scampi patterns validate
```

Menambah/mengubah pola tidak butuh restart plugin (dimuat saat dipakai),
tapi cache file berbasis mtime — cukup simpan file.

## Allowlist domain resmi (`data/allowlist.yaml`)

- Satu entri per entitas: `entity`, `category`, `aliases`, `domains`
  (registrable domain; subdomain otomatis dianggap resmi).
- Tambah domain **resmi** saja, jangan tambah situs partner/agen tanpa
  verifikasi.
- Alias yang berupa kata umum Indonesia (mis. "DANA", "Jago") harus terdaftar
  di `WEAK_ALIASES` (`core/checks/allowlist.py`) agar hanya cocok dengan huruf besar.
- Perbarui domain saat bank/instansi berpindah domain — ini titik paling
  sering menua.

## Bobot & ambang

- Bobot: `data/rules.yaml` → `weights` (ubah = review, karena memengaruhi
  semua verdict).
- Ambang: settings `caution_threshold` / `scam_threshold`
  (lihat `configuration.md`).
- Kalibrasi: jalankan eval pada korpus; target awal spec §16:
  **recall scam ≥ 85%**, **false positive pada pesan sah ≤ 5%**.
  Jika recall kurang → tambah/kuatkan pola; jika FP naik → persempit grup
  atau naikkan ambang.

## Laporan komunitas (moderasi)

```bash
hermes scampi reports list --status unverified
hermes scampi reports show 42
hermes scampi reports confirm 42      # bukti kuat
hermes scampi reports reject 42       # tidak berdasar / spam
hermes scampi reports dispute 42      # pemilik entitas menyanggah
```

Kebijakan label: selalu "pernah dilaporkan", tak pernah "penipu"; ambang
naik status = `report_confirm_reporters` (3) pelapor independen +
`report_confirm_evidence` (1) bukti; laporan menua lewat `report_decay_days`.

## Status seed v1

12 pola termuat (target spec: 30): undangan APK, kurir palsu, blokir bank,
pinjol, investasi, seller marketplace, impersonasi aparat, hadiah, PLN,
lowongan kerja, bansos, top up e-wallet. Review berkala: **bulanan**, atau
saat muncul modus baru di media/aduan.
