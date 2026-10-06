# Instalasi Scampi

## Prasyarat

- Hermes Agent yang mendukung *directory plugins* (manifest v2).
- Python 3.9+ (runtime Hermes juga memakai Python yang sama untuk plugin).
- Opsional: kunci Google Safe Browsing dan URLhaus (lihat `credentials.md`).

## Langkah

1. **Pasang plugin**

   ```bash
   hermes plugins install <owner>/<repo>
   ```

   Dari checkout lokal, jalankan `./install.sh` (script meneruskan ke CLI
   Hermes bila tersedia, atau menampilkan langkah manual).

2. **Aktifkan** jika belum otomatis (Hermes meminta konfirmasi dependensi
   saat instalasi — Scampi hanya butuh PyYAML):

   ```bash
   hermes plugins enable scampi
   ```

3. **Isi kunci opsional** (tidak wajib; verdict tetap jalan tanpa keduanya):

   ```bash
   # lewat config UI Hermes, atau:
   echo "SAFE_BROWSING_API_KEY=..." >> ~/.hermes/.env
   echo "URLHAUS_AUTH_KEY=..."       >> ~/.hermes/.env
   ```

   Panduan memperoleh kunci: `docs/credentials.md`.

4. **Verifikasi**

   ```bash
   hermes scampi status        # polanya termuat, kunci aktif/tidak, hitungan DB
   hermes scampi patterns validate
   ```

   Di chat: `/scampi status`.

5. **Uji cepat** — kirim pesan ke bot:

   > Akun BCA Anda diblokir. Verifikasi segera: bca-verifikasi.xyz

   Harusnya dijawab verdict "🚨 Kemungkinan besar penipuan" dengan alasan dan
   tindakan.

6. **(Opsional) Cron retensi** — hapus artefak lama secara berkala:

   ```bash
   hermes scampi retention purge          # pakai retention_days dari settings
   hermes scampi retention purge --days 30
   ```

   Jalankan lewat cron/scheduler Hermes dengan `--no-agent` (script-only).

## Upgrade & uninstall

- Upgrade: `hermes plugins install <owner>/<repo> --ref <tag/sha>` lalu
  `hermes plugins enable scampi`.
- Uninstall: `hermes plugins disable scampi` / `hermes plugins uninstall scampi`.
  Data di `<HERMES_HOME>/plugin-data/scampi/` tetap ada sampai dihapus manual.

## Troubleshooting

| Gejala | Penyebab umum | Solusi |
|---|---|---|
| Verdict bilang "Google Safe Browsing tidak aktif" | kunci belum diisi | isi `SAFE_BROWSING_API_KEY` atau biarkan (degradasi wajar) |
| "Batas pengecekan tercapai" | rate limit | tunggu sesuai `retry_after_seconds`, atau naikkan `rate_limit_checks_per_hour` |
| Domain age tidak terverifikasi | RDAP timeout/tidak terjangkau | cek koneksi; verdict menandai sumber tak terjangkau |
| Skill tidak terpanggil | `announce_skill` dimatikan | set `announce_skill: true` |
