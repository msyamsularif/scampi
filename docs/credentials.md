# Kredensial

Scampi berjalan tanpa kunci API apa pun. Kunci hanya menambah kekuatan
deteksi; ketiadaannya selalu dinyatakan di verdict.

## Google Safe Browsing API key

1. Buka Google Cloud Console, buat/pilih project.
2. **APIs & Services → Library** → cari "Safe Browsing API" → **Enable**.
3. **APIs & Services → Credentials → Create credentials → API key**.
4. Simpan sebagai `SAFE_BROWSING_API_KEY` (Hermes secret/env).

- Kuota gratis; cukup untuk beta. Pembatasan: pasang application restriction
  bila kunci dipakai hanya untuk layanan ini.
- Tanpa kunci: sumber ini di-skip, verdict menulis
  "Google Safe Browsing tidak aktif (API key belum diisi)".

## abuse.ch URLhaus Auth-Key

1. Buat akun di <https://auth.abuse.ch/>.
2. Salin **Auth-Key** dari halaman profil.
3. Simpan sebagai `URLHAUS_AUTH_KEY`.

- URLhaus gratis untuk keperluan keamanan/komunitas; **verifikasi ToS dan
  kuota terbaru** sebelum pemakaian intensif.
- Tanpa kunci: sumber ini di-skip dengan catatan eksplisit di verdict.

## Aturan penyimpanan

- Nilai kunci **tidak pernah** ditulis ke `plugin.yaml`, kode, atau basis data.
- Di Hermes: simpan lewat config UI/secret store (`~/.hermes/.env`); plugin
  hanya membaca dari environment variable.
- Rotasi: ganti nilai di Hermes, restart sesi; tidak perlu menyentuh plugin.
- `.env.example` hanya berisi nama variabel, tanpa nilai.
