# Sumber data

Semua sumber jaringan bersifat _read-only_ terhadap data target dan berjalan
dengan timeout masing-masing. Kegagalan satu sumber tidak menggagalkan
verdict — nilainya digantikan catatan "tidak terjangkau/di-skip".

| Sumber                  | Menjawab                                | Auth                    | Tanpa kunci / gagal                                    |
| ----------------------- | --------------------------------------- | ----------------------- | ------------------------------------------------------ |
| RDAP (`rdap.org`)       | Umur domain (tanggal registrasi)        | tanpa kunci             | status "tidak terjangkau"; verdict menyebut RDAP gagal |
| Google Safe Browsing v4 | URL ada di daftar ancaman Google?       | `SAFE_BROWSING_API_KEY` | sumber di-skip + catatan                               |
| abuse.ch URLhaus        | URL pernah dilaporkan malware/phishing? | `URLHAUS_AUTH_KEY`      | sumber di-skip + catatan                               |

## Catatan privasi & kepatuhan

- URL yang dicurigai **dikirim sebagai data** ke Google/abuse.ch. Target
  ** tidak pernah dibuka** dari server plugin (anti-SSRF). Informasi ini perlu
  disebut di privacy policy publik.
- Kueri RDAP mengungkap nama domain ke registri — bagaimanapun juga informasi
  publik.
- Hasil provider di-cache (`cache_ttl_hours`, default 24 jam) untuk menghemat
  kuota.
- Kuota, lisensi, dan ToS tiap penyedia **wajib diverifikasi ulang** sebelum
  pemakaian produksi (catatan spec §7.1).
- urlscan.io / sandbox browser ditunda (post-MVP); struktur adapter sudah
  disiapkan di `core/checks/linkcheck.py`.

## Degradasi yang dijanjikan

Untuk setiap sumber, verdict memuat entri `sources[]` dengan status:

- `ok` — selesai, hasil dipakai;
- `partial` — sebagian item gagal;
- `unreachable` — gagal total, dicatat sebagai catatan;
- `skipped_no_key` — kunci belum diisi, dicatat sebagai catatan;
- `disabled` — `network_enabled: false`.

Skill menginstruksikan model untuk mengutip status ini apa adanya, tanpa
menambah kesan "bersih".
