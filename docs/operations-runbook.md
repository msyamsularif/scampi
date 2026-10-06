# Runbook operasional

Panduan operator harian/mingguan dan playbook insiden untuk Scampi.

## Rutin

**Harian (5 menit)**

- `/scampi status` — pola termuat, kunci aktif, hitungan DB. Warning settings
  (`⚠️`) berarti `config.yaml` tidak terbaca dan default dipakai.
- `hermes scampi reports list --status unverified` — moderasi laporan baru.

**Mingguan**

- `hermes scampi patterns validate` — memastikan tidak ada YAML pola rusak.
- Spot-check laporan `confirmed` (pastikan bukti kuat) dan `disputed`
  (tanggapi sengketa).
- `hermes scampi eval run --dataset <korpus>` — pantau recall/FPR bila korpus
  sudah diperluas dengan data nyata.

**Bulanan**

- Review pola (`last_reviewed_at`), update domain allowlist yang berubah,
  tinjau ambang (`caution_threshold`/`scam_threshold`) terhadap metrik nyata.
- `hermes scampi retention purge` (atau via cron).

## Playbook insiden

### Provider gangguan (Safe Browsing / URLhaus / RDAP)

Gejala: verdict memuat catatan "tidak terjangkau", `sources[]` status
`unreachable`/`partial`.
Tindakan: tidak ada yang perlu dibatalkan — degradasi memang desainnya.
Cek koneksi/kuota; hasil tetap dapat di-cache dari sebelumnya.

### Gelombang spam cek / abuse

Gejala: `rate_limits` penuh, keluhan "batas tercapai".
Tindakan: jangan matikan rate limit (melindungi kuota & data); turunkan
`rate_limit_checks_per_hour` bila kuota provider terancam; naikkan bila
legit. Cek pola akses aneh di log audit.

### Gelombang laporan palsu / berbalas-balasan

Gejala: lonjakan `unverified` untuk entitas yang sama.
Tindakan: `reports list` → verifikasi bukti → `reject` yang tak berdasar;
pemilik entitas yang menyanggah → `dispute`; jangan pernah mengungkap
identitas pelapor. Naikkan ambang (`report_confirm_reporters`) bila
serangan sistematis.

### Sengketa pemilik rekening/nomor

Tindakan: catat kronologi, ubah status ke `disputed`, informasikan bahwa
status adalah fungsi dari laporan komunitas, bukan putusan hukum. Simpan
semua korespondensi untuk review legal.

### Kecurigaan kebocoran data

1. `hermes plugins disable scampi` (hentikan trafik).
2. Rotasi kunci provider (`SAFE_BROWSING_API_KEY`, `URLHAUS_AUTH_KEY`).
3. Periksa `plugin-data/scampi/scampi.db` (tanpa isi pesan mentah; catatan
   laporan bisa memuat detail — purga bila perlu: `retention purge --days 0`).
4. Evaluasi audit trail (`post_tool_call` → plugin state `run_audit`),
   putuskan notifikasi sesuai kewajiban UU PDP bersama penasihat hukum.

### Regresi kualitas

Gejala: FP pada pesan sah, atau scam lolos (miss).
Tindakan: reproduksi lewat eval harness; perbaiki grup pola (persempit /
perluas) atau bobot `data/rules.yaml`; tambahkan kasus baru ke korpus agar
regresi terkunci oleh tes.

## Backup & upgrade

- Backup: salin `plugin-data/scampi/` (berisi `scampi.db` + state). Tidak ada
  isi pesan mentah; tetap perlakukan sebagai data sensitif (catatan laporan).
- Upgrade: `hermes plugins install <owner>/<repo> --ref <tag/sha>`; data
  plugin-data tidak tersentuh update.
- Setelah upgrade: `hermes scampi status` + `patterns validate` + smoke test
  `scampi_check`.
