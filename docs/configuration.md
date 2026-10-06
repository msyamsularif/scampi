# Konfigurasi

Semua pengaturan dideklarasikan di `plugin.yaml` (`config_schema`) dan muncul
di halaman Settings Hermes. Cara set, berurutan prioritas:

1. Host Hermes (`config.yaml` → `plugins.entries.scampi.settings`), atau UI.
2. Variabel lingkungan `SCAMPI_<KEY>` (mis. `SCAMPI_SCAM_THRESHOLD=7`).
3. Default di tabel bawah.

## Daftar pengaturan

| Key                          | Default | Arti                                                                        |
| ---------------------------- | ------- | --------------------------------------------------------------------------- |
| `announce_skill`             | `true`  | Sisipkan pointer ke skill bawaan saat giliran terlihat seperti cek penipuan |
| `redact_before_llm`          | `true`  | Redaksi OTP/PIN/NIK/kartu dari payload ke LLM                               |
| `network_enabled`            | `true`  | Izinkan panggilan RDAP + provider daftar blokir                             |
| `caution_threshold`          | `3.0`   | Skor ≥ ini → "Perlu hati-hati"                                              |
| `scam_threshold`             | `6.0`   | Skor ≥ ini → "Kemungkinan besar penipuan"                                   |
| `young_domain_days`          | `30`    | Umur domain di bawah ini dianggap sinyal kuat                               |
| `report_confirm_reporters`   | `3`     | Jumlah pelapor independen sebelum status "terkonfirmasi"                    |
| `report_confirm_evidence`    | `1`     | Minimum bukti sebelum status "terkonfirmasi"                                |
| `report_decay_days`          | `180`   | Laporan lebih tua dari ini berhenti dihitung                                |
| `retention_days`             | `90`    | Retensi bukti/check metadata sebelum purge                                  |
| `rate_limit_checks_per_hour` | `20`    | Batas cek per identitas per jam                                             |
| `rate_limit_reports_per_day` | `10`    | Batas laporan per identitas per hari                                        |
| `cache_ttl_hours`            | `24`    | TTL cache hasil provider                                                    |
| `network_timeout_seconds`    | `4.0`   | Timeout per panggilan jaringan                                              |
| `max_domains_per_check`      | `3`     | Batas domain/link yang dicek per permintaan                                 |

## Catatan kalibrasi

- `caution_threshold` dan `scam_threshold` adalah **titik awal**. Setelah
  korpus uji bertambah (target spec: 200 scam + 200 legit), kalibrasi ulang
  dengan harness evaluasi dan data nyata — lihat `docs/curation-runbook.md`.
- Menurunkan `caution_threshold` menaikkan recall tetapi menaikkan risiko
  false positive. Spec memprioritaskan recall, dengan pagar "Perlu hati-hati".
- `network_enabled: false` menghasilkan mode sepenuhnya offline (pola,
  allowlist, basis laporan saja) — berguna untuk privasi maksimum atau saat
  provider sedang gangguan.

## Bobot sinyal

Bobot per sinyal _tidak_ diatur lewat settings, tetapi lewat
`data/rules.yaml` — sengaja berbasis file agar perubahan bisa direview.
