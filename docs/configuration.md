# Configuration

All settings are declared in `plugin.yaml` (`config_schema`) and appear on the
Hermes Settings page. How to set them, in order of precedence:

1. Hermes host (`config.yaml` → `plugins.entries.scampi.settings`), or the UI.
2. Environment variables `SCAMPI_<KEY>` (e.g. `SCAMPI_SCAM_THRESHOLD=7`).
3. The defaults in the table below.

## Settings

| Key                          | Default | Meaning                                                                       |
| ---------------------------- | ------- | ----------------------------------------------------------------------------- |
| `announce_skill`             | `true`  | Inject a pointer to the bundled skill when a turn looks like a scam check     |
| `redact_before_llm`          | `true`  | Redact OTP/PIN/NIK/card numbers from the payload sent to the LLM              |
| `network_enabled`            | `true`  | Allow RDAP + blocklist provider calls                                         |
| `caution_threshold`          | `3.0`   | Score ≥ this → "Perlu hati-hati" (use caution)                                |
| `scam_threshold`             | `6.0`   | Score ≥ this → "Kemungkinan besar penipuan" (likely scam)                      |
| `young_domain_days`          | `30`    | Domain age below this counts as a strong signal                               |
| `report_confirm_reporters`   | `3`     | Independent reporters needed before a report is "confirmed"                   |
| `report_confirm_evidence`    | `1`     | Minimum evidence items before a report is "confirmed"                         |
| `report_decay_days`          | `180`   | Reports older than this stop counting                                         |
| `retention_days`             | `90`    | Retention for evidence/check metadata before purge                            |
| `rate_limit_checks_per_hour` | `20`    | Check limit per identity per hour                                             |
| `rate_limit_reports_per_day` | `10`    | Report limit per identity per day                                             |
| `cache_ttl_hours`            | `24`    | TTL for provider result cache                                                 |
| `network_timeout_seconds`    | `4.0`   | Timeout per network call                                                      |
| `max_domains_per_check`      | `3`     | Maximum domains/links checked per request                                     |

## Calibration notes

- `caution_threshold` and `scam_threshold` are **starting points**. Once the
  test corpus grows (spec target: 200 scam + 200 legit), recalibrate with the
  evaluation harness and real data — see `docs/curation-runbook.md`.
- Lowering `caution_threshold` raises recall but increases the risk of false
  positives. The spec prioritizes recall, with the "use caution" tier as a
  guardrail.
- `network_enabled: false` yields a fully offline mode (patterns, allowlist,
  and the report database only) — useful for maximum privacy or when providers
  are having an outage.

## Signal weights

Per-signal weights are _not_ configured through settings but through
`data/rules.yaml` — deliberately file-based so that changes can be reviewed.
