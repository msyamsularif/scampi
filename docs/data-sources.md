# Data sources

All network sources are _read-only_ against target data and run with their own
timeout. One source failing never fails the verdict — its contribution is
replaced by an "unreachable/skipped" note.

| Source                  | Answers                                        | Auth                    | Without key / on failure                                  |
| ----------------------- | ---------------------------------------------- | ----------------------- | --------------------------------------------------------- |
| RDAP (`rdap.org`)       | Domain age (registration date)                 | no key                  | status "unreachable"; the verdict mentions the RDAP failure |
| Google Safe Browsing v4 | Is the URL on Google's threat list?            | `SAFE_BROWSING_API_KEY` | source skipped + note                                     |
| abuse.ch URLhaus        | Has the URL been reported for malware/phishing? | `URLHAUS_AUTH_KEY`      | source skipped + note                                     |

## Privacy & compliance notes

- Suspicious URLs are **sent as data** to Google/abuse.ch. Targets are
  **never fetched** from the plugin server (anti-SSRF). This must be mentioned
  in the public privacy policy.
- RDAP queries reveal the domain name to the registry — public information
  regardless.
- Provider results are cached (`cache_ttl_hours`, default 24 hours) to save
  quota.
- Quotas, licenses, and ToS of every provider **must be re-verified** before
  production use (spec note §7.1).
- urlscan.io / browser sandbox is deferred (post-MVP); the adapter structure is
  already prepared in `core/checks/linkcheck.py`.

## Promised degradation

For each source, the verdict contains a `sources[]` entry with a status:

- `ok` — completed, result used;
- `partial` — some items failed;
- `unreachable` — failed entirely, recorded as a note;
- `skipped_no_key` — key not filled in, recorded as a note;
- `disabled` — `network_enabled: false`.

The skill instructs the model to quote these statuses as they are, without
adding any impression of "clean".
