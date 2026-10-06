# Privacy & retention

## What is stored

| Data           | Stored in               | Contents                                                            |
| -------------- | ----------------------- | ------------------------------------------------------------------- |
| Check history  | `checks` table          | **hash** of the input + verdict + score + time (no message content) |
| Reports        | `reports` table         | normalized entity, bank, reporter hash (HMAC), pattern, note       |
| Evidence       | `report_evidence` table | **references** (file name/link) — file contents are never read      |
| Feedback       | `feedback` table        | check_id, verdict, accuracy, redacted note                          |
| Provider cache | `link_cache`            | RDAP/Safe Browsing/URLhaus results (24-hour TTL)                    |
| Rate limit     | `rate_limits`           | identity key, bucket, window, count                                 |

Raw message content is **never** stored; report matching uses normalized values
(account digits / registrable domain).

## Redaction (two layers)

1. **Before the LLM** — the `llm_request` middleware rewrites the outgoing
   payload: OTP, PIN, NIK (16 digits), and card numbers (4-4-4-4 pattern) are
   replaced with `[REDACTED_*]` markers. Can be disabled
   (`redact_before_llm: false`) for debugging only.
2. **Before storage** — `sanitize_note` redacts report notes and truncates
   their length.

Account numbers and amounts are deliberately **not** redacted — they are the
evidence being checked. Display masking (`****7890`) is used in all output.

## Identity

- Reporters are stored as an **HMAC-SHA256** of a per-profile random key; the
  key lives in plugin state. Real identities never enter the database.
- Rate limiting uses the host's identity (user/session) — see
  `core/store/identity.py`; it falls back to per-session when the host does not
  expose a user id.
- Note: Hermes conversation history itself is governed by the host
  configuration — the plugin does not change host session retention.

## Retention

`hermes scampi retention purge [--days N]` (default `retention_days: 90`)
deletes:

- `report_evidence` rows older than N days;
- `checks` and `feedback` rows older than N days;
- **notes** on old reports (the report rows stay, as community signal);
- expired cache entries and old rate-limit windows;
- files in `plugin-data/scampi/evidence/` older than N days.

"Delete my data" path: the operator runs
`hermes scampi retention purge --days 0` (deleting every artifact subject to
retention), then deletes specific report rows if requested — done manually by
the operator, not by the model.

## Compliance

- A review against Indonesia's PDP law (UU PDP) and defamation risk is
  **mandatory** before public launch — consult legal counsel (spec note §11).
- Every verdict carries the disclaimer "automated assessment, not a legal
  decision"; entity labels use "has been reported".
- Dispute channel: entity owners can contest; operators change the report
  status to `disputed`, without ever revealing reporter identities.
