# Operations runbook

Daily/weekly operator guidance and incident playbooks for Scampi.

## Routine

**Daily (5 minutes)**

- `/scampi status` — patterns loaded, keys active, DB counts. A settings
  warning (`⚠️`) means `config.yaml` could not be read and defaults are in use.
- `hermes scampi reports list --status unverified` — moderate new reports.

**Weekly**

- `hermes scampi patterns validate` — make sure no pattern YAML is broken.
- Spot-check `confirmed` reports (verify the evidence is strong) and `disputed`
  ones (respond to disputes).
- `hermes scampi eval run --dataset <corpus>` — monitor recall/FPR once the
  corpus has been extended with real data.

**Monthly**

- Review patterns (`last_reviewed_at`), update changed allowlist domains, and
  review the thresholds (`caution_threshold`/`scam_threshold`) against real
  metrics.
- `hermes scampi retention purge` (or via cron).

## Incident playbooks

### Provider outage (Safe Browsing / URLhaus / RDAP)

Symptoms: verdicts contain "unreachable" notes, `sources[]` status
`unreachable`/`partial`.
Action: nothing to roll back — degradation is by design. Check
connectivity/quota; results can still be served from the earlier cache.

### Check spam / abuse wave

Symptoms: `rate_limits` filling up, "check limit reached" complaints.
Action: do not disable rate limiting (it protects quota and data); lower
`rate_limit_checks_per_hour` if provider quota is at risk; raise it when the
traffic is legitimate. Look for odd access patterns in the audit log.

### Report flooding / tit-for-tat reports

Symptoms: a spike of `unverified` reports for the same entity.
Action: `reports list` → verify evidence → `reject` the unfounded ones; entity
owners who contest → `dispute`; never reveal reporter identities. Raise the
threshold (`report_confirm_reporters`) under a systematic attack.

### Account/number owner dispute

Action: record the chronology, change the status to `disputed`, and explain
that the status is a function of community reports, not a legal ruling. Keep
all correspondence for legal review.

### Suspected data leak

1. `hermes plugins disable scampi` (stop the traffic).
2. Rotate provider keys (`SAFE_BROWSING_API_KEY`, `URLHAUS_AUTH_KEY`).
3. Inspect `plugin-data/scampi/scampi.db` (no raw message content; report notes
   may contain details — purge if needed: `retention purge --days 0`).
4. Review the audit trail (`post_tool_call` → plugin state `run_audit`), and
   decide on notifications per UU PDP obligations together with legal counsel.

### Quality regression

Symptoms: FPs on legitimate messages, or scams slipping through (misses).
Action: reproduce via the eval harness; fix the pattern groups (narrow/widen)
or the weights in `data/rules.yaml`; add the new case to the corpus so the
regression is locked in by a test.

## Backup & upgrade

- Backup: copy `plugin-data/scampi/` (holds `scampi.db` + state). It contains
  no raw message content, but still treat it as sensitive data (report notes).
- Upgrade: `hermes plugins install <owner>/<repo> --ref <tag/sha>`; plugin-data
  is untouched by updates.
- After an upgrade: `hermes scampi status` + `patterns validate` + a
  `scampi_check` smoke test.
