# Scampi — after install

Instructions for the agent after this plugin is installed. Work through them
in order and keep each step short for the user.

1. **Tell the user what changed, in one or two lines.** Scampi adds
   `scampi_check` (risk verdict), `scampi_report` (community reporting), and
   `scampi_feedback`; scam checks now fold into normal chat, and a bundled
   skill (`skill_view("scampi:scampi")`) governs how verdicts are presented.

2. **Offer the optional keys — clearly optional.** Ask whether the user wants
   to enable the blocklist providers:
   - `SAFE_BROWSING_API_KEY` — Google Safe Browsing (free tier).
   - `URLHAUS_AUTH_KEY` — abuse.ch URLhaus (free account).
     Explain that without keys, link checks still run (RDAP domain age + local
     heuristics) and every verdict states which sources were skipped. Point to
     `docs/credentials.md` for the exact steps. Never paste keys into chat —
     have the user store them in Hermes settings/`.env`.

3. **Verify the install** by running:

   ```
   hermes scampi status
   hermes scampi patterns validate
   ```

   Expected: 12 patterns loaded, no `⚠️` settings warning.

4. **Smoke test with one known-bad sample**, using the tool directly:

   ```
   scampi_check {"text": "Akun BCA Anda diblokir. Verifikasi segera: bca-verifikasi.xyz"}
   ```

   Expected: `verdict: "likely_scam"`, reasons including a brand mismatch,
   and Bahasa Indonesia actions.

5. **Hand the operator the runbooks.** Mention `docs/operations-runbook.md`
   (moderation commands, incidents) and `docs/privacy-retention.md`
   (retention purge, data-deletion path). Retention purge is suggested as a
   periodic job: `hermes scampi retention purge`.

Do not enable anything else, do not modify settings on the user's behalf,
and do not run `retention purge` without being asked.
