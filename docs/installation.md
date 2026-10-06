# Installing Scampi

## Prerequisites

- Hermes Agent with directory plugin support (manifest v2).
- Python 3.9+ (the Hermes runtime uses the same Python for plugins).
- Optional: Google Safe Browsing and URLhaus keys (see `credentials.md`).

## Steps

1. **Install the plugin**

   ```bash
   hermes plugins install <owner>/<repo>
   ```

   From a local checkout, run `./install.sh` (the script delegates to the Hermes
   CLI when available, or prints the manual steps).

2. **Enable it** if that did not happen automatically (Hermes asks for
   dependency confirmation during install — Scampi only needs PyYAML):

   ```bash
   hermes plugins enable scampi
   ```

3. **Fill in the optional keys** (not required; verdicts still work without
   either key):

   ```bash
   # via the Hermes config UI, or:
   echo "SAFE_BROWSING_API_KEY=..." >> ~/.hermes/.env
   echo "URLHAUS_AUTH_KEY=..."       >> ~/.hermes/.env
   ```

   How to obtain the keys: `docs/credentials.md`.

4. **Verify**

   ```bash
   hermes scampi status        # patterns loaded, keys active or not, DB counts
   hermes scampi patterns validate
   ```

   In chat: `/scampi status`.

5. **Quick test** — send a message to the bot:

   > Akun BCA Anda diblokir. Verifikasi segera: bca-verifikasi.xyz

   It should answer with the verdict "🚨 Kemungkinan besar penipuan"
   ("likely scam") plus its reasons and recommended actions.

6. **(Optional) Retention cron** — periodically delete old artifacts:

   ```bash
   hermes scampi retention purge          # uses retention_days from settings
   hermes scampi retention purge --days 30
   ```

   Run it via cron/the Hermes scheduler with `--no-agent` (script-only).

## Upgrade & uninstall

- Upgrade: `hermes plugins install <owner>/<repo> --ref <tag/sha>` then
  `hermes plugins enable scampi`.
- Uninstall: `hermes plugins disable scampi` / `hermes plugins uninstall scampi`.
  Data in `<HERMES_HOME>/plugin-data/scampi/` remains until deleted manually.

## Troubleshooting

| Symptom                                                    | Common cause                  | Fix                                                                            |
| ---------------------------------------------------------- | ----------------------------- | ------------------------------------------------------------------------------ |
| Verdict says "Google Safe Browsing tidak aktif"             | key not filled in             | set `SAFE_BROWSING_API_KEY`, or leave it (graceful degradation)                 |
| "Batas pengecekan tercapai" (check limit reached)           | rate limit                    | wait `retry_after_seconds`, or raise `rate_limit_checks_per_hour`               |
| Domain age not verified                                     | RDAP timeout/unreachable      | check connectivity; the verdict flags the unreachable source                    |
| Skill is not triggered                                      | `announce_skill` disabled     | set `announce_skill: true`                                                      |
