# Credentials

Scampi runs without any API keys. Keys only add detection strength; their
absence is always stated in the verdict.

## Google Safe Browsing API key

1. Open Google Cloud Console, create/select a project.
2. **APIs & Services → Library** → search for "Safe Browsing API" → **Enable**.
3. **APIs & Services → Credentials → Create credentials → API key**.
4. Store it as `SAFE_BROWSING_API_KEY` (Hermes secret/env).

- Free quota; enough for beta. Restriction: set an application restriction if
  the key is used only for this service.
- Without the key: this source is skipped and the verdict says
  "Google Safe Browsing tidak aktif (API key belum diisi)" — inactive, key not
  set.

## abuse.ch URLhaus Auth-Key

1. Create an account at <https://auth.abuse.ch/>.
2. Copy the **Auth-Key** from the profile page.
3. Store it as `URLHAUS_AUTH_KEY`.

- URLhaus is free for security/community use; **verify the current ToS and
  quota** before intensive use.
- Without the key: this source is skipped with an explicit note in the verdict.

## Storage rules

- Key values are **never** written to `plugin.yaml`, code, or the database.
- In Hermes: store them through the config UI/secret store (`~/.hermes/.env`);
  the plugin only reads from environment variables.
- Rotation: change the value in Hermes, restart the session; no need to touch
  the plugin.
- `.env.example` contains variable names only, never values.
