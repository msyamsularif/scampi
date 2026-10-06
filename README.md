# Scampi 🦐 — Scam detector for Indonesia, as a Hermes Agent plugin

Scampi takes a suspicious message, link, bank account number, phone number, or
screenshot and answers with a **risk verdict + verifiable reasons + recommended
actions**, in Bahasa Indonesia.

The verdict does **not** come from the model's gut feeling: it is computed from
technical evidence (blocklists, domain age via RDAP, typosquatting, official
domain allowlist), a curated knowledge base of Indonesian scam patterns, and
community reports.
**Rules decide; the model extracts and explains.**

## Features (MVP v1)

| ID  | Feature                                                                                         |
| --- | ----------------------------------------------------------------------------------------------- |
| F1  | Check text messages (including forwarded messages)                                              |
| F2  | Check links: Google Safe Browsing, URLhaus, domain age (RDAP), local heuristics                  |
| F3  | Check screenshots (via Hermes vision → transcription → F1)                                      |
| F4  | Check accounts/numbers: community report database ("has been reported", never "is a scammer")   |
| F5  | Three-level verdict — no warning signs found / use caution / likely scam                         |
| F6  | Action guidance per scam pattern                                                                |
| F7  | Report a scam (with evidence reference)                                                         |
| F8  | Feedback on verdict accuracy in natural language                                                |

## How a verdict is formed

Every signal contributes a weight (see `data/rules.yaml`); the total falls into
configurable thresholds:

| Signal                                                    | Weight |
| --------------------------------------------------------- | ------ |
| Link listed in a blocklist (Safe Browsing / URLhaus)      | 8      |
| Link points to an APK file                                | 7      |
| Account/number reported by ≥3 independent users + evidence| 7      |
| Claims a brand, domain is not the official one / typosquatting | 5  |
| Domain younger than 30 days                               | 5      |
| Requests OTP/PIN/card details                             | 5      |
| Matches a strong scam pattern                             | 4      |
| Previously reported (not yet verified)                    | 3      |
| Urgent/threatening language (2+ markers)                  | 2      |
| Risky TLD / URL shortener                                 | 1.5    |

Default thresholds: **≥3 use caution**, **≥6 likely scam**.
All of them can be recalibrated with the evaluation harness (see
`docs/curation-runbook.md`).

## Requirements

- **Hermes Agent** (with directory plugin support)
- **Python 3.9+**
- Optional: `SAFE_BROWSING_API_KEY` (Google) and `URLHAUS_AUTH_KEY` (abuse.ch).
  Without either key, link checks still run (RDAP + local heuristics) and the
  verdict states which sources were skipped — the plugin never pretends things
  are "clean".

## Installation

```bash
hermes plugins install <owner>/<repo>
```

Or, from a local checkout:

```bash
./install.sh
```

Once installed: fill in the optional keys (see `docs/credentials.md`), then
check `/scampi status` in chat or `hermes scampi status` in the terminal.

## Usage examples

- **Forwarded message:** the user forwards an SMS "Akun BCA Anda diblokir..."
  ("Your BCA account is blocked...") → Scampi replies with the verdict, reasons,
  and actions.
- **Link:** `bca-klik-promo.xyz` → domain is not owned by BCA, domain age,
  blocklist status.
- **Account:** account number + bank → "reported by N users (last ...)" or
  "never reported — which does not mean it is safe".
- **Screenshot:** the user sends a photo of a scam SMS → the model transcribes
  it and Scampi assesses it.
- **Report:** "I want to report this number" → `scampi_report` → status
  "unverified".

## Privacy (summary)

- Message content is **not stored** after analysis; the `checks` table keeps
  only a hash + verdict.
- OTP/PIN/NIK/card numbers are redacted before the payload is sent to the LLM
  (the `llm_request` middleware) and before notes are stored.
- Reporter identity is stored as an HMAC; evidence retention is automatic
  (default 90 days). Details: `docs/privacy-retention.md`.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install pytest pyyaml ruff
.venv/bin/python -m pytest          # 105 tests
.venv/bin/ruff check .
```

Labelled corpus evaluation (JSONL: `{"text": ..., "label": "scam"|"legit"}`):

```bash
hermes scampi eval run --dataset tests/fixtures/scam_messages.jsonl
```

Current seed corpus metrics: **scam recall 100% (20/20), false positive 0%
(0/20)**.

## Layout

```
plugin.yaml            Hermes manifest (tools, hooks, settings, optional env)
__init__.py            register(ctx): tools, hooks, middleware, commands, skill
core/checks/           Deterministic detection engine
  analysis.py          Orchestration: extraction → signals → score → verdict payload
  extraction.py        URL/phone/account/text-marker extraction (deterministic)
  redaction.py         OTP/PIN/NIK/card redaction (one shared implementation)
  allowlist.py         Match brand against official domains (typosquat & mismatch)
  patterns.py          Load/validate/match YAML scam patterns
  rules.py             Scoring rules from rules.yaml
  scoring.py           Weights, thresholds, and scoring signals
  verdict.py           Bahasa Indonesia verdict text
  domains.py           Domain utilities (registrable domain, edit distance)
  linkcheck.py, rdap.py Network providers with timeout + degradation
  eval.py              Corpus evaluation harness
core/store/            SQLite: reports, evidence, feedback, cache, rate limit
  store.py, reports.py, identity.py, rate_limit.py
core/config/           Settings resolution: settings.py, config_file.py
core/hermes/           Hermes host glue
  tools.py, hooks.py, commands.py, runtime.py, schemas.py
core/about.py          Single source of truth for the plugin version
data/                  rules.yaml, allowlist.yaml, patterns/*.yaml
skills/scampi/         SKILL.md + references (templates, tone, glossary)
tests/                 105 tests + corpus of 20 scam / 20 legit
docs/                  Installation, configuration, credentials, curation, privacy, ops
```

## Language conventions

- **Documentation and code are written in English** — README, `docs/`, the
  specification, manifests, code comments, and commit messages.
- **User-facing output stays in Bahasa Indonesia** — verdicts, reasons,
  actions, and tool payloads are what Indonesian users read, so they are not
  translated.
- **Example cases may stay in Bahasa Indonesia** — sample scam messages,
  example verdicts, and quoted phrases mirror real Indonesian cases, so they
  keep their original language.
- **Indonesian-specific identifiers stay as-is** — e.g. the scam pattern
  files under `data/patterns/`, such as `03-bank-akun-diblokir.yaml`.

## License

MIT — see `LICENSE`.
