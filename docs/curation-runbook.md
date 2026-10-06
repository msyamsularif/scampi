# Curation runbook

A guide for Scampi operators: adding patterns, updating the allowlist, changing
weights, and calibrating thresholds.

## Scam patterns (`data/patterns/*.yaml`)

One pattern per file. Schema:

```yaml
id: undangan-pernikahan-apk # unique, lowercase, hyphens
name: "Undangan pernikahan berisi APK"
description: >- # how the modus operandi works (2-3 lines)
  ...
red_flags: # >= 2, user-facing language
  - "..."
match:
  groups: # EVERY group must have >= 1 matching term
    - ["undangan", "invitation"]
    - ["apk", "aplikasi", "instal"]
  strength: strong # strong (4.0) | medium (2.0)
impersonated_entities: [] # frequently impersonated brands (optional)
correct_response: # >= 1 concrete step (used by the verdict)
  - "..."
sources: # where the pattern came from (media/complaints/reports)
  - "..."
last_reviewed_at: "2026-10-06" # update on every review
```

Group authoring rules:

- Terms are checked as substrings of the normalized (lowercased) text.
- Pick modus-**specific** combinations, not generic words: the group
  `["gagal", "tertahan"]` is far better than `["cek", "link"]`, which collides
  with legitimate messages.
- Test every change against the corpus: `hermes scampi eval run --dataset ...`.

Validation:

```bash
hermes scampi patterns validate
```

Adding or changing patterns does not require a plugin restart (they are loaded
on use), but the file cache is mtime-based — saving the file is enough.

## Official domain allowlist (`data/allowlist.yaml`)

- One entry per entity: `entity`, `category`, `aliases`, `domains`
  (registrable domain; subdomains are automatically treated as official).
- Add **official** domains only; do not add partner/agent sites without
  verification.
- Aliases that are common Indonesian words (e.g. "DANA", "Jago") must be listed
  in `WEAK_ALIASES` (`core/checks/allowlist.py`) so they only match in
  uppercase.
- Update domains when a bank/institution migrates domains — this is the
  fastest-ageing part.

## Weights & thresholds

- Weights: `data/rules.yaml` → `weights` (change = review, because it affects
  every verdict).
- Thresholds: the `caution_threshold` / `scam_threshold` settings
  (see `configuration.md`).
- Calibration: run the eval on the corpus; the initial spec target (§16) is
  **scam recall ≥ 85%**, **false positives on legitimate messages ≤ 5%**.
  If recall is short → add/strengthen patterns; if FP rises → narrow the groups
  or raise the thresholds.

## Community reports (moderation)

```bash
hermes scampi reports list --status unverified
hermes scampi reports show 42
hermes scampi reports confirm 42      # strong evidence
hermes scampi reports reject 42       # unfounded / spam
hermes scampi reports dispute 42      # entity owner contests
```

Label policy: always "has been reported", never "scammer"; status promotion
threshold = `report_confirm_reporters` (3) independent reporters +
`report_confirm_evidence` (1) evidence item; reports age out via
`report_decay_days`.

## Seed status v1

12 patterns loaded (spec target: 30): APK wedding invitation, fake courier,
bank account block, illegal online loans (pinjol), fake investment, fake
marketplace seller, official impersonation, fake prizes, PLN bill, fake job
offer, fake social aid (bansos), e-wallet top-up.
Review cadence: **monthly**, or whenever a new modus shows up in the media or
in complaints.
