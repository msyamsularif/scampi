# Product Spec: Scampi (Scam Detector)

> Status: Draft v0.1
> Product type: Chat bot (Telegram first, WhatsApp later) built on RAG + an agent harness
> Target market: General public in Indonesia

---

## 1. Summary

**Scampi** is a bot that accepts suspicious messages, screenshots, links, phone numbers, or bank account numbers from users and returns a **risk assessment, verifiable reasons, and recommended next steps**.

The assessment does not come from an LLM's "gut feeling". It is built from three inputs:

1. **Technical evidence** (domain age, typosquatting, blocklists, page behavior).
2. **Knowledge of local scam patterns** in Indonesia (RAG).
3. **Verified community reports** (supporting signal only).

The LLM is used for extraction and explanation, not as the decision-maker for the verdict.

### 1.1 Name and Branding

**Scampi** is a play on *scam* and *scampi* (shrimp). It plugs into the well-known Indonesian proverb *"ada udang di balik batu"* ("there's a shrimp behind the rock", meaning a hidden motive), which is exactly the question a user asks when a message feels off.

| Element | Direction |
|---|---|
| Core idea | "Is there a shrimp behind this message?" |
| Tagline options | "Ada scampi di balik pesan ini?" / "Cek dulu sebelum klik." |
| Mascot | A suspicious little shrimp peeking out from behind a rock (friendly, never scary) |
| Tone of voice | Warm, calm, lightly playful; never alarmist, never blames the user |
| Verdict flavor (optional) | Verdict messages can use the mascot, e.g. a calm shrimp for "No red flags found", a wary shrimp for "Caution" |

**To verify before committing:** domain availability (.id/.com), Telegram/WhatsApp/Instagram handles, trademark conflicts (DJKI/WIPO), and search-engine collisions with the seafood dish. Consider a qualified variant such as "Scampi ID" or "Scampi Bot" if the bare name is taken.

## 2. Problem

- Digital fraud is widespread in Indonesia: fake wedding-invitation APKs, fake courier notices, bank phishing, illegal online lenders, investment scams, fake marketplace sellers, and impersonation of police or the financial regulator (OJK).
- Victims are often elderly or less digitally literate users.
- The information needed to verify a message (official bank sites, news reports, complaint platforms) is scattered and not available at the critical moment: **before clicking or transferring money**.
- General-purpose chatbots give opinions without checking real facts such as domain age or whether an account has been reported.

## 3. Goals and Non-Goals

### Goals
- Deliver a risk assessment in **under 15 seconds** for text/links and **under 30 seconds** for screenshots.
- Every verdict comes with **concrete reasons and their sources**.
- Be easy to use: users just *forward* a message, with no new app to install.
- Be honest about uncertainty: never claim something is "definitely safe".
- Respond to users in **Bahasa Indonesia** (the examples in this document are in English for readability).

### Non-Goals (v1)
- Not a substitute for legal authorities; does not issue legal judgments.
- Does not block messages or links on the user's device.
- Does not handle fund recovery or legal proceedings; only points users to official channels.
- Does not detect voice-call scams in real time.

## 4. Target Users

| Persona | Need | Usage |
|---|---|---|
| **Family members of elderly parents** | Check messages their parents received | Forward to the bot, or the parent forwards directly |
| **General users** | Quick check before clicking or transferring | Send a link/account number to the bot |
| **Online buyers/sellers** | Check a counterparty's bank account | Send account number + bank |
| **Reporters** | Report a scam they encountered | Use the in-bot report feature |

## 5. Features

### 5.1 MVP (v1)

| ID | Feature | Description | Priority |
|---|---|---|---|
| F1 | Message check | Analyze message text, extract entities, match against known scam patterns | P0 |
| F2 | Link check | Technical URL analysis + blocklist lookup | P0 |
| F3 | Screenshot check | OCR/vision, then handled like F1 | P0 |
| F4 | Account/number check | Look up the report database; display as "previously reported" | P1 |
| F5 | Three-level verdict | No red flags found / Caution / Likely a scam | P0 |
| F6 | Action guidance | What to do, tailored to the matched scam pattern | P0 |
| F7 | Report a scam | Users report a message/account/link with evidence | P1 |
| F8 | Verdict feedback | "Verdict was accurate / inaccurate" buttons | P1 |

### 5.2 Post-MVP

- WhatsApp support.
- Family mode (groups, alerts to family members).
- Alerts about newly trending scam patterns.
- Browser extension for link checks.
- Public dashboard of scam trends.
- API for third parties (marketplaces, fintechs).

## 6. User Flow

```
User forwards a message / sends a screenshot / link / account number
        ↓
[1] Intake & normalization
        ↓
[2] Entity extraction (URLs, numbers, accounts, claimed institution, pressure tactics)
        ↓
[3] Parallel checks (harness)
    ├─ Link check: blocklists + technical analysis + (optional) sandbox
    ├─ Account/number check: report database
    └─ RAG: match against the scam-pattern database
        ↓
[4] Rule-based scoring + LLM-written explanation
        ↓
[5] Response: verdict, reasons, recommended actions
        ↓
[6] User feedback / report → curation queue
```

### Example output

```
⚠️ LIKELY A SCAM

Reasons:
• The link "bca-klik-promo.xyz" is not an official BCA domain (domain is 5 days old)
• The urgent "your account is blocked" wording is typical of banking phishing
• Matches known pattern: "Account blocked + verification link"

What you should do:
1. Do not click the link and do not enter any data
2. If you already did, contact the bank's official call center immediately
3. Report it through the official complaint channels

Note: this is an automated assessment, not a legal judgment.
```

## 7. Architecture

### 7.1 Components

| Component | Function | Technology options |
|---|---|---|
| Interface | Receive and send messages | Telegram Bot API (v1), WhatsApp Business API (later) |
| Orchestrator (harness) | Control the flow and run tool calls in parallel | Python (FastAPI) or Kotlin (Ktor) |
| Extractor | Extract entities from text | Regex + LLM |
| Vision/OCR | Read screenshots | Multimodal model |
| Link Checker | Blocklist lookup + technical analysis | Safe Browsing/Web Risk, VirusTotal, URLhaus, PhishTank, WHOIS/RDAP |
| Sandbox (optional) | Open links in an isolated environment | urlscan.io (v1), isolated headless browser (later) |
| Account Checker | Look up accounts/numbers in the report database | PostgreSQL |
| RAG | Retrieve matching scam patterns | pgvector / Qdrant / Chroma |
| Scoring Engine | Compute a score from signals | Declarative rules (YAML/JSON) |
| Explainer | Write plain-language explanations | LLM |
| Admin/Curation | Moderate reports and scam patterns | Simple web admin |

> Note: access, quotas, and licensing terms of each external service must be verified directly before relying on them.

### 7.2 Design principles

1. **Rules decide the verdict, not the LLM.** The LLM only extracts and explains, which keeps results consistent and auditable.
2. **An official-domain allowlist as the anchor.** Curate the legitimate domains of banks, couriers, e-commerce platforms, and government agencies (a small, stable set) and detect brand impersonation by comparison.
3. **Parallel checks with timeouts.** If one source fails, the system still responds and states which source was unreachable.
4. **Safe link analysis.** Unknown links are never opened on the main server; use a sandbox or a third-party service.
5. **Data minimization.** Store as little as possible, anonymize, and auto-delete.

## 8. Data

### 8.1 Scam-pattern database (RAG)

Each scam-pattern entry:

| Field | Content |
|---|---|
| `id` | Unique identifier |
| `name` | e.g. "Wedding invitation APK" |
| `description` | How the scam works |
| `red_flags` | Characteristic warning signs |
| `sample_messages` | Several examples (anonymized) |
| `impersonated_entities` | Brands/institutions commonly impersonated |
| `correct_response` | What a victim or potential victim should do |
| `sources` | References (official releases, news, reports) |
| `last_reviewed_at` | Date of last review |

Initial target: **30 manually curated patterns**.

### 8.2 Report database (accounts/numbers/links)

| Field | Content |
|---|---|
| `entity_type` | account / phone / url / domain |
| `normalized_value` | The normalized value |
| `bank` | If an account |
| `reporter_id_hash` | Hash of the reporter's identity (not the real identity) |
| `pattern_id` | Relation to a scam pattern |
| `evidence` | Attachments (optional, with limited retention) |
| `status` | unverified / confirmed / rejected / disputed |
| `created_at` | Timestamp |

### 8.3 Official-domain allowlist

Manually curated: banks, e-wallets, couriers, e-commerce, government agencies. Stored with the date of last review.

## 9. Scoring Logic

### 9.1 Signals and weights (draft)

| Signal | Weight |
|---|---|
| URL listed in a trusted threat source | Very high |
| Link downloads an APK file | Very high |
| Account reported by many independent reporters + evidence | Very high |
| Impersonates a brand, domain is not the brand's | High |
| Domain younger than 30 days | High |
| Page asks for OTP/PIN/card data | High |
| Typosquatting detected | High |
| Strong match with a known scam pattern | Medium-high |
| Reported by users (limited count/evidence) | Medium |
| Risky TLD, many redirects, pressure language | Low-medium |

Numeric weights will be calibrated using a test dataset (see section 12).

### 9.2 Verdict levels

| Level | Meaning |
|---|---|
| ✅ **No red flags found** | No recognized signals. **Not a guarantee of safety.** |
| ⚠️ **Caution** | Some signals present; gray area |
| 🚨 **Likely a scam** | Multiple strong signals, or listed in a trusted source |

The label "Safe" is **not used**. Use "No red flags found" instead.

## 10. Labeling Policy for Accounts/Numbers

- Use the phrase **"previously reported"**, never "scammer".
- Show the number of reporters, time range, and scam pattern, not a verdict.
- Threshold to raise status: at least 3 independent reporters and at least 1 piece of evidence.
- Report weight **decays over time**; show the date of the most recent report.
- "No reports" is always distinguished from "safe".
- Provide a **dispute channel** for account/number owners.
- Anti-abuse: reporter rate limits, lower weight for new accounts, detection of suspicious report spikes.

## 11. Privacy, Security, and Legal

| Area | Policy |
|---|---|
| Message storage | By default, message content is not stored after analysis; stored only if the user submits a report |
| Personal data | Detect and redact ID numbers, OTPs, PINs, and card numbers before processing or storage |
| Reporter identity | Stored as a hash; never shown to other parties |
| Retention | Report evidence is auto-deleted after a set period (determined after legal review) |
| Bot abuse | Rate limits; scoring rule details are not disclosed |
| Disclaimer | Every result states that it is an automated assessment, not a legal judgment |
| Compliance | Review obligations under Indonesia's Personal Data Protection Law (UU PDP) and defamation risk before public launch; consult a legal professional |

## 12. Metrics and Evaluation

### Product metrics
- Weekly active users and checks per day.
- Share of checks resulting in "Caution" or "Likely a scam".
- 4-week user retention.
- Verified reports per week.

### Quality metrics
- **Recall** on the scam test set (priority: do not miss scams).
- **False positive rate** on the legitimate-message test set (real bank/courier/promo messages).
- Verdict satisfaction from the feedback buttons.
- Latency p50/p95.

### Test dataset
- Collect 200+ real scam messages (anonymized) and 200+ similar-looking legitimate messages (bank notifications, courier receipts, genuine e-commerce promos).
- Evaluate pattern retrieval and scoring separately from the quality of LLM explanations.

## 13. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| False positives on legitimate messages | Loss of trust | "Caution" level, official-domain allowlist, testing with legitimate messages |
| False negatives | Users get scammed | "Not a guarantee of safety" messaging, layered signals |
| Scam patterns change quickly | Stale database | Regular curation, monitor news/reports, show review dates |
| Abuse to test scam messages | Scammers optimize their messages | Rate limits, scoring details not disclosed |
| Fake reports / defamation | Legal and reputational risk | Minimum reporter + evidence thresholds, dispute channel, moderation |
| User data leak | Harm to users | Data minimization, automatic redaction, encryption |
| Dependence on third-party APIs | Service disruption | Timeouts, fallbacks, caching |
| LLM/API costs | Runaway spend | Cache results per URL/account, limit LLM use to extraction and explanation |

## 14. Roadmap

| Phase | Duration | Scope |
|---|---|---|
| **0. Research & curation** | Week 0-1 | Curate 30 scam patterns, official-domain list, verify data-source access and licensing, check name/domain/trademark availability |
| **1. Internal MVP** | Week 1-3 | Telegram bot, entity extraction, basic link checks, scam-pattern RAG, three-level verdict |
| **2. Closed beta** | Week 3-6 | Screenshots, account checks (own report database), feedback, test dataset, weight calibration |
| **3. Open beta** | Week 6-10 | Reporting feature, moderation, dispute channel, legal review, privacy policy |
| **4. Expansion** | After that | WhatsApp, family mode, trend dashboard, API |

## 15. Open Questions

1. Which account data sources can be accessed legally and technically (API, license, quota)?
2. Business model: free with donations, freemium, B2B (API for marketplaces/fintechs), or institutional partnerships?
3. What is the initial distribution strategy (family communities, parent communities, neighborhood groups)?
4. How much sandbox capability is needed in v1 versus using a third-party service?
5. Who curates scam patterns and moderates reports as volume grows?
6. Are partnerships with official bodies (OJK, the communications ministry, BSSN, banks) needed for credibility and data access?
7. Is the name "Scampi" available as a domain, social handle, and trademark, and does it need a qualifier?

## 16. MVP Success Criteria

- On the internal test set, **scam recall ≥ 85%** and **false positives on legitimate messages ≤ 5%** (initial targets, to be recalibrated once real data exists).
- Every verdict shows at least 2 concrete, verifiable reasons.
- 50 active beta users use the bot at least 3 times within 2 weeks.
- No user data breach incidents.
