"""Tool schemas — what the LLM reads to decide when to call each tool.

The descriptions are the routing surface: they say *when* a tool applies and
what its result means. Results are Bahasa Indonesia; the schema is English,
matching the host's conventions.
"""

SCAMPI_CHECK = {
    "name": "scampi_check",
    "description": (
        "Analyze a suspicious message, link, phone number, or bank account and return a "
        "deterministic risk verdict (no_red_flags / caution / likely_scam) with concrete "
        "reasons and recommended actions in Bahasa Indonesia. The verdict comes from "
        "technical evidence (threat blocklists, RDAP domain age, typosquatting, an "
        "official-domain allowlist), a curated Indonesian scam-pattern database, and "
        "community reports — never from guesswork. Call this for ANY scam-check request: "
        "forwarded messages, links, account numbers, and screenshots (transcribe the "
        "image to text first and pass it as `text`). Then present the result exactly as "
        "the bundled scampi skill instructs."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": (
                    "Message text to analyze — keep the original wording. For a screenshot, "
                    "transcribe it and pass the transcription here."
                ),
            },
            "url": {
                "type": "string",
                "description": "A suspicious URL or domain to check (one per call; the domain is extracted automatically).",
            },
            "account_number": {
                "type": "string",
                "description": "Bank account number to look up in the community report database.",
            },
            "bank": {
                "type": "string",
                "description": "Bank or e-wallet name for that account, if known (e.g. BCA, Mandiri, DANA).",
            },
            "phone": {
                "type": "string",
                "description": "Phone/WhatsApp number to look up in the community report database.",
            },
        },
        "required": [],
    },
}

SCAMPI_REPORT = {
    "name": "scampi_report",
    "description": (
        "Record a scam report from the user into the community database: a bank account, "
        "phone number, URL, or domain they believe is being used to scam people. Use it "
        "after the user says they were scammed or want to warn others. One report per "
        "person per entity is counted; evidence references (screenshot filenames/links) "
        "are optional. Never call this without the user explicitly asking to report."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "entity_type": {
                "type": "string",
                "enum": ["account", "phone", "url", "domain"],
                "description": "What is being reported.",
            },
            "value": {
                "type": "string",
                "description": "The account number, phone number, URL, or domain.",
            },
            "bank": {"type": "string", "description": "Bank/e-wallet name for an account report."},
            "pattern_id": {
                "type": "string",
                "description": "Optional known-pattern id (from a previous scampi_check result) this report matches.",
            },
            "note": {
                "type": "string",
                "description": "Short description of what happened, in the user's words (max 1000 chars; secrets are redacted automatically).",
            },
            "evidence_refs": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional evidence references — filenames or links only (max 5). File contents are not read.",
            },
        },
        "required": ["entity_type", "value"],
    },
}

SCAMPI_FEEDBACK = {
    "name": "scampi_feedback",
    "description": (
        "Record whether a previous scampi_check verdict turned out accurate, when the "
        "user says so (e.g. 'ternyata benar scam', 'tapi ini aman kok'). Include the "
        "check_id from the scampi_check result when available. Used to improve curation."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "accurate": {"type": "boolean", "description": "True when the verdict matched reality."},
            "check_id": {
                "type": "string",
                "description": "The check_id returned with the original scampi_check verdict.",
            },
            "verdict": {
                "type": "string",
                "description": "The verdict that was given, when check_id is unavailable.",
            },
            "note": {"type": "string", "description": "Optional short note from the user (max 400 chars)."},
        },
        "required": ["accurate"],
    },
}
