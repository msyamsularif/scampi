"""Check orchestration: extraction -> signals -> score -> payload.

One function, :func:`run_check`, takes the tool arguments and returns the
complete payload the tool serializes. Everything is injectable — rules,
patterns, allowlist, connection — so tests run fully offline and curation
files can be swapped without touching code.

The verdict is assembled here, from signals only. The model never scores.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from typing import Any

from . import allowlist as allowlist_mod
from . import extraction, linkcheck, reports, scoring, store, verdict
from . import patterns as patterns_mod
from .scoring import Signal

_MAX_ENTITY_INFOS = 6


def run_check(
    args: dict[str, Any],
    settings: dict[str, Any],
    conn: Any,
    *,
    rules: Any | None = None,
    pattern_list: Sequence[patterns_mod.Pattern] | None = None,
    allowlist_obj: allowlist_mod.Allowlist | None = None,
) -> dict[str, Any]:
    if rules is None:
        from . import rules as rules_mod

        rules = rules_mod.load()
    if pattern_list is None:
        pattern_list = patterns_mod.load_patterns()
    if allowlist_obj is None:
        allowlist_obj = allowlist_mod.default()

    combined = combined_text(args)
    extracted = extraction.analyze(combined, rules=rules)
    _merge_explicit(extracted, args)

    signals: list[Signal] = []
    notes: list[str] = []
    weights = rules.weights

    if combined and combined != extraction.defang(combined):
        notes.append(
            "Pesan berisi tautan yang disamarkan (mis. ditulis dengan [.]); sudah dinormalisasi untuk dianalisis."
        )

    # ---- known scam patterns ------------------------------------------------
    matches = patterns_mod.match(pattern_list, extracted.text)
    if matches:
        best = matches[0]
        weight = float(
            weights.get(
                f"pattern_match_{best.pattern.strength}",
                weights.get("pattern_match_medium", 2.0),
            )
        )
        signals.append(
            Signal(
                code="pattern_match",
                weight=weight,
                label=verdict.reason_label("pattern_match", name=best.pattern.name),
                detail=best.pattern.description,
            )
        )

    # ---- brand claims vs official domains ------------------------------------
    _brand_signals(signals, allowlist_obj, combined, extracted, weights)

    # ---- text signals ---------------------------------------------------------
    if extracted.otp_matches:
        signals.append(
            Signal(
                code="otp_pin_request",
                weight=float(weights["otp_pin_request"]),
                label=verdict.reason_label("otp_pin_request"),
            )
        )
    if len(extracted.pressure_markers) >= 2:
        signals.append(
            Signal(
                code="pressure_language",
                weight=float(weights["pressure_language"]),
                label=verdict.reason_label(
                    "pressure_language", markers=", ".join(extracted.pressure_markers[:4])
                ),
            )
        )
    if extracted.apk:
        signals.append(
            Signal(code="apk_link", weight=float(weights["apk_link"]), label=verdict.reason_label("apk_link"))
        )

    # ---- URL-level local signals ----------------------------------------------
    _url_signals(signals, extracted, rules, weights)

    # ---- community reports ------------------------------------------------------
    entity_infos: list[dict[str, Any]] = []
    _report_signals(signals, entity_infos, conn, settings, extracted, pattern_list, weights)

    # ---- network (isolated failures; explicit source status) -------------------
    net = linkcheck.check_network(extracted.urls, extracted.domains, settings, conn)
    notes.extend(net["notes"])
    _network_signals(signals, net["findings"], settings, weights)

    score = scoring.total(signals)
    verdict_key = scoring.verdict_for(
        score,
        float(settings.get("caution_threshold", 3.0)),
        float(settings.get("scam_threshold", 6.0)),
    )

    if verdict_key != scoring.VERDICT_NONE and len(signals) < 2:
        notes.append("Bukti yang terbaca masih terbatas — verifikasi lewat kanal resmi sebelum menyimpulkan.")
    if verdict_key == scoring.VERDICT_NONE:
        notes.append("Tidak ada sinyal yang dikenali dari data yang dikirim. Ini bukan jaminan aman.")

    pattern_responses = [matches[0].pattern.correct_response] if matches else []
    return {
        "verdict": verdict_key,
        "verdict_label": verdict.verdict_label(verdict_key),
        "score": score,
        "reasons": verdict.reasons_payload(signals),
        "actions": verdict.actions_for(verdict_key, pattern_responses),
        "pattern_matches": [
            {
                "id": item.pattern.id,
                "name": item.pattern.name,
                "strength": item.pattern.strength,
                "matched": list(item.terms),
            }
            for item in matches[:3]
        ],
        "entities": entity_infos[:_MAX_ENTITY_INFOS],
        "sources": net["sources"],
        "notes": notes,
        "disclaimer": verdict.DISCLAIMER,
        "extracted": _extracted_summary(extracted),
        "checked_at": store.utcnow(),
    }


def combined_text(args: dict[str, Any]) -> str:
    """All user-provided inputs joined for extraction (order is stable)."""
    parts: list[str] = []
    text = str(args.get("text") or "").strip()
    if text:
        parts.append(text)
    url = str(args.get("url") or "").strip()
    if url:
        parts.append(url)
    account = str(args.get("account_number") or "").strip()
    bank = str(args.get("bank") or "").strip()
    if account:
        parts.append(f"{bank} {account}".strip())
    phone = str(args.get("phone") or "").strip()
    if phone:
        parts.append(phone)
    return "\n".join(parts)


def fingerprint(args: dict[str, Any]) -> str:
    """Hash of the normalized input, stored instead of the message itself."""
    normalized = extraction.normalize(extraction.defang(combined_text(args)))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]


# --------------------------------------------------------------------------- #
# Signal builders
# --------------------------------------------------------------------------- #

def _merge_explicit(extracted: extraction.Extracted, args: dict[str, Any]) -> None:
    """Guarantee explicitly provided entities survive even with no keywords."""
    url_arg = str(args.get("url") or "").strip()
    if url_arg and not any(url_arg in url.raw or url.raw in url_arg for url in extracted.urls):
        found = extraction.find_urls(url_arg)
        if found:
            extracted.urls.append(found[0])
            _add_domain(extracted, found[0].registrable)

    account = str(args.get("account_number") or "").strip()
    if account:
        digits = re.sub(r"\D", "", account)
        if 8 <= len(digits) <= 20 and not any(item.normalized == digits for item in extracted.accounts):
            bank = str(args.get("bank") or "").strip().upper()
            if not bank:
                bank = allowlist_mod.find_bank_in_text(extracted.text)
            extracted.accounts.append(
                extraction.Account(raw=account, normalized=digits, bank=bank, context=extracted.text[:140])
            )

    phone_arg = str(args.get("phone") or "").strip()
    if phone_arg:
        found = extraction.find_phones(phone_arg)
        if found and not any(item.normalized == found[0].normalized for item in extracted.phones):
            extracted.phones.append(found[0])


def _brand_signals(
    signals: list[Signal],
    allowlist_obj: allowlist_mod.Allowlist,
    combined: str,
    extracted: extraction.Extracted,
    weights: dict[str, float],
) -> None:
    if not extracted.urls or not combined:
        return
    seen = set()
    for entry in allowlist_obj.find_brands(combined):
        for url in extracted.urls:
            key = (entry.entity, url.host)
            if key in seen:
                continue
            seen.add(key)
            if allowlist_obj.is_official(url.host, entry) or allowlist_obj.is_official(url.registrable, entry):
                continue
            token = allowlist_obj.brand_token_in_domain(url.host, entry)
            if token:
                signals.append(
                    Signal(
                        code="brand_mismatch",
                        weight=float(weights["brand_mismatch"]),
                        label=verdict.reason_label("brand_mismatch", entity=entry.entity),
                        detail=f"Domain: {url.host}",
                    )
                )
                continue
            official = allowlist_obj.closest_official(url.host, entry)
            if official:
                signals.append(
                    Signal(
                        code="typosquat",
                        weight=float(weights["typosquat"]),
                        label=verdict.reason_label("typosquat", official=official),
                        detail=f"Domain: {url.host}",
                    )
                )


def _url_signals(
    signals: list[Signal],
    extracted: extraction.Extracted,
    rules: Any,
    weights: dict[str, float],
) -> None:
    risky_seen = set()
    for url in extracted.urls:
        tld = url.host.rsplit(".", 1)[-1] if "." in url.host else ""
        if tld and tld in rules.risky_tlds and tld not in risky_seen:
            risky_seen.add(tld)
            signals.append(
                Signal(
                    code="risky_tld",
                    weight=float(weights["risky_tld"]),
                    label=verdict.reason_label("risky_tld", tld=tld),
                    detail=url.host,
                )
            )

    shortener_seen = set()
    for url in extracted.urls:
        if url.registrable in rules.shorteners and url.registrable not in shortener_seen:
            shortener_seen.add(url.registrable)
            signals.append(
                Signal(
                    code="url_shortener",
                    weight=float(weights["url_shortener"]),
                    label=verdict.reason_label("url_shortener"),
                    detail=url.host,
                )
            )


def _report_signals(
    signals: list[Signal],
    entity_infos: list[dict[str, Any]],
    conn: Any,
    settings: dict[str, Any],
    extracted: extraction.Extracted,
    pattern_list: Sequence[patterns_mod.Pattern],
    weights: dict[str, float],
) -> None:
    pattern_names = {pattern.id: pattern.name for pattern in pattern_list}

    subjects = (
        ("account", [(item.normalized, item.bank) for item in extracted.accounts]),
        ("phone", [(item.normalized, "") for item in extracted.phones]),
        ("domain", [(domain, "") for domain in extracted.domains]),
    )
    for entity_type, items in subjects:
        for value, bank in items:
            summary = reports.entity_summary(conn, entity_type, value, settings)
            label = _kind_label(entity_type, bank)
            if summary["status"] == "confirmed":
                signals.append(
                    Signal(
                        code="account_confirmed",
                        weight=float(weights["account_confirmed"]),
                        label=verdict.reason_label(
                            "account_confirmed", kind=label, reporters=summary["reporters"]
                        ),
                        source="community",
                    )
                )
            elif summary["status"] in ("unverified", "disputed") and summary["reporters"] > 0:
                signals.append(
                    Signal(
                        code="account_reported",
                        weight=float(weights["account_reported"]),
                        label=verdict.reason_label(
                            "account_reported", kind=label, reporters=summary["reporters"]
                        ),
                        source="community",
                    )
                )

            entity_infos.append(
                {
                    "type": entity_type,
                    "masked": reports.mask_value(entity_type, value),
                    "bank": bank,
                    "reported": summary["status"] != "none",
                    "status": summary["status"],
                    "reporters": summary["reporters"],
                    "evidence": summary["evidence"],
                    "patterns": [pattern_names.get(pid, pid) for pid in summary["patterns"]],
                    "last_report": summary["last_report"],
                    "note": reports.status_note(entity_type, summary),
                }
            )


def _network_signals(
    signals: list[Signal],
    findings: Sequence[dict[str, Any]],
    settings: dict[str, Any],
    weights: dict[str, float],
) -> None:
    young_days = int(settings.get("young_domain_days", 30))
    seen = set()

    for finding in findings:
        kind = finding.get("kind")
        if kind == "safe_browsing":
            key = ("sb", finding.get("url"))
            if key in seen:
                continue
            seen.add(key)
            threat = str(finding.get("threat") or "")
            signals.append(
                Signal(
                    code="blocklist_hit",
                    weight=float(weights["blocklist_hit"]),
                    label=verdict.reason_label("blocklist_hit", source_name="Google Safe Browsing"),
                    detail=" ".join(part for part in (threat, str(finding.get("url") or "")) if part),
                    source="safe_browsing",
                )
            )
        elif kind == "urlhaus":
            key = ("urlhaus", finding.get("url"))
            if key in seen:
                continue
            seen.add(key)
            detail = str(finding.get("detail") or finding.get("url") or "")
            signals.append(
                Signal(
                    code="blocklist_hit",
                    weight=float(weights["blocklist_hit"]),
                    label=verdict.reason_label("blocklist_hit", source_name="URLhaus"),
                    detail=detail,
                    source="urlhaus",
                )
            )
        elif kind == "domain_age":
            age = finding.get("age_days")
            if isinstance(age, int) and age < young_days:
                signals.append(
                    Signal(
                        code="young_domain",
                        weight=float(weights["young_domain"]),
                        label=verdict.reason_label("young_domain", days=age),
                        detail=str(finding.get("domain") or ""),
                        source="rdap",
                    )
                )


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def _add_domain(extracted: extraction.Extracted, domain: str) -> None:
    if domain and domain not in extracted.domains:
        extracted.domains.append(domain)


def _kind_label(entity_type: str, bank: str) -> str:
    if entity_type == "account":
        return f"Rekening {bank}".strip() if bank else "Nomor rekening"
    if entity_type == "phone":
        return "Nomor telepon"
    return "Domain"


def _extracted_summary(extracted: extraction.Extracted) -> dict[str, Any]:
    return {
        "urls": [url.host for url in extracted.urls],
        "domains": list(extracted.domains),
        "phones": [phone.normalized for phone in extracted.phones],
        "accounts": [
            {"masked": reports.mask_value("account", item.normalized), "bank": item.bank}
            for item in extracted.accounts
        ],
        "pressure_language": len(extracted.pressure_markers) >= 2,
        "otp_request": bool(extracted.otp_matches),
        "apk_link": extracted.apk,
    }
