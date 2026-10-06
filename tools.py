"""Tool handlers — the code that runs when the model calls each tool.

Contract (Hermes): handlers receive ``(args, **kwargs)``, always return a JSON
string, and never raise. The decision logic lives in :mod:`analysis`; this
module owns input validation, rate limiting, the check-id lifecycle, and
error translation. A handler exception here would break a tool call, so every
path is guarded.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Callable

from . import analysis, identity, rate_limit, reports, store
from . import settings as settings_mod
from .about import __version__

logger = logging.getLogger(__name__)

_MAX_TEXT = 20000


def scampi_check(args: Any, **kwargs: Any) -> str:
    return _guarded("scampi_check", lambda: _check_impl(_as_dict(args), kwargs))


def scampi_report(args: Any, **kwargs: Any) -> str:
    return _guarded("scampi_report", lambda: _report_impl(_as_dict(args), kwargs))


def scampi_feedback(args: Any, **kwargs: Any) -> str:
    return _guarded("scampi_feedback", lambda: _feedback_impl(_as_dict(args), kwargs))


# --------------------------------------------------------------------------- #
# Implementations
# --------------------------------------------------------------------------- #

def _check_impl(args: dict[str, Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    text = str(args.get("text") or "").strip()
    url = str(args.get("url") or "").strip()
    account = str(args.get("account_number") or "").strip()
    phone = str(args.get("phone") or "").strip()
    if not any((text, url, account, phone)):
        return {
            "ok": False,
            "error": "Isi minimal salah satu dari: text, url, account_number, atau phone.",
        }
    if len(text) > _MAX_TEXT:
        text = text[:_MAX_TEXT]
        args = {**args, "text": text}

    config = settings_mod.load()
    ident = identity.resolve(kwargs)

    with store.connection() as conn:
        gate = rate_limit.check(
            conn,
            ident.key,
            rate_limit.BUCKET_CHECKS,
            config["rate_limit_checks_per_hour"],
            3600,
        )
        if not gate["allowed"]:
            return {
                "ok": False,
                "error_code": "rate_limited",
                "retry_after_seconds": gate["retry_after_seconds"],
                "error": rate_limit.limit_message(rate_limit.BUCKET_CHECKS, gate),
            }

        payload = analysis.run_check(args, config, conn)
        check_id = uuid.uuid4().hex[:12]
        store.record_check(conn, check_id, analysis.fingerprint(args), payload["verdict"], payload["score"])

    payload["ok"] = True
    payload["check_id"] = check_id
    payload["plugin"] = {"name": "scampi", "version": __version__}
    return payload


def _report_impl(args: dict[str, Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    entity_type = str(args.get("entity_type") or "").strip().lower()
    value = str(args.get("value") or "").strip()
    if not entity_type or not value:
        return {"ok": False, "error": "entity_type dan value wajib diisi."}

    config = settings_mod.load()
    ident = identity.resolve(kwargs)
    reporter = identity.reporter_hash(ident.key)

    with store.connection() as conn:
        gate = rate_limit.check(
            conn,
            ident.key,
            rate_limit.BUCKET_REPORTS,
            config["rate_limit_reports_per_day"],
            86400,
        )
        if not gate["allowed"]:
            return {
                "ok": False,
                "error_code": "rate_limited",
                "retry_after_seconds": gate["retry_after_seconds"],
                "error": rate_limit.limit_message(rate_limit.BUCKET_REPORTS, gate),
            }

        try:
            result = reports.submit(
                conn,
                entity_type=entity_type,
                value=value,
                bank=str(args.get("bank") or ""),
                pattern_id=str(args.get("pattern_id") or ""),
                note=str(args.get("note") or ""),
                evidence_refs=args.get("evidence_refs"),
                reporter_hash=reporter,
                settings=config,
            )
        except reports.ReportError as exc:
            return {"ok": False, "error": str(exc)}

    summary = result["summary"]
    message = "Laporan tercatat. Terima kasih — ini membantu pengecekan pengguna lain."
    if result["duplicate"]:
        message = "Kamu sudah pernah melaporkan ini dalam 24 jam terakhir, jadi tidak dihitung dua kali."
    return {
        "ok": True,
        "report_id": result["report_id"],
        "duplicate": result["duplicate"],
        "entity_type": result["entity_type"],
        "masked_value": result["masked_value"],
        "status": summary["status"],
        "reporters": summary["reporters"],
        "status_note": reports.status_note(result["entity_type"], summary),
        "message": message,
    }


def _feedback_impl(args: dict[str, Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    accurate = args.get("accurate")
    if not isinstance(accurate, bool):
        return {"ok": False, "error": "Field 'accurate' harus true atau false."}

    ident = identity.resolve(kwargs)
    reporter = identity.reporter_hash(ident.key)
    note = reports.sanitize_note(str(args.get("note") or ""), limit=400)

    with store.connection() as conn:
        conn.execute(
            "INSERT INTO feedback(check_id, verdict, accurate, note, reporter_hash, created_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                str(args.get("check_id") or "")[:32],
                str(args.get("verdict") or "")[:32],
                1 if accurate else 0,
                note,
                reporter,
                store.utcnow(),
            ),
        )

    return {"ok": True, "recorded": True, "message": "Terima kasih, feedback-mu dicatat."}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _as_dict(args: Any) -> dict[str, Any]:
    return args if isinstance(args, dict) else {}


def _guarded(name: str, fn: Callable[[], dict[str, Any]]) -> str:
    try:
        payload = fn()
    except Exception as exc:  # pragma: no cover - last-resort guard
        logger.exception("scampi: %s failed", name)
        payload = {"ok": False, "error": f"Kesalahan internal: {exc.__class__.__name__}"}
    return json.dumps(payload, ensure_ascii=False)
