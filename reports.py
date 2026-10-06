"""Community report storage: submission, dedup, decay, status thresholds.

Label policy (spec section 10): an entity is "pernah dilaporkan", never
"penipu". Status derives from distinct reporters inside the decay window and
attached evidence — never from a single report, and never from a verdict the
model wrote.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from . import redaction, store

ENTITY_TYPES = ("account", "phone", "url", "domain")
_ACCOUNT_RE = re.compile(r"^\d{8,20}$")

ACTIVE_STATUSES = ("unverified", "confirmed", "disputed")
MODERATION_STATUSES = ("confirmed", "rejected", "disputed", "unverified")


class ReportError(ValueError):
    """Raised for user-correctable input problems; the tool returns it as JSON."""


# --------------------------------------------------------------------------- #
# Value handling
# --------------------------------------------------------------------------- #

def normalize_value(entity_type: str, value: str) -> str:
    entity_type = (entity_type or "").strip().lower()
    raw = (value or "").strip()
    if entity_type not in ENTITY_TYPES:
        raise ReportError(f"entity_type harus salah satu dari: {', '.join(ENTITY_TYPES)}")
    if not raw:
        raise ReportError("value wajib diisi")

    if entity_type == "account":
        digits = re.sub(r"\D", "", raw)
        if not _ACCOUNT_RE.fullmatch(digits):
            raise ReportError("nomor rekening harus 8-20 digit")
        return digits

    if entity_type == "phone":
        from . import extraction

        phones = extraction.find_phones(raw)
        if not phones:
            raise ReportError("nomor telepon tidak dikenali (contoh: 0812xxxxxxx)")
        return phones[0].normalized

    if entity_type == "domain":
        host = raw.lower().strip().rstrip(".")
        if "://" in host:
            from .domains import registrable_domain
            from .extraction import _host_from_raw  # noqa: PLC2701 - shared parser

            host = _host_from_raw(host)
            return registrable_domain(host)
        if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,24}", host):
            raise ReportError("domain tidak valid")
        from .domains import registrable_domain

        return registrable_domain(host)

    # url -> store the registrable domain (the reportable unit for links)
    from . import extraction
    from .domains import registrable_domain

    urls = extraction.find_urls(raw)
    if not urls:
        raise ReportError("link tidak valid")
    return registrable_domain(urls[0].host)


def mask_value(entity_type: str, value: str) -> str:
    value = value or ""
    if entity_type in ("account", "phone"):
        return "****" + value[-4:] if len(value) > 4 else "****"
    return value


def sanitize_note(note: str, *, limit: int = 1000) -> str:
    text = redaction.redact_text(str(note or "")).text
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def sanitize_evidence_refs(refs: Sequence[Any] | None) -> list[str]:
    out: list[str] = []
    for item in list(refs or [])[:5]:
        text = re.sub(r"\s+", " ", str(item or "")).strip()
        if not text:
            continue
        out.append(text[:300])
    return out


# --------------------------------------------------------------------------- #
# Submission
# --------------------------------------------------------------------------- #

def submit(
    conn: sqlite3.Connection,
    *,
    entity_type: str,
    value: str,
    bank: str = "",
    pattern_id: str = "",
    note: str = "",
    evidence_refs: Sequence[Any] | None = None,
    reporter_hash: str = "",
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    settings = settings or {}
    normalized = normalize_value(entity_type, value)
    entity_type = entity_type.strip().lower()
    now = datetime.now(timezone.utc)

    # Dedup: one report per reporter per entity within 24 hours.
    cutoff = (now - timedelta(hours=24)).isoformat(timespec="seconds")
    existing = conn.execute(
        "SELECT id FROM reports WHERE entity_type=? AND normalized_value=? AND reporter_hash=? "
        "AND created_at >= ? ORDER BY id DESC LIMIT 1",
        (entity_type, normalized, reporter_hash, cutoff),
    ).fetchone()
    if existing is not None:
        summary = entity_summary(conn, entity_type, normalized, settings)
        return {
            "report_id": int(existing["id"]),
            "duplicate": True,
            "entity_type": entity_type,
            "normalized_value": normalized,
            "masked_value": mask_value(entity_type, normalized),
            "summary": summary,
        }

    created = store.utcnow()
    cursor = conn.execute(
        "INSERT INTO reports(entity_type, normalized_value, bank, reporter_hash, pattern_id, note, "
        "status, created_at, updated_at) VALUES(?,?,?,?,?,?, 'unverified', ?, ?)",
        (
            entity_type,
            normalized,
            str(bank or "").strip().upper()[:40],
            reporter_hash,
            str(pattern_id or "").strip()[:64],
            sanitize_note(note),
            created,
            created,
        ),
    )
    report_id = int(cursor.lastrowid)

    for ref in sanitize_evidence_refs(evidence_refs):
        conn.execute(
            "INSERT INTO report_evidence(report_id, ref, created_at) VALUES(?,?,?)",
            (report_id, ref, created),
        )

    summary = entity_summary(conn, entity_type, normalized, settings)
    return {
        "report_id": report_id,
        "duplicate": False,
        "entity_type": entity_type,
        "normalized_value": normalized,
        "masked_value": mask_value(entity_type, normalized),
        "summary": summary,
    }


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

def entity_summary(
    conn: sqlite3.Connection,
    entity_type: str,
    value: str,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    settings = settings or {}
    decay_days = int(settings.get("report_decay_days", 180))
    confirm_reporters = int(settings.get("report_confirm_reporters", 3))
    confirm_evidence = int(settings.get("report_confirm_evidence", 1))

    cutoff = (datetime.now(timezone.utc) - timedelta(days=max(0, decay_days))).isoformat(
        timespec="seconds"
    )
    rows = conn.execute(
        "SELECT id, reporter_hash, pattern_id, status, created_at FROM reports "
        "WHERE entity_type=? AND normalized_value=? AND created_at >= ? ORDER BY created_at ASC",
        (entity_type, value, cutoff),
    ).fetchall()

    active = [row for row in rows if row["status"] != "rejected"]
    reporters = {row["reporter_hash"] for row in active if row["reporter_hash"]}
    pattern_ids = sorted({row["pattern_id"] for row in active if row["pattern_id"]})

    evidence_count = 0
    if active:
        placeholders = ",".join("?" for _ in active)
        ids = [int(row["id"]) for row in active]
        evidence_count = int(
            conn.execute(
                f"SELECT COUNT(*) AS n FROM report_evidence WHERE report_id IN ({placeholders})",
                ids,
            ).fetchone()["n"]
        )

    disputed = any(row["status"] == "disputed" for row in active)
    if not active:
        status = "none"
    elif disputed:
        status = "disputed"
    elif len(reporters) >= confirm_reporters and evidence_count >= confirm_evidence:
        status = "confirmed"
    else:
        status = "unverified"

    return {
        "status": status,
        "reporters": len(reporters),
        "evidence": evidence_count,
        "patterns": pattern_ids,
        "first_report": active[0]["created_at"] if active else None,
        "last_report": active[-1]["created_at"] if active else None,
        "total_reports": len(active),
    }


def status_note(entity_type: str, summary: dict[str, Any]) -> str:
    """Human-readable, label-policy-safe description of report status."""
    kind = {"account": "Nomor rekening", "phone": "Nomor telepon", "domain": "Domain"}.get(
        entity_type, "Entitas"
    )
    status = summary.get("status")
    if status == "confirmed":
        return (
            f"{kind} ini pernah dilaporkan oleh {summary['reporters']} pengguna independen "
            f"dengan bukti (terakhir: {summary['last_report']})."
        )
    if status == "unverified":
        return (
            f"{kind} ini pernah dilaporkan oleh {summary['reporters']} pengguna "
            f"(belum terverifikasi penuh; terakhir: {summary['last_report']})."
        )
    if status == "disputed":
        return f"Ada laporan yang sedang disengketakan untuk {kind.lower()} ini."
    return "Belum pernah dilaporkan — ini bukan berarti aman."


# --------------------------------------------------------------------------- #
# Moderation (operator CLI)
# --------------------------------------------------------------------------- #

def set_status(conn: sqlite3.Connection, report_id: int, status: str) -> bool:
    status = (status or "").strip().lower()
    if status not in MODERATION_STATUSES:
        raise ReportError(f"status harus salah satu dari: {', '.join(MODERATION_STATUSES)}")
    cursor = conn.execute(
        "UPDATE reports SET status=?, updated_at=? WHERE id=?",
        (status, store.utcnow(), int(report_id)),
    )
    return cursor.rowcount > 0


def get_report(conn: sqlite3.Connection, report_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT id, entity_type, normalized_value, bank, pattern_id, note, status, created_at, updated_at "
        "FROM reports WHERE id=?",
        (int(report_id),),
    ).fetchone()
    if row is None:
        return None
    report = dict(row)
    evidence = conn.execute(
        "SELECT ref, created_at FROM report_evidence WHERE report_id=? ORDER BY id", (int(report_id),)
    ).fetchall()
    report["evidence"] = [dict(item) for item in evidence]
    return report


def list_reports(
    conn: sqlite3.Connection,
    *,
    status: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    sql = "SELECT id, entity_type, normalized_value, bank, pattern_id, status, created_at FROM reports"
    params: list[Any] = []
    if status:
        sql += " WHERE status=?"
        params.append(status.strip().lower())
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, int(limit)))
    rows = conn.execute(sql, params).fetchall()
    return [
        {
            "id": int(row["id"]),
            "entity_type": row["entity_type"],
            "masked_value": mask_value(row["entity_type"], row["normalized_value"]),
            "bank": row["bank"],
            "pattern_id": row["pattern_id"],
            "status": row["status"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]
