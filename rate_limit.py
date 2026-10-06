"""Per-identity rate limiting, backed by :mod:`store`.

Fixed windows are deliberate: predictable for the user ("20 cek per jam"),
trivial to reason about, and cheap in SQLite. The limit message always says
which window was exhausted and how long to wait.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from . import store

BUCKET_CHECKS = "checks"
BUCKET_REPORTS = "reports"


def check(
    conn: sqlite3.Connection,
    identity_key: str,
    bucket: str,
    limit: int,
    window_seconds: int,
) -> dict[str, Any]:
    allowed, remaining, retry_after = store.rate_hit(
        conn, identity_key, bucket, max(1, limit), max(1, window_seconds)
    )
    return {
        "allowed": allowed,
        "remaining": remaining,
        "retry_after_seconds": retry_after,
        "limit": limit,
        "window_seconds": window_seconds,
    }


def limit_message(bucket: str, result: dict[str, Any]) -> str:
    minutes = max(1, int(round(result["retry_after_seconds"] / 60)))
    if bucket == BUCKET_REPORTS:
        return (
            "Batas laporan harian tercapai. Coba lagi sekitar "
            f"{minutes} menit lagi, atau lanjutkan besok."
        )
    return (
        "Batas pengecekan tercapai untuk jam ini. Coba lagi sekitar "
        f"{minutes} menit lagi."
    )
