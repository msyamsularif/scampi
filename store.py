"""SQLite storage: reports, evidence references, feedback, checks, cache, limits.

One database per profile, created on first use. WAL mode plus a fresh
connection per call (Hermes runs multiple threads) keeps this safe without a
pool. Callers use :func:`connection` as a context manager.

The ``checks`` table stores only a hash of the analyzed input, never the
message itself — that is the spec's "message content is not stored" rule,
expressed in the schema.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import runtime

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

_DDL = """
CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_type TEXT NOT NULL,
  normalized_value TEXT NOT NULL,
  bank TEXT NOT NULL DEFAULT '',
  reporter_hash TEXT NOT NULL,
  pattern_id TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'unverified',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_entity ON reports(entity_type, normalized_value);
CREATE INDEX IF NOT EXISTS idx_reports_reporter ON reports(reporter_hash, entity_type, normalized_value);
CREATE TABLE IF NOT EXISTS report_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  ref TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_report ON report_evidence(report_id);
CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  check_id TEXT NOT NULL DEFAULT '',
  verdict TEXT NOT NULL DEFAULT '',
  accurate INTEGER,
  note TEXT NOT NULL DEFAULT '',
  reporter_hash TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checks (
  id TEXT PRIMARY KEY,
  input_hash TEXT NOT NULL,
  verdict TEXT NOT NULL DEFAULT '',
  score REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS link_cache (
  cache_key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limits (
  identity_key TEXT NOT NULL,
  bucket TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (identity_key, bucket, window_start)
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: Path | None = None) -> sqlite3.Connection:
    resolved = Path(path) if path else runtime.db_path()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(resolved), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    init_db(conn)
    # Commit bootstrap writes immediately: a later connection must be able to
    # see the schema and never fight an uncommitted first-run transaction.
    conn.commit()
    return conn


@contextmanager
def connection(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    conn = connect(path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    row = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
    if row is not None:
        return
    conn.executescript(_DDL)
    conn.execute(
        "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )


# --------------------------------------------------------------------------- #
# Checks (hash-only) and provider cache
# --------------------------------------------------------------------------- #

def record_check(conn: sqlite3.Connection, check_id: str, input_hash: str, verdict: str, score: float) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO checks(id, input_hash, verdict, score, created_at) VALUES(?,?,?,?,?)",
        (check_id, input_hash, verdict, score, utcnow()),
    )


def cache_get(conn: sqlite3.Connection, key: str, ttl_hours: int) -> Any | None:
    row = conn.execute("SELECT value, created_at FROM link_cache WHERE cache_key=?", (key,)).fetchone()
    if row is None:
        return None
    if time.time() - int(row["created_at"]) > max(0, ttl_hours) * 3600:
        return None
    try:
        return json.loads(row["value"])
    except json.JSONDecodeError:  # pragma: no cover - defensive
        return None


def cache_set(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO link_cache(cache_key, value, created_at) VALUES(?,?,?)",
        (key, json.dumps(value, ensure_ascii=False), int(time.time())),
    )


# --------------------------------------------------------------------------- #
# Rate limiting (fixed window per identity and bucket)
# --------------------------------------------------------------------------- #

def rate_hit(
    conn: sqlite3.Connection,
    identity_key: str,
    bucket: str,
    limit: int,
    window_seconds: int,
) -> tuple[bool, int, int]:
    """Count one hit. Returns ``(allowed, remaining, retry_after_seconds)``."""
    now = int(time.time())
    window_start = now - (now % max(1, window_seconds))

    row = conn.execute(
        "SELECT count FROM rate_limits WHERE identity_key=? AND bucket=? AND window_start=?",
        (identity_key, bucket, window_start),
    ).fetchone()
    current = int(row["count"]) if row else 0

    if current >= limit:
        retry_after = window_start + window_seconds - now
        return False, 0, max(1, retry_after)

    conn.execute(
        "INSERT INTO rate_limits(identity_key, bucket, window_start, count) VALUES(?,?,?,1) "
        "ON CONFLICT(identity_key, bucket, window_start) DO UPDATE SET count = count + 1",
        (identity_key, bucket, window_start),
    )
    # Opportunistic prune: windows older than two days can never be consulted.
    conn.execute("DELETE FROM rate_limits WHERE window_start < ?", (now - 2 * 86400,))
    return True, max(0, limit - current - 1), 0


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #

def purge(conn: sqlite3.Connection, retention_days: int, evidence_dir: Path | None = None) -> dict[str, int]:
    """Delete aged artifacts. Report rows survive; their personal note does not."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max(0, retention_days))).isoformat(
        timespec="seconds"
    )
    cutoff_epoch = int(time.time()) - max(0, retention_days) * 86400
    counts: dict[str, int] = {}

    counts["evidence"] = conn.execute(
        "DELETE FROM report_evidence WHERE created_at < ?", (cutoff,)
    ).rowcount
    counts["checks"] = conn.execute("DELETE FROM checks WHERE created_at < ?", (cutoff,)).rowcount
    counts["feedback"] = conn.execute("DELETE FROM feedback WHERE created_at < ?", (cutoff,)).rowcount
    counts["notes_cleared"] = conn.execute(
        "UPDATE reports SET note='' WHERE note != '' AND created_at < ?", (cutoff,)
    ).rowcount
    counts["cache"] = conn.execute("DELETE FROM link_cache WHERE created_at < ?", (cutoff_epoch,)).rowcount
    counts["rate_windows"] = conn.execute(
        "DELETE FROM rate_limits WHERE window_start < ?", (cutoff_epoch,)
    ).rowcount

    if evidence_dir is not None and evidence_dir.is_dir():
        removed = 0
        for child in evidence_dir.iterdir():
            try:
                if child.is_file() and child.stat().st_mtime < time.time() - max(0, retention_days) * 86400:
                    child.unlink(missing_ok=True)
                    removed += 1
            except OSError:  # pragma: no cover - filesystem race
                continue
        counts["evidence_files"] = removed

    return counts
