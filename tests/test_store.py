"""Storage: schema, cache TTL, rate windows, retention purge."""

from __future__ import annotations

from scampi import store


def test_connect_is_idempotent():
    first = store.connect()
    first.close()
    with store.connection() as conn:
        row = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        assert row["value"] == str(store.SCHEMA_VERSION)


def test_record_check_stores_hash_only(conn):
    store.record_check(conn, "abc123", "hashvalue", "caution", 4.0)
    row = conn.execute("SELECT * FROM checks WHERE id='abc123'").fetchone()
    assert row["input_hash"] == "hashvalue"
    assert "text" not in row


def test_cache_roundtrip_and_ttl(conn):
    store.cache_set(conn, "key", {"a": 1})
    assert store.cache_get(conn, "key", 24) == {"a": 1}
    assert store.cache_get(conn, "key", 0) is None


def test_cache_missing(conn):
    assert store.cache_get(conn, "nope", 24) is None


def test_rate_limit_windows(conn):
    allowed, remaining, _ = store.rate_hit(conn, "user:1", "checks", 2, 3600)
    assert allowed and remaining == 1
    allowed, remaining, _ = store.rate_hit(conn, "user:1", "checks", 2, 3600)
    assert allowed and remaining == 0
    allowed, remaining, retry_after = store.rate_hit(conn, "user:1", "checks", 2, 3600)
    assert not allowed
    assert remaining == 0
    assert retry_after > 0


def test_purge_clears_old_rows_keeps_reports(conn):
    conn.execute(
        "INSERT INTO checks(id, input_hash, verdict, score, created_at) "
        "VALUES('old','h','caution',1.0,'2020-01-01T00:00:00+00:00')"
    )
    conn.execute(
        "INSERT INTO reports(entity_type, normalized_value, bank, reporter_hash, pattern_id, note, status, "
        "created_at, updated_at) VALUES('account','123','BCA','r','p','catatan lama','unverified',"
        "'2020-01-01T00:00:00+00:00','2020-01-01T00:00:00+00:00')"
    )
    counts = store.purge(conn, retention_days=30)
    assert counts["checks"] == 1
    assert counts["notes_cleared"] == 1
    kept = conn.execute("SELECT note FROM reports WHERE normalized_value='123'").fetchone()
    assert kept is not None
    assert kept["note"] == ""
