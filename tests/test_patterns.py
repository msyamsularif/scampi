"""Pattern database loading, validation, and deterministic matching."""

from __future__ import annotations

from scampi import patterns


def test_all_shipped_patterns_valid():
    loaded = patterns.load_patterns()
    assert len(loaded) >= 12
    ids = [pattern.id for pattern in loaded]
    assert len(ids) == len(set(ids))
    for pattern in loaded:
        assert pattern.groups
        assert pattern.red_flags
        assert pattern.correct_response
        assert pattern.strength in ("strong", "medium")


def test_schema_validation_rejects_broken():
    assert patterns.validate({"id": "x"}) != []
    errors = patterns.validate(
        {
            "id": "x",
            "name": "n",
            "description": "d",
            "red_flags": ["satu"],
            "match": {"groups": [[]], "strength": "huge"},
            "correct_response": [],
        }
    )
    assert errors


def test_match_wedding_sample():
    loaded = patterns.load_patterns()
    matches = patterns.match(loaded, "undangan pernikahan: cek undangan.apk di sini")
    assert matches
    assert matches[0].pattern.id == "undangan-pernikahan-apk"


def test_match_benign_empty():
    loaded = patterns.load_patterns()
    assert patterns.match(loaded, "halo apa kabar? besok kita makan siang ya") == []


def test_matches_sorted_strong_first_then_id():
    loaded = patterns.load_patterns()
    matches = patterns.match(loaded, "paket gagal dikirim, undangan pernikahan apk")
    assert len(matches) >= 2
    strengths = [match.pattern.strength for match in matches]
    assert strengths == sorted(strengths, key=lambda value: 0 if value == "strong" else 1)
