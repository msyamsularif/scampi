"""Domain helper unit tests."""

from __future__ import annotations

from scampi.domains import levenshtein, registrable_domain


def test_registrable_domain_plain():
    assert registrable_domain("example.com") == "example.com"
    assert registrable_domain("www.example.com") == "example.com"
    assert registrable_domain("a.b.example.com") == "example.com"


def test_registrable_domain_indonesia():
    assert registrable_domain("bca.co.id") == "bca.co.id"
    assert registrable_domain("sub.bca.co.id") == "bca.co.id"
    assert registrable_domain("bca.co.id.") == "bca.co.id"


def test_registrable_domain_edge_cases():
    assert registrable_domain("") == ""
    assert registrable_domain("localhost") == "localhost"


def test_levenshtein_basics():
    assert levenshtein("bca", "bca") == 0
    assert levenshtein("bcaa", "bca") == 1
    assert levenshtein("bca", "bri") == 2
    assert levenshtein("", "abc") == 3
