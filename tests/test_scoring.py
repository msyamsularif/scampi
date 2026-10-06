"""Scoring: weight sum and verdict bands."""

from __future__ import annotations

from scampi import scoring


def test_total_sums_weights():
    signals = [
        scoring.Signal(code="a", weight=5.0, label="x"),
        scoring.Signal(code="b", weight=1.5, label="y"),
    ]
    assert scoring.total(signals) == 6.5


def test_verdict_bands_at_boundaries():
    assert scoring.verdict_for(0, 3, 6) == scoring.VERDICT_NONE
    assert scoring.verdict_for(2.99, 3, 6) == scoring.VERDICT_NONE
    assert scoring.verdict_for(3, 3, 6) == scoring.VERDICT_CAUTION
    assert scoring.verdict_for(5.99, 3, 6) == scoring.VERDICT_CAUTION
    assert scoring.verdict_for(6, 3, 6) == scoring.VERDICT_SCAM
