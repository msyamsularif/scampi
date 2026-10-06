"""Corpus-level acceptance: recall first, false positives second (spec §16)."""

from __future__ import annotations

from scampi.core.checks import eval as eval_mod


def test_scam_corpus_meets_recall_target(corpus_dir):
    metrics = eval_mod.run(corpus_dir / "scam_messages.jsonl")
    assert metrics["scam_total"] == 20
    assert metrics["recall"] is not None
    assert metrics["recall"] >= 0.85, metrics


def test_legit_corpus_stays_under_false_positive_budget(corpus_dir):
    metrics = eval_mod.run(corpus_dir / "legit_messages.jsonl")
    assert metrics["legit_total"] == 20
    assert metrics["false_positive_rate"] is not None
    assert metrics["false_positive_rate"] <= 0.10, metrics


def test_format_report_mentions_both_metrics(corpus_dir):
    metrics = eval_mod.run(corpus_dir / "legit_messages.jsonl", limit=3)
    text = eval_mod.format_report(metrics)
    assert "recall" in text.lower()
    assert "False positives" in text
