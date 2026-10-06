"""Offline evaluation harness: recall and false-positive rate on a labeled corpus.

Corpus format: JSONL, one object per line — ``{"text": "...", "label": "scam"}``
with ``label`` in ``{"scam", "legit"}``. The harness runs the same
deterministic pipeline as ``scampi_check``, records nothing, and reports the
metrics the spec weighs heaviest: scam recall first, false positives second.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from . import analysis, store
from . import settings as settings_mod

_MAX_REPORTED_CASES = 10


def load_corpus(path: Path, limit: int | None = None) -> list[dict[str, str]]:
    cases: list[dict[str, str]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                case = json.loads(line)
            except json.JSONDecodeError:
                continue
            text = str(case.get("text") or "").strip()
            label = str(case.get("label") or "").strip().lower()
            if not text or label not in ("scam", "legit"):
                continue
            cases.append({"text": text, "label": label})
            if limit and len(cases) >= limit:
                break
    return cases


def run(
    dataset_path: Path,
    *,
    limit: int | None = None,
    network: bool = False,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    cases = load_corpus(Path(dataset_path), limit=limit)
    config = settings_mod.load()
    config["network_enabled"] = bool(network)

    metrics: dict[str, Any] = {
        "total": len(cases),
        "scam_total": 0,
        "scam_detected": 0,
        "legit_total": 0,
        "legit_flagged": 0,
        "misses": [],
        "false_positives": [],
    }

    own_connection = conn is None
    connection = conn if conn is not None else store.connect()
    try:
        for case in cases:
            payload = analysis.run_check({"text": case["text"]}, config, connection)
            detected = payload["verdict"] != "no_red_flags"
            if case["label"] == "scam":
                metrics["scam_total"] += 1
                if detected:
                    metrics["scam_detected"] += 1
                elif len(metrics["misses"]) < _MAX_REPORTED_CASES:
                    metrics["misses"].append({"text": case["text"][:160], "verdict": payload["verdict"]})
            else:
                metrics["legit_total"] += 1
                if detected:
                    metrics["legit_flagged"] += 1
                    if len(metrics["false_positives"]) < _MAX_REPORTED_CASES:
                        metrics["false_positives"].append(
                            {
                                "text": case["text"][:160],
                                "verdict": payload["verdict"],
                                "reasons": [reason["label"] for reason in payload["reasons"][:3]],
                            }
                        )
    finally:
        if own_connection:
            connection.close()

    metrics["recall"] = (
        round(metrics["scam_detected"] / metrics["scam_total"], 3) if metrics["scam_total"] else None
    )
    metrics["false_positive_rate"] = (
        round(metrics["legit_flagged"] / metrics["legit_total"], 3) if metrics["legit_total"] else None
    )
    return metrics


def format_report(metrics: dict[str, Any]) -> str:
    lines = [
        "Scampi eval — korpus berlabel",
        f"Total kasus      : {metrics['total']}",
        f"Scam recall      : {metrics['scam_detected']}/{metrics['scam_total']} "
        f"({_pct(metrics['recall'])})",
        f"False positives  : {metrics['legit_flagged']}/{metrics['legit_total']} "
        f"({_pct(metrics['false_positive_rate'])})",
    ]
    if metrics["misses"]:
        lines.append("")
        lines.append("Scam yang terlewat:")
        for item in metrics["misses"]:
            lines.append(f"  - [{item['verdict']}] {item['text']}")
    if metrics["false_positives"]:
        lines.append("")
        lines.append("Pesan wajar yang ditandai:")
        for item in metrics["false_positives"]:
            reasons = "; ".join(item["reasons"]) or "-"
            lines.append(f"  - [{item['verdict']}] {item['text']} ({reasons})")
    return "\n".join(lines)


def _pct(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{round(value * 100)}%"
