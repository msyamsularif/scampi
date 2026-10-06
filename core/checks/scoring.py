"""Score assembly: signals -> weight sum -> verdict band.

Pure functions only. The verdict is a function of (weights, thresholds) and
nothing else — no model, no randomness. Weights come from ``data/rules.yaml``;
thresholds come from plugin settings with the same defaults.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

VERDICT_NONE = "no_red_flags"
VERDICT_CAUTION = "caution"
VERDICT_SCAM = "likely_scam"


@dataclass(frozen=True)
class Signal:
    code: str
    weight: float
    label: str
    detail: str = ""
    source: str = "local"  # local | community | rdap | safe_browsing | urlhaus


def total(signals: Sequence[Signal]) -> float:
    return round(sum(signal.weight for signal in signals), 2)


def verdict_for(score: float, caution_threshold: float, scam_threshold: float) -> str:
    if score >= scam_threshold:
        return VERDICT_SCAM
    if score >= caution_threshold:
        return VERDICT_CAUTION
    return VERDICT_NONE
