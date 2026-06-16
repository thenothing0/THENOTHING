"""
Two-signal confirmation (attack section improvement #1 — pure, network-free).

The platform's #1 validation principle is "two INDEPENDENT signals before elevating severity"
(CLAUDE.md). A single differential hit is easy to fake (a WAF challenge page, an error template, a
coincidental length change). `TwoSignalConfirmer` collects the signals observed for a finding and only
returns `confirmed` when at least two come from INDEPENDENT mechanisms (reflection vs DOM-execution vs
timing vs error vs out-of-band vs behavioural). One signal → `single_signal` (needs review). This is
the biggest false-positive killer and the thing that aligns the attack scanner with the rest of Hydra.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

CONFIRMED, SINGLE_SIGNAL, UNCONFIRMED = "confirmed", "single_signal", "unconfirmed"

# Independent signal families — two signals only count as corroboration if they are in DIFFERENT
# families (reflection + differential-length share a root cause; reflection + DOM-execution do not).
_FAMILY = {
    "reflection": "reflection", "marker": "reflection", "differential_length": "reflection",
    "dom_execution": "execution",
    "error_signature": "error",
    "timing": "timing",
    "boolean_pair": "behavioural", "differential_status": "behavioural",
    "oob_callback": "oob",
    "file_marker": "file_read",
    "redirect_location": "redirect",
}


@dataclass
class Signal:
    kind: str
    detail: str = ""

    @property
    def family(self) -> str:
        return _FAMILY.get(self.kind, self.kind)


@dataclass
class Confirmation:
    verdict: str
    signals: List[Signal] = field(default_factory=list)

    @property
    def families(self) -> List[str]:
        return sorted({s.family for s in self.signals})

    def to_dict(self) -> Dict:
        return {"verdict": self.verdict, "signal_count": len(self.signals),
                "independent_signals": len(self.families), "families": self.families,
                "signals": [{"kind": s.kind, "detail": s.detail} for s in self.signals],
                "advisory": True}


class TwoSignalConfirmer:
    def assess(self, signals: List[Signal]) -> Confirmation:
        families = {s.family for s in signals}
        if len(families) >= 2:
            verdict = CONFIRMED
        elif signals:
            verdict = SINGLE_SIGNAL
        else:
            verdict = UNCONFIRMED
        return Confirmation(verdict=verdict, signals=list(signals))
