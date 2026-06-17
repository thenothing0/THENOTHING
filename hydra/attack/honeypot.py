"""
Honeypot / trap-response guard (improvement #3 — fewer false positives).

A trap (or a static "vulnerable-looking" template, or a deception page) returns success-shaped content
for ANY input — so a naive scanner "confirms" every payload. `HoneypotGuard` sends a BENIGN, never-
injected token through the same injection point and asks the differential detector what it sees: if a
class-CONFIRMING signal (a SQL error, an /etc/passwd marker, a 7*7 evaluation, an off-host redirect,
or a time delay) fires for harmless input, the endpoint is a trap and its "confirmations" must be
downgraded to `suspected`. Plain reflection of a benign token is NORMAL (that's just a reflective sink)
and is deliberately NOT treated as a trap signal.

Pure logic over the detector + an injected probe; deterministic; no I/O of its own (the executor is
passed in). Complements the platform's infrastructure-level `hydra.deception` engine (which scores
honeypot hosts) by guarding the in-band scan verdict specifically.
"""

from __future__ import annotations

from typing import Callable, Dict, Tuple

# Signal KINDS that should NEVER fire for benign, non-payload input — their presence means the endpoint
# returns canned "vulnerable" content regardless of what you send (trap / static template).
_TRAP_KINDS = {"file_marker", "error_signature", "timing", "redirect_location", "marker"}


class HoneypotGuard:
    def __init__(self, benign_token: str = "hydrabenignprobe7"):
        self.benign_token = benign_token

    def probe(self, detector, vuln_class: str, baseline: Dict,
              point_apply: Callable[[str], Dict], executor) -> Tuple[bool, str]:
        """Send a benign token through the point; trap if a class-confirming signal fires for it."""
        try:
            resp = executor({**point_apply(self.benign_token), "payload": self.benign_token,
                             "vuln_class": vuln_class})
        except Exception as e:
            return False, f"trap probe skipped: {e}"
        if not resp.get("executed"):
            return False, "trap probe not executed"
        signals = detector.signals(vuln_class, baseline, self.benign_token, resp)
        tripped = sorted({s.kind for s in signals if s.kind in _TRAP_KINDS})
        if tripped:
            return True, f"benign input triggered confirming signal(s) {tripped} → trap/static page"
        return False, "no trap signal for benign input"
