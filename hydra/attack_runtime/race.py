"""
Race-condition testing (attack section improvement #3 — runtime/I/O, bounded concurrency).

Fires a BOUNDED number of concurrent identical requests at one endpoint and reports the outcome
distribution — the standard limit-overrun / TOCTOU detection (e.g. a single-use coupon redeemed N
times, a balance debited twice). Authorization-gated (each send re-verifies via the executor) and
bounded (≤ a hard cap) so it detects a race window without becoming load abuse. The verdict is
deliberately conservative: duplicate successes are a *candidate* the operator confirms against the
app's intended once-only semantics; it never auto-claims impact.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Dict

_HARD_CAP = 30


class RaceTester:
    def __init__(self, gate=None, executor=None):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate
        self._executor = executor          # optional shared executor (else one is built, rate 0)

    def test(self, request: Dict, n: int = 10) -> Dict:
        url = request.get("url", "")
        decision = self.gate.authorize(url, "exploitation")
        if not decision.authorized:
            return {"authorized": False, "reason": decision.reason, "advisory": True}
        n = max(2, min(int(n), _HARD_CAP))
        executor = self._executor or self._build_executor()
        with ThreadPoolExecutor(max_workers=n) as pool:
            results = list(pool.map(lambda _: executor(dict(request)), range(n)))

        executed = [r for r in results if r.get("executed")]
        success = [r for r in executed if (r.get("status") or 0) // 100 == 2]
        statuses: Dict[int, int] = {}
        for r in executed:
            s = r.get("status")
            statuses[s] = statuses.get(s, 0) + 1
        distinct_success_bodies = {r.get("body_snippet") for r in success}
        # candidate race: most concurrent requests succeeded identically (possible limit overrun)
        candidate = len(success) > 1 and len(distinct_success_bodies) <= 2
        return {
            "authorized": True, "requests": n, "executed": len(executed),
            "success_2xx": len(success), "status_distribution": {str(k): v for k, v in statuses.items()},
            "verdict": "candidate" if candidate else "suspected",
            "note": "bounded concurrency; a CANDIDATE race window — confirm against the app's "
                    "once-only intent. PoC-only; never amplifies/abuses the action.",
            "poc_only": True, "advisory": True,
        }

    def _build_executor(self):
        from hydra.attack_runtime import HttpExecutor
        return HttpExecutor(gate=self.gate, rate_per_sec=0)     # concurrent → no per-request sleep
