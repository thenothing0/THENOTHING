"""
Active out-of-band testers (audit improvement #2 — runtime/I-O).

Blind SSRF / XXE / OOB command-injection are invisible to in-band differential analysis, so the audit
flagged that the OOB infrastructure existed but was never wired into an ACTIVE tester. `OOBAttackTester`
closes that: it mints a per-finding correlation token, injects OOB payloads that embed the callback
(SSRF/cmdi into discovered injection points; XXE as an XML body), sends them through the GATED, rate-
limited executor, then polls the operator's OWN collaborator and correlates received interactions →
confirmed blind finding.

Gated (deny-by-default; the executor re-verifies per request), PoC-only (the payload just causes a
benign callback — no exfiltration), and it talks only to the target + the operator-supplied OOB server.
"""

from __future__ import annotations

import time
from typing import Callable, Dict, List, Optional

from hydra.attack.injection_points import InjectionPointFinder
from hydra.attack.oob import ListenerConfig, OOBCorrelator

_BODY_CLASSES = {"xxe", "deserialization"}


class OOBAttackTester:
    def __init__(self, gate=None, executor=None, correlator: Optional[OOBCorrelator] = None,
                 poller: Optional[Callable[[], List[Dict]]] = None,
                 oob_domain: str = "oob.invalid", finder: Optional[InjectionPointFinder] = None):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate
        if executor is None:
            from hydra.attack_runtime import HttpExecutor
            executor = HttpExecutor(gate=gate)
        self.executor = executor
        self.correlator = correlator or OOBCorrelator(ListenerConfig(oob_domain=oob_domain))
        self.poller = poller
        self.finder = finder or InjectionPointFinder()

    def _send(self, target: str, vuln_class: str, payloads: List[Dict]) -> int:
        sent = 0
        if vuln_class in _BODY_CLASSES:                       # XXE/deserialization → request body
            ctype = "application/xml" if vuln_class == "xxe" else "application/octet-stream"
            for p in payloads:
                self.executor({"method": "POST", "url": target,
                               "headers": {"Content-Type": ctype},
                               "body": p["value"], "payload": p["value"]})
                sent += 1
        else:                                                 # SSRF/cmdi → injection points
            base = {"method": "GET", "url": target, "headers": {}}
            points = self.finder.find(base)[:8]
            if not points:
                from hydra.attack.injection_points import _with_query
                points = [type("P", (), {"apply": staticmethod(
                    lambda v: _with_query(base, "url", v))})()]
            for pt in points:
                for p in payloads:
                    req = pt.apply(p["value"])
                    req["payload"] = p["value"]
                    self.executor(req)
                    sent += 1
        return sent

    def test(self, target: str, vuln_class: str, finding_id: str = "poc",
             poll_wait: float = 0.0, max_payloads: int = 4) -> Dict:
        vc = vuln_class.lower()
        decision = self.gate.authorize(target, "exploitation")
        if not decision.authorized:
            return {"authorized": False, "reason": decision.reason, "advisory": True}
        token = self.correlator.mint(finding_id, vc)
        payloads = self.correlator.payloads(vc, token.callback_url)[:max(1, max_payloads)]
        if not payloads:
            return {"authorized": True, "error": f"no OOB payloads for '{vc}'",
                    "supported": ["ssrf", "xxe", "xss", "sqli", "cmdi"], "advisory": True}
        sent = self._send(target, vc, payloads)
        if poll_wait > 0:
            time.sleep(min(poll_wait, 30.0))                  # bounded wait for async callbacks
        interactions: List[Dict] = []
        if self.poller is not None:
            try:
                interactions = self.poller() or []
            except Exception:
                interactions = []
        correlation = self.correlator.correlate(interactions)
        return {
            "target": target, "vuln_class": vc, "authorized": True, "poc_only": True,
            "oob_callback": token.callback_url, "payloads_sent": sent,
            "confirmed": correlation["count"] > 0,
            "confirmed_blind_findings": correlation["confirmed_blind_findings"],
            "note": "blind finding CONFIRMED when an out-of-band interaction returns to your "
                    "collaborator for the issued token",
            "advisory": True,
        }
