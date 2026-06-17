"""
Guarded validate-then-exploit workflow (attack section, suggestion #1 — the keystone).

Ties the whole attack section together behind the bug-bounty authorization gate:

    finding + target
       → gate.require(target, "exploitation")      # DENY-BY-DEFAULT; raises if unauthorized
       → map to ATT&CK technique (Phase-T)          # explainability
       → select context-aware PoC payloads          # payloads.py
       → match exploit-chain templates               # chain_templates.py
       → (gated) execute via an injectable Executor   # default = DryRunExecutor (sends nothing)
       → capture reproducible evidence                # evidence.py
       → result: confirmed / suspected, PoC-only

The Executor is the single NETWORK boundary. The default `DryRunExecutor` performs NO I/O — it returns
the planned requests so the flow is fully testable offline. An operator injects a real executor (or
wires the existing MCP tools) to actually run against an AUTHORIZED target; even then every action is
PoC-only and the gate has already allowed it. Nothing here exfiltrates, destroys, or runs without
authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hydra.attack.chain_templates import ChainTemplateEngine
from hydra.attack.crawl_seed import CrawlSeeder
from hydra.attack.detection import (
    AccessControlAnalyzer,
    DifferentialDetector,
    is_waf_block,
)
from hydra.attack.evidence import EvidenceCollector
from hydra.attack.honeypot import HoneypotGuard
from hydra.attack.injection_points import InjectionPoint, InjectionPointFinder
from hydra.attack.payloads import PayloadContext, PayloadLibrary, VulnClass
from hydra.attack.report_builder import record_outcome
from hydra.attack.two_signal import Signal, TwoSignalConfirmer


def _inject_param(url: str, param: str, value: str) -> str:
    """Place the PoC payload into a query parameter (deterministic; preserves existing params)."""
    p = urlparse(url if "://" in url else f"https://{url}")
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(p._replace(query=urlencode(q)))


# Reflection-based classes: the payload echoed in the response body is a confirmation signal.
_REFLECTION_CLASSES = {"xss", "crlf", "lfi", "path_traversal", "open_redirect"}


def _verdict(vuln_class: str, payload: str, resp: Dict) -> Optional[bool]:
    """Basic, honest confirmation from a live response. None = suspected (needs manual review)."""
    vc = vuln_class.lower()
    body = resp.get("body_snippet") or ""
    if resp.get("reflected") and vc in _REFLECTION_CLASSES:
        return True
    if vc == "ssti" and "49" in body:                        # {{7*7}} evaluated
        return True
    if vc == "sqli" and (resp.get("elapsed_ms") or 0) >= 4500:  # time-based blind
        return True
    if vc == "open_redirect":
        loc = (resp.get("location") or "")
        if loc and ("evil.example.com" in loc or payload.strip("/") in loc):
            return True
    return None


class DryRunExecutor:
    """Default executor: plans the requests, sends NOTHING. Pure, offline, deterministic."""

    def __call__(self, request: Dict) -> Dict:
        return {"status": None, "length": None, "executed": False,
                "note": "dry-run — no request was sent", "request": request}


@dataclass
class AttackResult:
    target: str
    vuln_class: str
    authorized: bool
    technique: Optional[str]
    payloads: List[Dict]
    chains: List[Dict]
    evidence: Optional[Dict]
    executed: bool
    poc_only: bool
    reason: str
    audit_id: str = ""

    def to_dict(self) -> Dict:
        return {"target": self.target, "vuln_class": self.vuln_class,
                "authorized": self.authorized, "technique": self.technique,
                "payloads": self.payloads, "candidate_chains": self.chains,
                "evidence": self.evidence, "executed": self.executed, "poc_only": self.poc_only,
                "reason": self.reason, "audit_id": self.audit_id, "advisory": True}


# vuln class → a representative ATT&CK technique (Phase-T vocabulary), for explainability.
_VC_TECHNIQUE = {
    "sqli": "T1190", "xss": "T1190", "ssti": "T1190", "ssrf": "T1190", "xxe": "T1190",
    "idor": "T1190", "lfi": "T1190", "path_traversal": "T1083", "cmdi": "T1190",
    "open_redirect": "T1190", "crlf": "T1190",
    "nosqli": "T1190", "ldapi": "T1190", "prototype_pollution": "T1190",
}


class AttackWorkflow:
    def __init__(self, gate=None, executor: Optional[Callable[[Dict], Dict]] = None,
                 library: Optional[PayloadLibrary] = None,
                 chains: Optional[ChainTemplateEngine] = None,
                 evidence: Optional[EvidenceCollector] = None,
                 detector: Optional[DifferentialDetector] = None,
                 access: Optional[AccessControlAnalyzer] = None,
                 finder: Optional[InjectionPointFinder] = None,
                 browser_confirmer: Optional[Callable[[str], Dict]] = None,
                 oob_confirmer: Optional[Callable[[], Dict]] = None,
                 two_signal: Optional[TwoSignalConfirmer] = None):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate
        self.executor = executor or DryRunExecutor()
        self.library = library or PayloadLibrary()
        self.chains = chains or ChainTemplateEngine()
        self.evidence = evidence or EvidenceCollector()
        self.detector = detector or DifferentialDetector()
        self.access = access or AccessControlAnalyzer()
        self.finder = finder or InjectionPointFinder()
        self.browser_confirmer = browser_confirmer       # callable(url) -> {confirmed, screenshot}
        self.oob_confirmer = oob_confirmer                 # callable() -> correlation report
        self.two_signal = two_signal or TwoSignalConfirmer()

    def run(self, target: str, vuln_class: str,
            context: str = "any", findings: Optional[List[Dict]] = None,
            execute: bool = False, param: str = "q") -> AttackResult:
        # 1) DENY-BY-DEFAULT authorization (the hard gate).
        decision = self.gate.authorize(target, "exploitation")
        if not decision.authorized:
            return AttackResult(target=target, vuln_class=vuln_class, authorized=False,
                                technique=None, payloads=[], chains=[], evidence=None,
                                executed=False, poc_only=True, reason=decision.reason,
                                audit_id=decision.audit_id)

        # 2) ATT&CK technique (explainability).
        technique = _VC_TECHNIQUE.get(vuln_class.lower())

        # 3) Context-aware PoC payloads.
        payloads: List[Dict] = []
        if vuln_class.lower() in VulnClass._value2member_map_:
            try:
                ctx = PayloadContext(context)
            except ValueError:
                ctx = PayloadContext.ANY
            payloads = [p.to_dict()
                        for p in self.library.for_context(VulnClass(vuln_class.lower()), ctx)]

        # 4) Candidate exploit chains from any provided findings.
        chain_match = self.chains.match(findings or [{"vuln_class": vuln_class}])
        chains = chain_match["instantiable_chains"] + chain_match["partial_chains"]

        # 5) Gated execution boundary. The default DryRunExecutor sends nothing; an injected
        #    HttpExecutor actually sends the PoC payload (and re-checks authorization itself).
        evidence_dict = None
        executed = False
        if execute and payloads:
            p0 = payloads[0]
            req = {"method": "GET", "url": _inject_param(target, param, p0["value"]),
                   "headers": {}, "payload": p0["value"], "vuln_class": vuln_class}
            resp = self.executor(req)            # the ONLY network boundary
            executed = bool(resp.get("executed"))
            indicators = [p0["technique"]]
            if resp.get("reflected"):
                indicators.append("payload reflected in response")
            if resp.get("status") is not None:
                indicators.append(f"HTTP {resp.get('status')}")
            # The verdict comes ONLY from response evidence (reflection/timing), never from the mere
            # presence of indicators — pass an explicit bool so the collector does not infer.
            confirmed = _verdict(vuln_class, p0["value"], resp) is True
            bundle = self.evidence.capture(vuln_class, req, resp, indicators=indicators,
                                           confirmed=confirmed)
            evidence_dict = bundle.to_dict()

        return AttackResult(
            target=target, vuln_class=vuln_class, authorized=True, technique=technique,
            payloads=payloads, chains=chains, evidence=evidence_dict, executed=executed,
            poc_only=True,
            reason=f"AUTHORIZED (PoC-only) by '{decision.program}' — {len(payloads)} PoC payload(s), "
                   f"{chain_match['instantiable_count']} instantiable chain(s)",
            audit_id=decision.audit_id)

    def plan(self, target: str, vuln_class: str, context: str = "any",
             findings: Optional[List[Dict]] = None) -> Dict:
        """Authorization-gated attack PLAN (never executes — `execute=False`)."""
        return self.run(target, vuln_class, context, findings, execute=False).to_dict()

    def _default_point(self, base_req: Dict) -> InjectionPoint:
        def apply(v: str) -> Dict:
            r = dict(base_req)
            r["url"] = _inject_param(base_req["url"], "q", v)
            return r
        return InjectionPoint("query", "q", apply)

    def _baseline(self, pt: InjectionPoint, marker: str, samples: int) -> Dict:
        """Send the benign baseline `samples` times → annotate length jitter + status stability (#3),
        so the detector's length/status differentials don't fire on a noisy/dynamic page."""
        samples = max(1, samples)
        resps = [self.executor(pt.apply(marker)) for _ in range(samples)]
        base = dict(resps[-1])
        if samples > 1:
            lengths = [r.get("length") or 0 for r in resps]
            base["length_jitter"] = max(lengths) - min(lengths)
            base["status_unstable"] = len({r.get("status") for r in resps}) > 1
        return base

    def _boolean_signal(self, pt: InjectionPoint, vc: str):
        """Boolean-based blind SQLi (#3): a TRUE-condition vs FALSE-condition pair that diverges is a
        strong INDEPENDENT signal (behavioural family) — wires the detector's `boolean_blind` into the
        active loop so it can corroborate an error/timing hit into a confirmation."""
        tr = self.executor({**pt.apply("' AND '1'='1"), "payload": "' AND '1'='1", "vuln_class": vc})
        fr = self.executor({**pt.apply("' AND '1'='2"), "payload": "' AND '1'='2", "vuln_class": vc})
        differs, why = self.detector.boolean_blind(tr, fr)
        return Signal("boolean_pair", f"boolean-based blind ({why})") if differs else None

    def scan(self, target: str, vuln_class: str, context: str = "any", session=None,
             max_payloads: int = 8, max_points: int = 12, confirm_dom: bool = False,
             record: bool = False, baseline_marker: str = "hydrabaseline0",
             baseline_samples: int = 1, detect_traps: bool = True,
             boolean_blind: bool = True, fingerprint: str = "") -> Dict:
        """Differential multi-payload scan across injection points (improvements #1/#3/#4/#5/#7).

        Gated (deny-by-default). Samples a benign BASELINE (optionally several times for stability),
        guards against trap/honeypot endpoints, then iterates PoC payloads per injection point: confirms
        via the differential detector (two-signal), adds boolean-blind corroboration for SQLi and DOM
        execution for XSS, adapts to WAF blocks, early-exits a point on first confirmation. A trap
        endpoint downgrades confirmations to suspected. With the default DryRunExecutor it sends nothing
        (everything 'suspected')."""
        decision = self.gate.authorize(target, "exploitation")
        if not decision.authorized:
            return {"target": target, "vuln_class": vuln_class, "authorized": False,
                    "executed": False, "confirmed": False, "evidence": [],
                    "reason": decision.reason, "advisory": True}
        vc = vuln_class.lower()
        if vc not in VulnClass._value2member_map_:
            return {"target": target, "vuln_class": vuln_class, "authorized": True,
                    "error": f"unknown vuln_class '{vuln_class}'", "advisory": True}
        try:
            ctx = PayloadContext(context)
        except ValueError:
            ctx = PayloadContext.ANY
        payloads = self.library.for_context(VulnClass(vc), ctx)
        if fingerprint:                                  # #5 float stack-relevant payloads to the front
            from hydra.attack.fingerprint_select import FingerprintPayloadSelector
            order = FingerprintPayloadSelector().prioritize_payloads(
                vc, fingerprint, [p.value for p in payloads])
            rank = {v: i for i, v in enumerate(order)}
            payloads = sorted(payloads, key=lambda p: rank.get(p.value, 999))
        payloads = payloads[:max(1, max_payloads)]

        base_req = {"method": "GET", "url": target if "://" in target else f"https://{target}",
                    "headers": {}, "vuln_class": vc}
        if session is not None:
            base_req = session.apply(base_req)
        points = self.finder.find(base_req)[:max(1, max_points)] or [self._default_point(base_req)]

        guard = HoneypotGuard() if detect_traps else None
        confirmed, suspected, evidence = [], [], []
        executed_any = False
        traps = 0
        for pt in points:
            base_resp = self._baseline(pt, baseline_marker, baseline_samples)
            executed_any = executed_any or bool(base_resp.get("executed"))
            is_trap, trap_reason = (guard.probe(self.detector, vc, base_resp, pt.apply, self.executor)
                                    if guard else (False, ""))
            if is_trap:
                traps += 1
            bool_sig = (self._boolean_signal(pt, vc)
                        if (boolean_blind and vc == "sqli") else None)
            hit, best_single = False, None
            for p in payloads:
                req = {**pt.apply(p.value), "payload": p.value, "vuln_class": vc}
                resp = self.executor(req)
                if is_waf_block(resp):                       # #5 adapt: retry once mutated
                    mutated = self.library.waf_adapted(p.value)[1:2]
                    if mutated:
                        req = {**pt.apply(mutated[0]), "payload": mutated[0], "vuln_class": vc}
                        resp = self.executor(req)
                signals = self.detector.signals(vc, base_resp, req["payload"], resp)
                if bool_sig is not None:                     # #3 boolean-blind corroboration (sqli)
                    signals = signals + [bool_sig]
                # #3 second INDEPENDENT signal: confirm reflective XSS by real DOM execution
                if confirm_dom and vc == "xss" and self.browser_confirmer and \
                        any(s.kind == "reflection" for s in signals):
                    bc = self.browser_confirmer(req["url"]) or {}
                    if bc.get("confirmed"):
                        resp["dom_executed"] = True
                        signals = self.detector.signals(vc, base_resp, req["payload"], resp)
                        if bool_sig is not None:
                            signals = signals + [bool_sig]
                conf = self.two_signal.assess(signals)
                verdict = conf.verdict
                if verdict == "confirmed" and is_trap:       # #3 trap returns canned signals → demote
                    verdict = "single_signal"
                if verdict == "confirmed":                   # #1 TWO independent signals required
                    ev = self.evidence.capture(vc, req, resp,
                                               indicators=[s.detail for s in signals],
                                               confirmed=True).to_dict()
                    ev["injection_point"] = pt.describe()
                    ev["confirmation"] = conf.to_dict()
                    evidence.append(ev)
                    confirmed.append({"vuln_class": vc, "point": pt.name, "verdict": "confirmed",
                                      "evidence": ev})
                    if record:
                        record_outcome(target, vc, "confirmed", pt.name, ev)
                    hit = True
                    break                                    # early-exit this point
                if verdict == "single_signal" and best_single is None:
                    ev = self.evidence.capture(vc, req, resp,
                                               indicators=[s.detail for s in signals],
                                               confirmed=False).to_dict()
                    ev["injection_point"] = pt.describe()
                    ev["confirmation"] = conf.to_dict()
                    if is_trap:
                        ev["honeypot"] = True
                        ev["honeypot_reason"] = trap_reason
                    best_single = ev
            if not hit:
                row = {"vuln_class": vc, "point": pt.name, "verdict": "suspected",
                       "evidence": best_single}
                if is_trap:
                    row["honeypot"] = True
                    row["honeypot_reason"] = trap_reason
                suspected.append(row)

        return {"target": target, "vuln_class": vc, "authorized": True, "poc_only": True,
                "executed": executed_any, "confirmed": bool(confirmed),
                "confirmed_findings": confirmed, "suspected": suspected,
                "points_tested": len(points), "payloads_per_point": len(payloads),
                "honeypot_points": traps, "evidence": evidence,
                "reason": f"AUTHORIZED scan by '{decision.program}' — {len(confirmed)} confirmed"
                          + (f", {traps} trap point(s) demoted" if traps else ""),
                "advisory": True}

    def scan_many(self, urls: List[str], vuln_class: str, context: str = "any", session=None,
                  max_seeds: int = 25, max_payloads: int = 5, max_points: int = 8,
                  record: bool = False, confirm_dom: bool = False,
                  concurrency: int = 1, resume: bool = False, state=None) -> Dict:
        """Scan a CRAWL's worth of URLs (e.g. from katana/gau): de-dupe to distinct injectable
        endpoints, then run the gated differential scan on each. Every target is independently
        authorization-gated (deny-by-default).

        Robustness (#4): `concurrency` runs up to N (≤8) endpoints in parallel (the executor is the
        thread-safe, globally rate-limited boundary, so total traffic stays bounded); `resume` consults
        a cross-run `ScanState` to SKIP endpoints already scanned in a prior run and records progress.
        Results are returned in seed order regardless of concurrency (deterministic)."""
        seeds = CrawlSeeder().seeds(urls, max_seeds=max(1, max_seeds))
        vc = vuln_class.lower()
        if resume and state is None:
            from hydra.attack.scan_state import ScanState
            state = ScanState()

        to_scan, skipped = [], []
        for u in seeds:
            if state is not None and state.seen(u, vc):
                skipped.append(u)
            else:
                to_scan.append(u)

        def _one(u: str) -> Dict:
            r = self.scan(u, vuln_class, context, session=session, max_payloads=max_payloads,
                          max_points=max_points, record=record, confirm_dom=confirm_dom)
            if state is not None:
                state.mark(u, vc, "*", "confirmed" if r.get("confirmed") else "scanned")
            return r

        results: Dict[str, Dict] = {}
        workers = max(1, min(int(concurrency), 8))
        if workers > 1 and len(to_scan) > 1:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for u, r in zip(to_scan, pool.map(_one, to_scan)):
                    results[u] = r
        else:
            for u in to_scan:
                results[u] = _one(u)

        scanned, confirmed = [], []
        for u in to_scan:                                  # deterministic: seed/scan order
            r = results[u]
            scanned.append({"target": u, "authorized": r.get("authorized"),
                            "confirmed": r.get("confirmed", False),
                            "confirmed_findings": r.get("confirmed_findings", [])})
            confirmed.extend(r.get("confirmed_findings", []))
        return {"input_urls": len(urls), "distinct_seeds": len(seeds), "scanned": scanned,
                "skipped_already_scanned": skipped, "concurrency": workers,
                "confirmed": bool(confirmed), "confirmed_findings": confirmed,
                "vuln_class": vc, "poc_only": True, "advisory": True}

    def access_control_test(self, target: str, session_a, session_b,
                            owner_markers: Optional[List[str]] = None) -> Dict:
        """IDOR / broken access control (#2): fetch the SAME resource as two identities and diff."""
        decision = self.gate.authorize(target, "exploitation")
        if not decision.authorized:
            return {"target": target, "authorized": False, "reason": decision.reason,
                    "advisory": True}
        url = target if "://" in target else f"https://{target}"
        resp_a = self.executor(session_a.apply({"method": "GET", "url": url, "headers": {}}))
        resp_b = self.executor(session_b.apply({"method": "GET", "url": url, "headers": {}}))
        verdict, reason, signals = self.access.decide(resp_a, resp_b, owner_markers)
        return {"target": target, "authorized": True, "poc_only": True, "verdict": verdict,
                "reason": reason, "signals": signals, "identity_a": session_a.name,
                "identity_b": session_b.name, "advisory": True}
