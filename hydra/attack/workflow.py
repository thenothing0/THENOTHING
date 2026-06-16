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
from hydra.attack.evidence import EvidenceCollector
from hydra.attack.payloads import PayloadContext, PayloadLibrary, VulnClass


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
}


class AttackWorkflow:
    def __init__(self, gate=None, executor: Optional[Callable[[Dict], Dict]] = None,
                 library: Optional[PayloadLibrary] = None,
                 chains: Optional[ChainTemplateEngine] = None,
                 evidence: Optional[EvidenceCollector] = None):
        if gate is None:
            from hydra.authorization import BugBountyAuthorizationGate
            gate = BugBountyAuthorizationGate()
        self.gate = gate
        self.executor = executor or DryRunExecutor()
        self.library = library or PayloadLibrary()
        self.chains = chains or ChainTemplateEngine()
        self.evidence = evidence or EvidenceCollector()

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
