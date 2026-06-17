"""
Exploit-chain templates + realized-severity elevation (attack section, suggestion #5).

Declarative templates for the classic high-value attack paths (SSRF→cloud-metadata→creds→admin,
IDOR→account-takeover, subdomain-takeover→cookie-scoping, open-redirect→OAuth-token-theft,
XXE→SSRF→metadata, LFI→RCE). `match(findings)` reports which templates are INSTANTIABLE from a set of
confirmed findings and elevates the realized severity (a chained P4 can land P2). Each template links
to ATT&CK techniques so a chain is explainable as an attack path. Declarative, deterministic, advisory;
chains are constructed/scored, never executed here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

# Severity ranks for elevation math (higher = worse). P-scale mirrors the bug-bounty rubric.
_SEV = {"info": 0, "p5": 0, "low": 1, "p4": 1, "medium": 2, "p3": 2,
        "high": 3, "p2": 3, "critical": 4, "p1": 4}
_RANK_SEV = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


@dataclass
class ChainTemplate:
    chain_id: str
    name: str
    stages: List[str]                       # ordered vuln classes / finding types
    realized_severity: str                  # severity if the full chain lands
    attack_techniques: List[str]            # ATT&CK ids (Phase-T vocabulary)
    rationale: str
    requires_all: bool = True               # all stages needed, vs best-effort partial

    def to_dict(self) -> Dict:
        return {"chain_id": self.chain_id, "name": self.name, "stages": self.stages,
                "realized_severity": self.realized_severity,
                "attack_techniques": self.attack_techniques, "rationale": self.rationale,
                "advisory": True}


CHAIN_TEMPLATES: List[ChainTemplate] = [
    ChainTemplate("ssrf_imds_takeover", "SSRF → cloud metadata → credentials → admin",
                  ["ssrf", "cloud_metadata", "credential"], "critical",
                  ["T1190", "T1552.005", "T1078"],
                  "SSRF reaches the instance metadata service, leaks IAM creds, escalates to console"),
    ChainTemplate("idor_ato", "IDOR → account takeover",
                  ["idor", "auth_bypass"], "high", ["T1190", "T1087"],
                  "object-id tampering exposes another user's session/PII → full ATO"),
    ChainTemplate("subdomain_takeover_cookie", "Subdomain takeover → cookie scoping → session theft",
                  ["takeover", "cors"], "high", ["T1190", "T1539"],
                  "dangling subdomain claimed, parent-scoped cookies/CORS leak sessions"),
    ChainTemplate("open_redirect_oauth", "Open redirect → OAuth token theft",
                  ["open_redirect", "auth_flow"], "high", ["T1190", "T1539"],
                  "redirect_uri abuse leaks the OAuth code/token to an attacker-controlled host"),
    ChainTemplate("xxe_ssrf_metadata", "XXE → SSRF → cloud metadata",
                  ["xxe", "ssrf", "cloud_metadata"], "critical", ["T1190", "T1552.005"],
                  "external-entity load pivots to internal metadata services"),
    ChainTemplate("lfi_rce", "LFI → RCE (log poisoning / wrapper)",
                  ["path_traversal", "info_disclosure"], "critical", ["T1190"],
                  "local file inclusion plus a writable/loggable sink yields code execution"),
    ChainTemplate("cors_credential_leak", "Permissive CORS → credentialed data leak",
                  ["cors", "info_disclosure"], "medium", ["T1190"],
                  "reflective CORS with credentials exposes authenticated responses cross-origin"),
    # auth-protocol / API-authz chains (improvement #5) — confirmed auth findings elevate to ATO.
    ChainTemplate("oauth_redirect_ato", "OAuth redirect_uri abuse → code/token theft → ATO",
                  ["oauth", "open_redirect"], "critical", ["T1190", "T1539", "T1550.001"],
                  "a honoured attacker redirect_uri leaks the OAuth code/token → full account takeover"),
    ChainTemplate("bola_ato", "BOLA → cross-account object access → account takeover",
                  ["bola", "auth_bypass"], "high", ["T1190", "T1087"],
                  "object-level authz gap exposes another user's data/session → ATO"),
    ChainTemplate("bfla_mass_assignment_privesc",
                  "BFLA → privileged function → mass assignment → privilege escalation",
                  ["bfla", "mass_assignment"], "critical", ["T1190", "T1068"],
                  "function-level authz gap plus privileged-field binding escalates a low-priv user"),
    ChainTemplate("saml_forgery_ato", "Unsigned/wrappable SAML → assertion forgery → ATO",
                  ["saml", "auth_bypass"], "critical", ["T1190", "T1606.002"],
                  "missing/wrappable SAML signature lets an attacker forge an assertion → ATO"),
]


def _finding_classes(findings: List[Dict]) -> set:
    out = set()
    for f in findings:
        for k in ("vuln_class", "type", "finding_type", "class"):
            if f.get(k):
                out.add(str(f[k]).lower())
    return out


class ChainTemplateEngine:
    def templates(self) -> List[Dict]:
        return [t.to_dict() for t in CHAIN_TEMPLATES]

    def match(self, findings: List[Dict]) -> Dict:
        present = _finding_classes(findings)
        max_finding_sev = max((_SEV.get(str(f.get("severity", "info")).lower(), 0)
                               for f in findings), default=0)
        matched, partial = [], []
        for t in CHAIN_TEMPLATES:
            have = [s for s in t.stages if s in present]
            if len(have) == len(t.stages):
                matched.append({**t.to_dict(), "matched_stages": have,
                                "severity_elevation": {
                                    "from": _RANK_SEV[max_finding_sev],
                                    "to": t.realized_severity,
                                    "elevated": _SEV.get(t.realized_severity, 0) > max_finding_sev}})
            elif len(have) >= 1:
                partial.append({"chain_id": t.chain_id, "name": t.name,
                                "have": have, "missing": [s for s in t.stages if s not in present],
                                "advisory": True})
        matched.sort(key=lambda c: (-_SEV.get(c["realized_severity"], 0), c["chain_id"]))
        return {"instantiable_chains": matched, "instantiable_count": len(matched),
                "partial_chains": partial, "advisory": True}

    def report(self, findings: Optional[List[Dict]] = None) -> Dict:
        if findings:
            out = self.match(findings)
            out["templates"] = self.templates()
            return out
        return {"templates": self.templates(), "count": len(CHAIN_TEMPLATES), "advisory": True}
