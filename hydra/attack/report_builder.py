"""
Submission report builder + attack memory (attack section improvement #7).

`AttackReporter` turns confirmed/suspected evidence into a submission-ready report following the
project's report structure (executive summary → findings → PoC → honest assessment → chaining →
impact/severity → remediation), with severity calibration (a confirmed chain elevates severity) and an
explicit confirmed-vs-suspected split. `record_outcome` persists each result per target to the
existing `attack_memory.jsonl` so re-runs don't repeat work and the platform learns across targets.
Pure formatting + append-only memory (no network).
"""

from __future__ import annotations

from typing import Dict, List, Optional

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CLASS_SEVERITY = {"sqli": "high", "cmdi": "critical", "xxe": "high", "ssrf": "high",
                   "xss": "medium", "idor": "high", "ssti": "high", "lfi": "high",
                   "path_traversal": "medium", "open_redirect": "low", "crlf": "low"}
_REMEDIATION = {
    "xss": "Context-aware output encoding + CSP; never reflect untrusted input unescaped.",
    "sqli": "Parameterized queries / prepared statements; least-privilege DB user.",
    "ssrf": "Allowlist egress; block link-local/metadata ranges; no user-controlled fetch targets.",
    "idor": "Enforce per-object authorization server-side; use unguessable, scoped references.",
    "open_redirect": "Allowlist redirect targets; never redirect to user-supplied absolute URLs.",
    "ssti": "Do not render user input as a template; sandbox the engine.",
    "lfi": "No user-controlled file paths; canonicalize + allowlist.",
    "cmdi": "Avoid shelling out with user input; use safe APIs / strict allowlists.",
}


def record_outcome(target: str, vuln_class: str, verdict: str, point: str = "",
                   evidence: Optional[Dict] = None) -> None:
    """Append an attack outcome to the existing attack-memory journal (best-effort, never raises)."""
    try:
        from hydra.skills.attack_memory import record_event
        record_event({"kind": "attack_outcome", "target": target, "vuln_class": vuln_class,
                      "verdict": verdict, "point": point,
                      "status": (evidence or {}).get("response", {}).get("status")})
    except Exception:
        pass


class AttackReporter:
    def _severity(self, vuln_class: str, chains: Optional[List[Dict]]) -> str:
        base = _CLASS_SEVERITY.get(vuln_class.lower(), "medium")
        if chains:
            best = max((_SEV_RANK.get(c.get("realized_severity", "info"), 0) for c in chains),
                       default=0)
            if best > _SEV_RANK[base]:
                return {v: k for k, v in _SEV_RANK.items()}[best]      # elevated by chaining
        return base

    def build(self, target: str, findings: List[Dict],
              chains: Optional[List[Dict]] = None) -> Dict:
        confirmed = [f for f in findings if f.get("verdict") == "confirmed"]
        suspected = [f for f in findings if f.get("verdict") == "suspected"]
        sections = []
        for f in confirmed:
            vc = f.get("vuln_class", "")
            ev = f.get("evidence") or {}
            sections.append({
                "vuln_class": vc, "verdict": "confirmed",
                "severity": self._severity(vc, chains),
                "injection_point": f.get("point", ""),
                "proof_of_concept": ev.get("curl", ""),
                "evidence_indicators": ev.get("indicators", []),
                "remediation": _REMEDIATION.get(vc, "Validate and constrain untrusted input."),
            })
        top_sev = max((_SEV_RANK[s["severity"]] for s in sections), default=0)
        return {
            "target": target,
            "executive_summary": (
                f"{len(confirmed)} confirmed and {len(suspected)} suspected finding(s) on {target}; "
                f"highest confirmed severity: {[k for k, v in _SEV_RANK.items() if v == top_sev][0]}."),
            "confirmed_findings": sections,
            "suspected_findings": [{"vuln_class": f.get("vuln_class"), "point": f.get("point", ""),
                                    "reason": (f.get("evidence") or {}).get("reason", "needs review")}
                                   for f in suspected],
            "chaining": chains or [],
            "honest_assessment": ("Confirmed findings are backed by differential/PoC evidence; "
                                  "suspected findings need manual verification before submission."),
            "overall_severity": [k for k, v in _SEV_RANK.items() if v == top_sev][0],
            "advisory": True,
        }
