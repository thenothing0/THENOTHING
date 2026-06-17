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
                   "path_traversal": "medium", "open_redirect": "low", "crlf": "low",
                   "nosqli": "high", "ldapi": "high", "prototype_pollution": "high",
                   "bola": "high", "bfla": "high", "mass_assignment": "high",
                   "excessive_data_exposure": "medium", "oauth": "high", "saml": "high",
                   "csrf": "medium", "password_reset_poisoning": "high", "insecure_cookie": "low"}
_REMEDIATION = {
    "xss": "Context-aware output encoding + CSP; never reflect untrusted input unescaped.",
    "sqli": "Parameterized queries / prepared statements; least-privilege DB user.",
    "ssrf": "Allowlist egress; block link-local/metadata ranges; no user-controlled fetch targets.",
    "idor": "Enforce per-object authorization server-side; use unguessable, scoped references.",
    "open_redirect": "Allowlist redirect targets; never redirect to user-supplied absolute URLs.",
    "ssti": "Do not render user input as a template; sandbox the engine.",
    "lfi": "No user-controlled file paths; canonicalize + allowlist.",
    "cmdi": "Avoid shelling out with user input; use safe APIs / strict allowlists.",
    "nosqli": "Cast/validate input types; reject query operators; use parameterized queries.",
    "ldapi": "Escape LDAP metacharacters (RFC 4515); bind with least privilege; validate input.",
    "prototype_pollution": "Reject __proto__/constructor/prototype keys; use Map / null-prototype objects.",
    "bola": "Enforce per-object authorization server-side on every request; scope references to the caller.",
    "bfla": "Enforce function/role authorization server-side; default-deny privileged operations.",
    "mass_assignment": "Allowlist bindable fields; never bind privileged attributes from client input.",
    "excessive_data_exposure": "Return only client-needed fields; filter sensitive attributes server-side.",
    "oauth": "Strict redirect_uri allowlist; require state + PKCE; avoid implicit flow.",
    "saml": "Validate signatures over the whole assertion; reject unsigned/multi-assertion responses.",
    "csrf": "Require an unpredictable anti-CSRF token on state-changing requests; verify Origin/Referer.",
    "password_reset_poisoning": "Build reset links from a server-side allowlisted host; ignore Host/X-Forwarded-Host.",
    "insecure_cookie": "Set Secure + HttpOnly + SameSite on session cookies; scope Domain/Path tightly.",
}


def record_outcome(target: str, vuln_class: str, verdict: str, point: str = "",
                   evidence: Optional[Dict] = None) -> None:
    """Append an attack outcome to the existing attack-memory journal (best-effort, never raises)."""
    try:
        from hydra.skills.attack_memory import append_event
        append_event("attack_outcome", {"target": target, "vuln_class": vuln_class,
                                         "verdict": verdict, "point": point,
                                         "status": (evidence or {}).get("response", {}).get("status")})
    except Exception:
        pass


# CVSS 3.1 (base score, vector) + CWE per class — a defensible default the operator can refine.
_CVSS = {
    "sqli": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-89"),
    "cmdi": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-78"),
    "ssrf": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", "CWE-918"),
    "xxe": (8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L", "CWE-611"),
    "idor": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "CWE-639"),
    "ssti": (9.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", "CWE-1336"),
    "xss": (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "CWE-79"),
    "lfi": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-98"),
    "path_traversal": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-22"),
    "open_redirect": (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "CWE-601"),
    "crlf": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "CWE-93"),
    "jwt": (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-347"),
    "cors": (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", "CWE-942"),
    "graphql": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-200"),
    "nosqli": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-943"),
    "ldapi": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-90"),
    "prototype_pollution": (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "CWE-1321"),
    "bola": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "CWE-639"),
    "bfla": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "CWE-285"),
    "mass_assignment": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "CWE-915"),
    "excessive_data_exposure": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-213"),
    "oauth": (8.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", "CWE-601"),
    "saml": (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-347"),
    "csrf": (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N", "CWE-352"),
    "password_reset_poisoning": (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "CWE-640"),
    "insecure_cookie": (4.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", "CWE-614"),
}


class AttackReporter:
    def _severity(self, vuln_class: str, chains: Optional[List[Dict]]) -> str:
        base = _CLASS_SEVERITY.get(vuln_class.lower(), "medium")
        if chains:
            best = max((_SEV_RANK.get(c.get("realized_severity", "info"), 0) for c in chains),
                       default=0)
            if best > _SEV_RANK[base]:
                return {v: k for k, v in _SEV_RANK.items()}[best]      # elevated by chaining
        return base

    @staticmethod
    def cvss(vuln_class: str) -> Dict:
        score, vector, cwe = _CVSS.get(vuln_class.lower(), (5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                                                            "S:U/C:L/I:L/A:N", "CWE-20"))
        return {"score": score, "vector": vector, "cwe": cwe}

    @staticmethod
    def dedup(findings: List[Dict]) -> List[Dict]:
        seen, out = set(), []
        for f in findings:
            key = (str(f.get("vuln_class", "")).lower(), f.get("point", ""), f.get("verdict", ""))
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out

    def to_markdown(self, report: Dict, platform: str = "hackerone") -> str:
        lines = [f"# {report.get('overall_severity', 'medium').title()} — "
                 f"{len(report.get('confirmed_findings', []))} confirmed finding(s) on "
                 f"{report.get('target', '')}", "", "## Summary", report.get("executive_summary", ""),
                 ""]
        for s in report.get("confirmed_findings", []):
            c = s.get("cvss", {})
            lines += [f"## {s.get('vuln_class', '').upper()} — {s.get('severity', '')} "
                      f"(CVSS {c.get('score', '')} · {c.get('cwe', '')})",
                      f"- **Injection point:** {s.get('injection_point', '')}",
                      f"- **CVSS:** `{c.get('vector', '')}`",
                      "- **Proof of concept:**", "```bash", s.get("proof_of_concept", ""), "```",
                      f"- **Evidence:** {', '.join(s.get('evidence_indicators', []))}",
                      f"- **Remediation:** {s.get('remediation', '')}", ""]
        lines += ["## Honest assessment", report.get("honest_assessment", "")]
        if platform == "bugcrowd":
            lines.insert(1, "_Submitted via Bugcrowd VRT mapping._")
        return "\n".join(lines)

    def build(self, target: str, findings: List[Dict],
              chains: Optional[List[Dict]] = None) -> Dict:
        # #3 correlate confirmed findings by root cause (one bug → one section, with every instance).
        from hydra.attack.correlate import FindingCorrelator
        corr = FindingCorrelator().merge([f for f in findings if f.get("verdict") == "confirmed"])
        confirmed = corr["merged_findings"]
        suspected = [f for f in findings if f.get("verdict") == "suspected"]
        sections = []
        for f in confirmed:
            vc = f.get("vuln_class", "")
            ev = f.get("evidence") or {}
            sections.append({
                "vuln_class": vc, "verdict": "confirmed",
                "severity": self._severity(vc, chains), "cvss": self.cvss(vc),
                "injection_point": f.get("point", ""),
                "instances": f.get("instances", []), "instance_count": f.get("instance_count", 1),
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
            "duplicates_collapsed": corr["duplicates_collapsed"],
            "suspected_findings": [{"vuln_class": f.get("vuln_class"), "point": f.get("point", ""),
                                    "reason": (f.get("evidence") or {}).get("reason", "needs review")}
                                   for f in suspected],
            "chaining": chains or [],
            "honest_assessment": ("Confirmed findings are backed by differential/PoC evidence; "
                                  "suspected findings need manual verification before submission."),
            "overall_severity": [k for k, v in _SEV_RANK.items() if v == top_sev][0],
            "advisory": True,
        }
