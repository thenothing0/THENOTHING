"""
Program-aware triage + submission-readiness gate (improvement #2).

CVSS is generic; bug-bounty programs pay on their OWN rubric and only accept findings that come with
proof, two signals, and in-scope targets. This module bridges that gap:

  * `program_severity(cvss_score, platform)` — maps a CVSS base score to the platform's severity
    vocabulary (HackerOne Critical→Low / Bugcrowd-style P1–P5) plus an advisory bounty band.
  * `SubmissionReadiness.assess(finding, target, gate, known_signatures)` — a deterministic gate that
    encodes the operator's hard rules BEFORE a report goes out: confirmed verdict, TWO independent
    signals, a reproducible proof artifact (curl/screenshot), the target is in a registered scope
    (deny-by-default), and it isn't a duplicate. Returns a readiness score + the precise blockers.

Pure/advisory (the only network touch is the optional in-scope gate check, which sends nothing). No
canonical writes. Deterministic.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# CVSS base-score → (P-scale, label, advisory USD bounty band). Bands are rough planning aids only.
_BANDS = [
    (9.0, "P1", "critical", "$2k–$15k+"),
    (7.0, "P2", "high", "$750–$4k"),
    (4.0, "P3", "medium", "$250–$1k"),
    (0.1, "P4", "low", "$50–$300"),
    (0.0, "P5", "info", "$0–$50"),
]
_H1 = {"P1": "Critical", "P2": "High", "P3": "Medium", "P4": "Low", "P5": "None"}


def program_severity(cvss_score: float, platform: str = "hackerone") -> Dict:
    score = float(cvss_score or 0)
    pscale, label, band = "P5", "info", "$0–$50"
    for threshold, p, lbl, b in _BANDS:
        if score >= threshold:
            pscale, label, band = p, lbl, b
            break
    out = {"cvss_score": score, "p_scale": pscale, "label": label, "bounty_band": band,
           "platform": platform, "advisory": True}
    if platform == "hackerone":
        out["hackerone_severity"] = _H1[pscale]
    elif platform == "bugcrowd":
        out["bugcrowd_priority"] = pscale         # VRT technical severity ≈ P-scale
    return out


class SubmissionReadiness:
    """Deterministic pre-submission gate enforcing the operator's reporting rules."""

    def assess(self, finding: Dict, target: str = "", gate=None,
               known_signatures: Optional[List[str]] = None) -> Dict:
        ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else finding
        conf = ev.get("confirmation") or {}
        checks: List[Dict] = []

        def chk(name, passed, detail, blocking=True):
            checks.append({"check": name, "passed": bool(passed), "detail": detail,
                           "blocking": blocking})

        chk("confirmed_verdict", finding.get("verdict") == "confirmed",
            "finding must be confirmed (not suspected/single-signal)")
        chk("two_independent_signals", (conf.get("independent_signals") or 0) >= 2,
            "two independent signal families required (validation-first rule)")
        has_proof = bool(ev.get("curl")) or bool(ev.get("screenshot_path")) or bool(ev.get("request"))
        chk("reproducible_proof", has_proof,
            "a reproducible PoC artifact (curl/screenshot/request) must be attached")
        if gate is not None and target:
            try:
                in_scope = gate.authorize(target, "exploitation").authorized
            except Exception:
                in_scope = False
            chk("in_scope", in_scope, "target must be in a registered bug-bounty scope")
        sig = f"{(finding.get('vuln_class') or '').lower()}|{finding.get('point', '')}"
        chk("not_duplicate", sig not in set(known_signatures or []),
            "must not duplicate an already-submitted finding", blocking=False)

        blockers = [c["check"] for c in checks if c["blocking"] and not c["passed"]]
        passed = sum(1 for c in checks if c["passed"])
        return {"vuln_class": finding.get("vuln_class"), "ready": not blockers,
                "readiness_score": round(passed / len(checks), 2) if checks else 0.0,
                "checks": checks, "blockers": blockers,
                "note": ("READY to submit" if not blockers
                         else f"NOT ready — resolve: {', '.join(blockers)}"),
                "advisory": True}


def triage_finding(finding: Dict, target: str = "", platform: str = "hackerone", gate=None,
                   known_signatures: Optional[List[str]] = None) -> Dict:
    """One-call triage: CVSS → program severity/bounty band + submission-readiness."""
    from hydra.attack.report_builder import AttackReporter
    vc = finding.get("vuln_class", "")
    cvss = AttackReporter.cvss(vc)
    sev = program_severity(cvss["score"], platform)
    readiness = SubmissionReadiness().assess(finding, target, gate, known_signatures)
    return {"vuln_class": vc, "cvss": cvss, "severity": sev, "readiness": readiness,
            "advisory": True}
