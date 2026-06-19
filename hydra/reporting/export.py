"""Findings export to SARIF 2.1.0 / Markdown / JSON (over the Phase-4 findings schema)."""

from __future__ import annotations

import json
from typing import Dict, List

# CVSS qualitative severity → SARIF level.
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def to_sarif(findings: List[Dict], tool_name: str = "THENOTHING") -> str:
    """Render findings as a SARIF 2.1.0 run (GitHub code-scanning / CI ingestible).
    One rule per distinct vuln_class; one result per finding."""
    rules: Dict[str, Dict] = {}
    results = []
    for f in findings:
        vclass = (f.get("vuln_class") or "finding").lower()
        if vclass not in rules:
            rules[vclass] = {
                "id": vclass,
                "name": vclass,
                "shortDescription": {"text": f.get("title", vclass)},
                "properties": {k: v for k, v in
                               (("cwe", f.get("cwe")), ("owasp", f.get("owasp"))) if v},
            }
        sev = (f.get("severity") or "info").lower()
        result = {
            "ruleId": vclass,
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {"text": f.get("title", "") + (f" — {f['impact']}" if f.get("impact") else "")},
            "properties": {"state": f.get("state"), "severity": sev,
                           "cvss_score": f.get("cvss_score")},
        }
        loc = f.get("endpoint") or f.get("asset")
        if loc:
            result["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": loc}}}]
        results.append(result)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def to_json(findings: List[Dict], engagement: Dict | None = None) -> str:
    return json.dumps({"engagement": engagement or {}, "findings": findings,
                       "count": len(findings)}, indent=2)


def to_markdown(findings: List[Dict], engagement: Dict | None = None) -> str:
    out: List[str] = []
    eng = engagement or {}
    out.append(f"# Security Assessment — {eng.get('name', 'Findings Report')}")
    if eng.get("client"):
        out.append(f"\n**Client:** {eng['client']}")
    # Severity summary table.
    order = ["critical", "high", "medium", "low", "info"]
    counts = {s: 0 for s in order}
    for f in findings:
        counts[(f.get("severity") or "info").lower()] = counts.get(
            (f.get("severity") or "info").lower(), 0) + 1
    out.append("\n## Summary\n")
    out.append("| Severity | Count |\n|---|---|")
    for s in order:
        out.append(f"| {s.capitalize()} | {counts[s]} |")
    out.append("\n## Findings\n")
    sev_rank = {s: i for i, s in enumerate(order)}
    for f in sorted(findings, key=lambda x: sev_rank.get((x.get("severity") or "info").lower(), 9)):
        out.append(f"### [{(f.get('severity') or 'info').upper()}] {f.get('title', '(untitled)')}")
        meta = []
        for label, key in (("State", "state"), ("CVSS", "cvss_score"), ("CWE", "cwe"),
                           ("OWASP", "owasp"), ("Endpoint", "endpoint"), ("Param", "parameter")):
            if f.get(key):
                meta.append(f"**{label}:** {f[key]}")
        if meta:
            out.append("  \n".join(meta))
        if f.get("impact"):
            out.append(f"\n**Impact:** {f['impact']}")
        if f.get("remediation"):
            out.append(f"\n**Remediation:** {f['remediation']}")
        out.append("")
    return "\n".join(out)
