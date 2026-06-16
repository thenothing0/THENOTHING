"""
Gated chain execution (attack section improvement #6).

`ChainTemplateEngine` only MATCHES chains; this executes a matched chain's testable stages in order
through the (gated, PoC-only) workflow, recording how far the chain demonstrably reaches and the
realized severity at that depth. Each stage is independently authorization-gated; evidence is REDACTED
(credentials / cloud secrets / tokens are masked — we demonstrate access, we do not store the secret).
It does not auto-pivot one stage's output into the next (that is target-specific and operator-driven);
it validates each stage and reports the demonstrable depth — honestly, never over-claiming.
"""

from __future__ import annotations

import re
from typing import Dict, List

from hydra.attack.chain_templates import _SEV, _RANK_SEV, CHAIN_TEMPLATES

# Stages that map to a directly testable payload vuln class (others are observed/manual).
_TESTABLE = {"ssrf", "xss", "sqli", "ssti", "xxe", "lfi", "path_traversal", "crlf",
             "open_redirect", "cmdi", "idor"}

_REDACT = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA****REDACTED****"),
    (re.compile(r"(?i)(secret|password|passwd|token|api[_-]?key)\s*[=:]\s*\S+"), r"\1=****REDACTED****"),
    (re.compile(r"(?i)secret[_\s]?access[_\s]?key[\"'\s]*[:=][\"'\s]*[\w/+=\-]+"),
     "SecretAccessKey=****REDACTED****"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "eyJ****JWT-REDACTED****"),
]


def redact(text: str) -> str:
    if not text:
        return text
    for pat, repl in _REDACT:
        text = pat.sub(repl, text)
    return text


class ChainExecutor:
    def __init__(self, workflow):
        self.workflow = workflow         # hydra.attack.AttackWorkflow (gated)

    def execute(self, target: str, chain_id: str, session=None) -> Dict:
        tmpl = next((t for t in CHAIN_TEMPLATES if t.chain_id == chain_id), None)
        if tmpl is None:
            return {"chain_id": chain_id, "error": "unknown chain template", "advisory": True}

        stages: List[Dict] = []
        demonstrated_depth = 0
        for i, stage in enumerate(tmpl.stages):
            if stage not in _TESTABLE:
                stages.append({"stage": stage, "order": i, "tested": False,
                               "verdict": "observed", "reason": "not a directly testable stage"})
                continue
            res = self.workflow.scan(target, stage, session=session, max_payloads=4)
            confirmed = res.get("confirmed", False)
            ev = res.get("evidence") or []
            for e in ev:                                   # PoC redaction
                if isinstance(e, dict) and e.get("response", {}).get("body_snippet"):
                    e["response"]["body_snippet"] = redact(e["response"]["body_snippet"])
            stages.append({"stage": stage, "order": i, "tested": True,
                           "verdict": "confirmed" if confirmed else "not_confirmed",
                           "authorized": res.get("authorized", False), "evidence": ev})
            if confirmed:
                demonstrated_depth = i + 1
            else:
                break                                      # chain stops at first unconfirmed stage

        full = demonstrated_depth == len(tmpl.stages)
        # realized severity scales with how far the chain demonstrably reached
        reach = demonstrated_depth / max(1, len(tmpl.stages))
        realized = tmpl.realized_severity if full else _RANK_SEV[
            min(_SEV.get(tmpl.realized_severity, 0), round(_SEV.get(tmpl.realized_severity, 0) * reach))]
        return {
            "chain_id": chain_id, "name": tmpl.name, "stages": stages,
            "demonstrated_depth": demonstrated_depth, "total_stages": len(tmpl.stages),
            "fully_demonstrated": full, "realized_severity": realized,
            "attack_techniques": tmpl.attack_techniques,
            "note": "PoC-only; evidence redacted; stages validated independently (no auto-pivot)",
            "advisory": True,
        }
