"""
Knowledge-graph loop-back (attack section improvement #2 — close the loop).

Confirmed exploits should not dead-end in a report — they are the platform's most valuable learning
signal. `FindingPublisher` turns TWO-SIGNAL-CONFIRMED findings into knowledge-graph findings (via an
injected `save_fn`, default the platform's `save_finding`) and records them to attack memory. Once in
the graph they feed Phase-D source learning, Phase-S opportunity re-ranking, Phase-T ATT&CK coverage
and Phase-U threat fusion — so each engagement makes the next one smarter.

ONLY `confirmed` findings are written (never single-signal/suspected — that would pollute the graph
with false positives). The actual graph write is injected, so this module imports nothing canonical
and stays test-isolated.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from hydra.attack.report_builder import record_outcome

_DEFAULT_SEV = {"sqli": "high", "cmdi": "critical", "xxe": "high", "ssrf": "high", "xss": "medium",
                "idor": "high", "ssti": "high", "lfi": "high", "path_traversal": "medium",
                "open_redirect": "low", "crlf": "low", "graphql": "medium", "jwt": "high",
                "cors": "medium"}


class FindingPublisher:
    def __init__(self, save_fn: Optional[Callable] = None):
        # save_fn(title, severity, target, description, vuln_class) -> result; None ⇒ dry (no write)
        self.save_fn = save_fn

    def publish(self, target: str, findings: List[Dict]) -> Dict:
        saved, skipped = [], 0
        for f in findings:
            if f.get("verdict") != "confirmed":
                skipped += 1
                continue
            vc = (f.get("vuln_class") or "").lower()
            point = f.get("point", "")
            ev = f.get("evidence") or {}
            title = f"{vc.upper()} at {point or target}"
            severity = f.get("severity") or _DEFAULT_SEV.get(vc, "medium")
            desc = (ev.get("reason", "") + " | PoC: " + (ev.get("curl", "")[:240])).strip(" |")
            written = False
            if self.save_fn:
                try:
                    self.save_fn(title, severity, target, desc, vc)
                    written = True
                except Exception:
                    written = False
            record_outcome(target, vc, "confirmed", point, ev)
            saved.append({"title": title, "severity": severity, "written_to_graph": written})
        return {"target": target, "candidates": len(findings), "saved": len(saved),
                "skipped_unconfirmed": skipped,
                "note": "only two-signal-confirmed findings are written to the knowledge graph",
                "advisory": True}
