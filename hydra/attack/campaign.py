"""
Campaign orchestration (audit improvement #1 — the capstone).

`AttackCampaign` runs the whole gated pipeline in one call instead of an operator manually chaining a
dozen tools:

    authorize → seeds (crawl/provided) → differential multi-class scan (two-signal) →
    confirmed findings → match exploit chains → (loop-back) publish to the knowledge graph +
    verification learning → submission report.

Pure orchestration over the (gated, PoC-only) `AttackWorkflow` — the workflow's executor is the only
network boundary, so this module imports no I/O. Every endpoint is independently authorization-gated;
publishing (the loop-back) is opt-in. Deterministic given the executor.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.attack.report_builder import AttackReporter

# Default class set: the well-supported, two-signal-confirmable web classes.
DEFAULT_CLASSES = ["xss", "sqli", "open_redirect", "lfi", "ssti"]


class AttackCampaign:
    def __init__(self, workflow, publisher=None, reporter: Optional[AttackReporter] = None,
                 classes: Optional[List[str]] = None):
        self.wf = workflow                         # AttackWorkflow (gated executor)
        self.publisher = publisher                 # FindingPublisher (loop-back) or None (no write)
        self.reporter = reporter or AttackReporter()
        self.classes = classes or DEFAULT_CLASSES

    def run(self, target: str, urls: Optional[List[str]] = None, session=None,
            max_seeds: int = 8, max_payloads: int = 4, confirm_dom: bool = False,
            publish: bool = False) -> Dict:
        decision = self.wf.gate.authorize(target, "exploitation")
        if not decision.authorized:
            return {"target": target, "authorized": False, "reason": decision.reason,
                    "advisory": True}
        seeds = urls or [target]
        confirmed: List[Dict] = []
        per_class: Dict[str, int] = {}
        for vc in self.classes:
            r = self.wf.scan_many(seeds, vc, session=session, max_seeds=max_seeds,
                                  max_payloads=max_payloads, confirm_dom=confirm_dom)
            cf = r.get("confirmed_findings", [])
            confirmed.extend(cf)
            per_class[vc] = len(cf)

        chain_match = self.wf.chains.match([{"vuln_class": f["vuln_class"]} for f in confirmed])
        published = (self.publisher.publish(target, confirmed)
                     if (publish and self.publisher and confirmed) else None)
        report = self.reporter.build(target, confirmed, chain_match["instantiable_chains"])
        return {
            "target": target, "authorized": True, "poc_only": True,
            "seeds": len(seeds), "classes_tested": self.classes,
            "confirmed": len(confirmed), "per_class": per_class,
            "instantiable_chains": chain_match["instantiable_count"],
            "chains": chain_match["instantiable_chains"],
            "published": published,
            "report_summary": report["executive_summary"],
            "overall_severity": report["overall_severity"],
            "report": report,
            "advisory": True,
        }
