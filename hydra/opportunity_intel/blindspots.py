"""
BlindSpotAnalyzer (Phase S) — where Hydra's offensive model is blind.

Fuses the gap signals from every reused layer into one severity-ranked blind-spot list:
  * verification-blind categories        — Phase-P (cannot independently validate);
  * uncovered / weak finding-types        — Phase-P missing_finding_types;
  * weak chains                           — Phase-P (low-effectiveness link / no verifying terminal);
  * capabilities with no skill            — Phase-R skill gaps;
  * capabilities with no agent owner      — agent-ownership orphans;
  * model-only campaign phases            — Phase-Q post-exploitation (INTENTIONAL — flagged
                                            `intentional: true`, severity 0.0, never a defect).
Each blind spot carries a bounded severity (0-1) and a rationale. Deterministic, read-only,
advisory; O(C + chains). NON-executing — it describes the MODEL, it never probes a target.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.opportunity_intel.context import OpportunityContext
from hydra.opportunity_intel.util import clamp01

SEV_VERIFICATION_BLIND = 0.8
SEV_NO_SKILL = 0.4
SEV_NO_OWNER = 0.5


class BlindSpotAnalyzer:
    def __init__(self, oc: Optional[OpportunityContext] = None):
        self.oc = oc or OpportunityContext()

    def blind_spots(self) -> List[Dict]:
        out: List[Dict] = []
        gaps = self.oc.oi.gaps.report()

        # verification-blind categories
        for c in self.oc.oi.coverage.category_coverage():
            if c["verification_coverage_pct"] == 0.0 and c["capabilities"] > 0:
                out.append({"type": "verification_blind_category", "target": c["category"],
                            "severity": SEV_VERIFICATION_BLIND,
                            "rationale": f"category '{c['category']}' has no verification-capable capability",
                            "intentional": False, "advisory": True})

        # uncovered / weak finding-types
        for ft in gaps["missing_finding_types"]:
            out.append({"type": "uncovered_finding_type", "target": ft["finding_type"],
                        "severity": round(clamp01(1.0 - ft["best_effectiveness"]), 4),
                        "rationale": ft["reason"], "intentional": False, "advisory": True})

        # weak chains
        for ch in gaps["weak_chains"]:
            out.append({"type": "weak_chain", "target": " -> ".join(ch["chain"]),
                        "severity": round(clamp01(1.0 - ch["weakest_link_effectiveness"]), 4),
                        "rationale": "weakest link low-effectiveness or no verifying terminal",
                        "intentional": False, "advisory": True})

        # capabilities with no skill (Phase-R)
        for u in self.oc.skill().gaps.uncovered_capabilities():
            out.append({"type": "capability_no_skill", "target": u["capability_id"],
                        "severity": SEV_NO_SKILL,
                        "rationale": f"capability has no skill ({u['category']})",
                        "intentional": False, "advisory": True})

        # capabilities with no agent owner (orphans)
        owner = self.oc.owner_of()
        for cid in sorted(k for k, v in owner.items() if not v):
            out.append({"type": "capability_no_owner", "target": cid,
                        "severity": SEV_NO_OWNER,
                        "rationale": "capability is not owned by any agent (orphan)",
                        "intentional": False, "advisory": True})

        # model-only campaign phases (Phase-Q) — INTENTIONAL, not a defect
        for phase in self.oc.campaign().campaign_gaps().get("model_only_phases", []):
            out.append({"type": "model_only_phase", "target": phase, "severity": 0.0,
                        "rationale": "post-exploitation tactic Hydra deliberately does not cover",
                        "intentional": True, "advisory": True})

        out.sort(key=lambda d: (-d["severity"], d["type"], str(d["target"])))
        return out

    def report(self) -> Dict:
        spots = self.blind_spots()
        by_type: Dict[str, int] = {}
        for s in spots:
            by_type[s["type"]] = by_type.get(s["type"], 0) + 1
        actionable = [s for s in spots if not s["intentional"]]
        return {
            "blind_spots": spots, "count": len(spots),
            "actionable_count": len(actionable),
            "intentional_count": len(spots) - len(actionable),
            "by_type": dict(sorted(by_type.items())),
            "top_severity": actionable[:10],
            "advisory": True,
        }
