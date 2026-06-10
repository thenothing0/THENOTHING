"""
WorkflowGraph (Phase Q) — the campaign workflow as a phase→capability DAG.

Phase nodes (the 12 ordered tactics, model-only flag preserved) + sequential phase edges +
the capability dependency subgraph. Deterministic, advisory, read-only; O(C + D).
"""

from __future__ import annotations

from typing import Dict, Optional

from hydra.campaigns.campaign_model import CampaignContext, CampaignModel


class WorkflowGraph:
    def __init__(self, cc: Optional[CampaignContext] = None):
        self.cc = cc or CampaignContext()
        self.model = CampaignModel(self.cc)

    def build(self, capabilities=None) -> Dict:
        phases = self.model.phases()
        capset = set(capabilities) if capabilities is not None else None
        nodes = []
        for p in phases:
            caps = p.capabilities if capset is None else sorted(set(p.capabilities) & capset)
            nodes.append({"phase": p.phase, "order": p.order,
                          "advisory_model_only": p.advisory_model_only,
                          "hydra_capability_coverage": p.hydra_capability_coverage,
                          "capability_count": len(caps)})
        phase_edges = [{"from": phases[i].phase, "to": phases[i + 1].phase, "relation": "precedes"}
                       for i in range(len(phases) - 1)]
        scope = capset if capset is not None else {c.capability_id for c in self.cc.catalog().all()}
        dep_edges = sorted([{"from": e["from"], "to": e["to"], "relation": e["relation"]}
                            for e in self.cc.graph().edges()
                            if e["relation"] in ("requires", "enhances")
                            and e["from"] in scope and e["to"] in scope],
                           key=lambda e: (e["relation"], e["from"], e["to"]))
        return {"phase_nodes": nodes, "phase_edges": phase_edges,
                "capability_dependency_edges": dep_edges,
                "phase_count": len(nodes), "dependency_edge_count": len(dep_edges),
                "advisory": True}
