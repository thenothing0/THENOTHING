"""
ThreatGraph (Phase U) — the unified, fully-explainable knowledge-fusion graph.

Builds the typed graph  Threat → Campaign → Technique → Capability → Skill → Agent  where EVERY edge
carries a `reason` string — there is NO hidden inference. Edges:
  * threat → technique     ("technique belongs to tactic")
  * threat → campaign       ("shared category")            — Phase-Q link
  * campaign → technique    ("shared category")
  * technique → capability  ("capability addresses technique")
  * capability → skill      ("skill provides capability")  — Phase-R link
  * capability → agent      ("agent owns capability")       — Phase-P ownership
Built over in-scope threats (model-only tactics contribute no capability and are noted, not edged).
Deterministic (all edges sorted), read-only, advisory; O(C + D + T).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.threat_intel.context import ThreatContext
from hydra.threat_intel.threat_model import ThreatModel


class ThreatGraph:
    def __init__(self, tc: Optional[ThreatContext] = None, model: Optional[ThreatModel] = None):
        self.tc = tc or ThreatContext()
        self.model = model or ThreatModel(self.tc)
        self._built: Optional[Dict] = None

    def build(self) -> Dict:
        if self._built is not None:
            return self._built
        mapping = self.tc.mapping()
        cap_to_skills = self.tc.cap_to_skills()
        owner = self.tc.owner_of()
        threats = self.model.in_scope()
        phases = {p.phase: p for p in self.tc.campaign().model.phases() if not p.advisory_model_only}

        nodes: Dict[str, set] = {"threat": set(), "campaign": set(), "technique": set(),
                                 "capability": set(), "skill": set(), "agent": set()}
        edges: List[Dict] = []

        def edge(a, at, b, bt, rel, reason):
            edges.append({"from": a, "from_type": at, "to": b, "to_type": bt,
                          "relation": rel, "reason": reason})

        for th in threats:
            nodes["threat"].add(th.threat_id)
            tcats = set(th.categories)
            # threat → campaign (shared category)
            for ph in th.campaign_phases:
                nodes["campaign"].add(ph)
                shared = sorted(tcats & set(phases[ph].hydra_categories))
                edge(th.threat_id, "threat", ph, "campaign", "exercised_by",
                     f"shared category: {', '.join(shared)}")
            for tech in mapping.techniques_for_tactic(th.threat_id):
                if tech.model_only:
                    continue
                nodes["technique"].add(tech.technique_id)
                # threat → technique
                edge(th.threat_id, "threat", tech.technique_id, "technique", "comprises",
                     f"technique belongs to tactic {th.threat_id}")
                # campaign → technique (shared category)
                for ph in th.campaign_phases:
                    if set(tech.categories) & set(phases[ph].hydra_categories):
                        edge(ph, "campaign", tech.technique_id, "technique", "covers",
                             "shared category")
                # technique → capability → skill / agent
                for cap in mapping.capabilities_for(tech):
                    nodes["capability"].add(cap)
                    edge(tech.technique_id, "technique", cap, "capability", "addressed_by",
                         "capability category/finding-type matches technique")
                    for sk in cap_to_skills.get(cap, []):
                        nodes["skill"].add(sk)
                        edge(cap, "capability", sk, "skill", "provided_by",
                             "skill provides capability")
                    if owner.get(cap):
                        nodes["agent"].add(owner[cap])
                        edge(cap, "capability", owner[cap], "agent", "owned_by",
                             "agent owns capability")

        uniq = sorted({(e["from"], e["from_type"], e["to"], e["to_type"], e["relation"]): e
                       for e in edges}.values(),
                      key=lambda e: (e["from_type"], e["from"], e["to_type"], e["to"], e["relation"]))
        self._built = {
            "node_counts": {k: len(v) for k, v in nodes.items()},
            "node_count": sum(len(v) for v in nodes.values()),
            "edges": uniq, "edge_count": len(uniq),
            "edge_relations": sorted({e["relation"] for e in uniq}),
            "model_only_threats": [t.threat_id for t in self.model.threats() if t.model_only],
            "advisory": True,
        }
        return self._built

    def report(self, threat_id: str = "") -> Dict:
        g = self.build()
        if not threat_id:
            return g
        if self.model.get(threat_id) is None:
            return {"threat_id": threat_id, "error": "unknown threat", "advisory": True}
        # The threat's subgraph = every edge whose source is reachable from the threat node
        # (one fixed-point pass over the edge set → O(E)).
        reachable = {threat_id}
        changed = True
        while changed:
            changed = False
            for e in g["edges"]:
                if e["from"] in reachable and e["to"] not in reachable:
                    reachable.add(e["to"])
                    changed = True
        sub = [e for e in g["edges"] if e["from"] in reachable]
        return {"threat_id": threat_id, "edges": sub, "edge_count": len(sub),
                "reachable_nodes": len(reachable), "advisory": True}
