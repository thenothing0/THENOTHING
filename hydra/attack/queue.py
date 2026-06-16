"""
Intelligence-driven attack prioritization (attack section, suggestion #7).

Instead of attacking breadth-first, rank candidate attacks for a target by realized value: finding
severity, chain potential (does it feed a high-value chain template?), and capability backing (do we
have PoC payloads / does Phase-T cover the technique?). Deterministic; reuses the chain-template engine
and the payload library, with an optional, guarded Phase-T coverage signal. Advisory — it orders the
work; the bug-bounty gate still authorizes each action before anything runs.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.attack.chain_templates import _SEV, ChainTemplateEngine
from hydra.attack.payloads import PayloadContext, PayloadLibrary, VulnClass
from hydra.attack.util import clamp01

# Priority blend (bounded → score in [0,1]).
W_SEVERITY = 0.45
W_CHAIN = 0.35
W_BACKING = 0.20


class AttackQueue:
    def __init__(self, chains: Optional[ChainTemplateEngine] = None,
                 library: Optional[PayloadLibrary] = None):
        self.chains = chains or ChainTemplateEngine()
        self.library = library or PayloadLibrary()

    def _technique_backed(self, vuln_class: str) -> bool:
        """Guarded Phase-T signal: is this vuln class addressable by a covered ATT&CK technique?"""
        try:
            from hydra.adversary_intel.intelligence import AdversaryIntelligence
            techs = AdversaryIntelligence().attack_techniques().get("techniques", [])
            return any(vuln_class in (t.get("technique_id", "") + " ").lower()
                       or vuln_class in t.get("name", "").lower() for t in techs)
        except Exception:
            return False

    def prioritize(self, target: str, findings: List[Dict],
                   use_phase_t: bool = False) -> Dict:
        match = self.chains.match(findings)
        # vuln_class → best realized severity of an instantiable chain it's part of
        chain_sev: Dict[str, int] = {}
        for c in match["instantiable_chains"]:
            for s in c["stages"]:
                chain_sev[s] = max(chain_sev.get(s, 0), _SEV.get(c["realized_severity"], 0))
        partial_classes = {s for p in match["partial_chains"] for s in p["have"]}

        rows: List[Dict] = []
        for f in findings:
            vc = str(f.get("vuln_class") or f.get("type") or f.get("finding_type") or "").lower()
            sev = _SEV.get(str(f.get("severity", "info")).lower(), 0) / 4.0
            chain = (chain_sev.get(vc, 0) / 4.0) if vc in chain_sev else (
                0.4 if vc in partial_classes else 0.0)
            backed = 0.0
            if vc in VulnClass._value2member_map_:
                n = len(self.library.for_context(VulnClass(vc), PayloadContext.ANY))
                backed = min(1.0, n / 5.0)
                if use_phase_t and self._technique_backed(vc):
                    backed = 1.0
            priority = round(clamp01(W_SEVERITY * sev + W_CHAIN * chain + W_BACKING * backed), 4)
            rows.append({"finding": f.get("id") or f.get("title") or vc, "vuln_class": vc,
                         "severity": f.get("severity", "info"), "priority": priority,
                         "feeds_chain": vc in chain_sev, "feeds_partial_chain": vc in partial_classes,
                         "poc_payloads_available": vc in VulnClass._value2member_map_,
                         "advisory": True})
        rows.sort(key=lambda r: (-r["priority"], str(r["finding"])))
        return {"target": target, "queue": rows, "count": len(rows),
                "instantiable_chains": match["instantiable_count"],
                "top": [r["finding"] for r in rows[:5]], "advisory": True}
