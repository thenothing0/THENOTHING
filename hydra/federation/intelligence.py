"""
IntelligenceMesh (Phase N) — federation-wide aggregation of imported digests.

Read-only. Folds every imported digest envelope (from KnowledgeExchangeStore) into
ecosystem-wide views: effectiveness, capability popularity, verification trends,
source-category trends, plugin adoption, and overall federation health.

Single pass over the imported digests with grouped dict accumulation → O(E), never O(N²).
Deterministic (all outputs sorted). Touches nothing canonical; advisory views only.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from hydra.federation.store import KnowledgeExchangeStore


def _wmean(total: float, weight: float) -> float:
    return round(total / weight, 4) if weight else 0.0


class IntelligenceMesh:
    def __init__(self, store: Optional[KnowledgeExchangeStore] = None):
        self.store = store or KnowledgeExchangeStore()

    # One materialization of the imported log, reused by every view (keeps reads O(E)).
    def _digests(self) -> List[Dict]:
        return self.store.imported_digests()

    # ── capability popularity / effectiveness ────────────────────────────────────
    def capability_popularity(self) -> List[Dict]:
        agg: Dict[str, Dict] = {}
        for env in self._digests():
            peer = env.get("origin_peer_id", "")
            for cd in env.get("capability_digests", []):
                cid = cd.get("capability_id")
                if not cid:
                    continue
                a = agg.setdefault(cid, {"category": cd.get("category", ""), "peers": set(),
                                         "exercise": 0, "eff_sum": 0.0, "eff_n": 0})
                a["peers"].add(peer)
                a["exercise"] += int(cd.get("exercise_count", 0) or 0)
                eff = float(cd.get("effectiveness", 0.0) or 0.0)
                if eff > 0:
                    a["eff_sum"] += eff
                    a["eff_n"] += 1
        out = [{"capability_id": cid, "category": a["category"],
                "peer_count": len(a["peers"]), "total_exercise": a["exercise"],
                "mean_effectiveness": _wmean(a["eff_sum"], a["eff_n"])}
               for cid, a in agg.items()]
        out.sort(key=lambda d: (-d["peer_count"], -d["total_exercise"], d["capability_id"]))
        return out

    def ecosystem_effectiveness(self) -> float:
        total, n = 0.0, 0
        for env in self._digests():
            for cd in env.get("capability_digests", []):
                eff = float(cd.get("effectiveness", 0.0) or 0.0)
                if eff > 0:
                    total += eff
                    n += 1
        return _wmean(total, n)

    # ── verification trends ──────────────────────────────────────────────────────
    def verification_trends(self) -> Dict:
        m_sum: Dict[str, float] = {}
        m_n: Dict[str, int] = {}
        e_sum: Dict[str, float] = {}
        e_n: Dict[str, int] = {}
        eff_sum, eff_n = 0.0, 0
        for env in self._digests():
            vd = env.get("verification_digest", {}) or {}
            for m in (vd.get("method_success") or []):
                method, rate = m.get("method"), float(m.get("success_rate", 0.0) or 0.0)
                if method:
                    m_sum[method] = m_sum.get(method, 0.0) + rate
                    m_n[method] = m_n.get(method, 0) + 1
            for e in (vd.get("evidence_class_success") or []):
                ec, rate = e.get("evidence_class"), float(e.get("success_rate", 0.0) or 0.0)
                if ec:
                    e_sum[ec] = e_sum.get(ec, 0.0) + rate
                    e_n[ec] = e_n.get(ec, 0) + 1
            eff = float(vd.get("verification_effectiveness", 0.0) or 0.0)
            if eff > 0:
                eff_sum += eff
                eff_n += 1
        methods = sorted(({"method": k, "mean_success_rate": _wmean(m_sum[k], m_n[k]),
                           "peer_count": m_n[k]} for k in m_sum),
                         key=lambda d: (-d["mean_success_rate"], d["method"]))
        evidence = sorted(({"evidence_class": k, "mean_success_rate": _wmean(e_sum[k], e_n[k]),
                            "peer_count": e_n[k]} for k in e_sum),
                          key=lambda d: (-d["mean_success_rate"], d["evidence_class"]))
        return {"methods": methods, "evidence_classes": evidence,
                "federation_verification_effectiveness": _wmean(eff_sum, eff_n)}

    # ── source-category trends ───────────────────────────────────────────────────
    def source_category_trends(self) -> List[Dict]:
        agg: Dict[str, Dict] = {}
        for env in self._digests():
            for sd in env.get("source_digests", []):
                cat = sd.get("source_category")
                if not cat:
                    continue
                a = agg.setdefault(cat, {"eff": 0.0, "trust": 0.0, "nov": 0.0,
                                         "n": 0, "sources": 0})
                a["eff"] += float(sd.get("effectiveness", 0.0) or 0.0)
                a["trust"] += float(sd.get("trust", 0.0) or 0.0)
                a["nov"] += float(sd.get("novelty", 0.0) or 0.0)
                a["n"] += 1
                a["sources"] += int(sd.get("distinct_sources", 0) or 0)
        out = [{"source_category": cat, "mean_effectiveness": _wmean(a["eff"], a["n"]),
                "mean_trust": _wmean(a["trust"], a["n"]), "mean_novelty": _wmean(a["nov"], a["n"]),
                "peer_count": a["n"], "total_distinct_sources": a["sources"]}
               for cat, a in agg.items()]
        out.sort(key=lambda d: (-d["mean_effectiveness"], d["source_category"]))
        return out

    # ── plugin adoption trends ───────────────────────────────────────────────────
    def plugin_adoption_trends(self) -> List[Dict]:
        agg: Dict[str, Dict] = {}
        for env in self._digests():
            peer = env.get("origin_peer_id", "")
            pd = env.get("plugin_digest", {}) or {}
            for pid in pd.get("plugin_ids", []):
                a = agg.setdefault(pid, {"peers": set()})
                a["peers"].add(peer)
        out = [{"plugin_id": pid, "adopting_peers": len(a["peers"])} for pid, a in agg.items()]
        out.sort(key=lambda d: (-d["adopting_peers"], d["plugin_id"]))
        return out

    # ── federation health ────────────────────────────────────────────────────────
    def federation_health(self) -> Dict:
        digests = self._digests()
        peers = {env.get("origin_peer_id", "") for env in digests}
        categories = set()
        for env in digests:
            for cd in env.get("capability_digests", []):
                if cd.get("category"):
                    categories.add(cd["category"])
        return {
            "contributing_peers": len(peers),
            "imported_digests": len(digests),
            "distinct_categories": len(categories),
            "ecosystem_effectiveness": self.ecosystem_effectiveness(),
            "federation_verification_effectiveness":
                self.verification_trends()["federation_verification_effectiveness"],
            "tracked_capabilities": len(self.capability_popularity()),
            "tracked_plugins": len(self.plugin_adoption_trends()),
        }
