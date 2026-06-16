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
    def __init__(self, save_fn: Optional[Callable] = None,
                 verify_fn: Optional[Callable] = None, method: str = "attack_scan"):
        # save_fn(title, severity, target, description, vuln_class) -> result; None ⇒ dry (no write)
        # verify_fn(vuln_class, method, dedup_key, strength) -> bool; None ⇒ real verification store
        self.save_fn = save_fn
        self.verify_fn = verify_fn
        self.method = method

    @staticmethod
    def _strength(f: Dict) -> float:
        """Evidence strength from the two-signal confirmation (more independent families ⇒ stronger)."""
        fams = ((f.get("evidence") or {}).get("confirmation") or {}).get("families", [])
        return round(min(1.0, 0.6 + 0.2 * len(fams)), 4)

    def _learn(self, target: str, vuln_class: str, point: str, strength: float) -> bool:
        """A confirmed finding IS a verification SUCCESS for its vuln-class — record it so Phase-F /
        Phase-P (and therefore Phase-S/T/U, which build on Phase-P) actually learn from it.
        Idempotent on a stable dedup_key; guarded; honors HYDRA_VERIFICATION_DB for test isolation."""
        key = f"attack:{target}:{vuln_class}:{point}"
        if self.verify_fn is not None:
            try:
                return bool(self.verify_fn(vuln_class, self.method, key, strength))
            except Exception:
                return False
        try:
            from hydra.knowledge.verification import VerificationLearningStore
            return VerificationLearningStore().record_verification(
                vuln_class, self.method, "success", evidence_type="two_signal",
                evidence_strength=strength, dedup_key=key)
        except Exception:
            return False

    def publish(self, target: str, findings: List[Dict]) -> Dict:
        saved, skipped, learned = [], 0, 0
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
            record_outcome(target, vc, "confirmed", point, ev)          # attack memory
            if self._learn(target, vc, point, self._strength(f)):       # close the loop → Phase-F/P
                learned += 1
            saved.append({"title": title, "severity": severity, "written_to_graph": written})
        return {"target": target, "candidates": len(findings), "saved": len(saved),
                "learned_into_intelligence": learned, "skipped_unconfirmed": skipped,
                "note": "confirmed findings are written to the findings store AND recorded as "
                        "verification successes that feed Phase-F/P -> Phase-S/T/U effectiveness",
                "advisory": True}
