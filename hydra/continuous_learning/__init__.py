"""
╔══════════════════════════════════════════════════════════════╗
║  Continuous Learning Engine                                  ║
║  Self-improving exploit intelligence, methodology evolution  ║
║  Personal Exploit Intelligence Database                      ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("hydra.continuous_learning")


@dataclass
class LearningRecord:
    """A record of a learning event."""
    id: str = ""
    event_type: str = ""          # success, failure, false_positive, methodology_update
    attack_vector: str = ""
    target_type: str = ""
    payload: str = ""
    outcome: str = ""
    confidence_before: float = 0.0
    confidence_after: float = 0.0
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class MethodologyEntry:
    """An entry in the semantic methodology memory."""
    id: str = ""
    name: str = ""
    attack_vector: str = ""
    steps: List[str] = field(default_factory=list)
    success_rate: float = 0.0
    total_uses: int = 0
    successful_uses: int = 0
    avg_detection_risk: float = 0.0
    best_against: List[str] = field(default_factory=list)    # technologies
    worst_against: List[str] = field(default_factory=list)
    last_success: float = 0.0
    evolved_from: str = ""


@dataclass
class PayloadIntelligence:
    """Intelligence about payload effectiveness."""
    payload: str
    payload_type: str
    success_count: int = 0
    failure_count: int = 0
    blocked_count: int = 0
    effective_against: List[str] = field(default_factory=list)
    blocked_by: List[str] = field(default_factory=list)
    mutations_tried: int = 0
    best_mutation: str = ""


class ContinuousLearningEngine:
    """
    Self-improving exploit intelligence engine.

    Learns from:
      - Successful findings → reinforce methods
      - Failed operations → avoid repeating mistakes
      - False positives → tighten validation
      - Blocked payloads → evolve mutations
      - Stealth failures → adapt timing

    Builds:
      - Personal Exploit Intelligence Database
      - Semantic Methodology Memory
      - Exploit Pattern Knowledge Base
    """

    def __init__(self, persist_dir: str = ""):
        self._records: List[LearningRecord] = []
        self._methodologies: Dict[str, MethodologyEntry] = {}
        self._payload_intel: Dict[str, PayloadIntelligence] = {}
        self._stealth_learnings: List[Dict[str, Any]] = []
        self._technology_profiles: Dict[str, Dict[str, Any]] = {}
        self._persist_dir = Path(persist_dir) if persist_dir else None

    # ── Learning Interface ────────────────────

    async def record(self, learning: Dict[str, Any]):
        """Record a learning event from the cognitive loop."""
        record = LearningRecord(
            id=f"lr_{int(time.time())}_{len(self._records)}",
            event_type=learning.get("outcome", "unknown"),
            attack_vector=learning.get("attack_vector", ""),
            context=learning,
        )
        self._records.append(record)

        # Update methodology intelligence
        if record.attack_vector:
            self._update_methodology(record)

        # Update payload intelligence
        payload = learning.get("payload", "")
        if payload:
            self._update_payload_intel(record, payload)

    def record_success(self, attack_vector: str, payload: str = "",
                        target_tech: str = "", context: Dict = None):
        """Record a successful exploit."""
        self._records.append(LearningRecord(
            id=f"lr_s_{int(time.time())}",
            event_type="success",
            attack_vector=attack_vector,
            payload=payload,
            target_type=target_tech,
            context=context or {},
        ))
        self._update_methodology_success(attack_vector, target_tech)
        if payload:
            self._record_payload_success(payload, attack_vector, target_tech)

    def record_failure(self, attack_vector: str, reason: str = "",
                        payload: str = "", blocked_by: str = ""):
        """Record a failed exploit attempt."""
        self._records.append(LearningRecord(
            id=f"lr_f_{int(time.time())}",
            event_type="failure",
            attack_vector=attack_vector,
            payload=payload,
            outcome=reason,
        ))
        self._update_methodology_failure(attack_vector)
        if payload and blocked_by:
            self._record_payload_blocked(payload, attack_vector, blocked_by)

    def record_false_positive(self, attack_vector: str, details: str = ""):
        """Record a false positive finding."""
        self._records.append(LearningRecord(
            id=f"lr_fp_{int(time.time())}",
            event_type="false_positive",
            attack_vector=attack_vector,
            outcome=details,
        ))

    def record_stealth_failure(self, action: str, detection_type: str = "",
                                response_code: int = 0):
        """Record a stealth failure (got detected/blocked)."""
        self._stealth_learnings.append({
            "action": action,
            "detection_type": detection_type,
            "response_code": response_code,
            "timestamp": time.time(),
        })

    # ── Intelligence Queries ──────────────────

    def get_best_methodology(self, attack_vector: str,
                              target_tech: str = "") -> Optional[MethodologyEntry]:
        """Get the best methodology for an attack vector."""
        candidates = [m for m in self._methodologies.values()
                       if m.attack_vector == attack_vector]
        if target_tech:
            # Prefer methodologies that work against this tech
            tech_matches = [m for m in candidates if target_tech in m.best_against]
            if tech_matches:
                candidates = tech_matches

        if not candidates:
            return None

        return max(candidates, key=lambda m: m.success_rate)

    def get_effective_payloads(self, attack_vector: str,
                                target_tech: str = "",
                                limit: int = 10) -> List[str]:
        """Get the most effective payloads for an attack vector."""
        relevant = [
            pi for pi in self._payload_intel.values()
            if pi.payload_type == attack_vector and pi.success_count > 0
        ]

        if target_tech:
            relevant = [pi for pi in relevant if target_tech in pi.effective_against]

        relevant.sort(key=lambda pi: pi.success_count / max(
            pi.success_count + pi.failure_count, 1), reverse=True)

        return [pi.payload for pi in relevant[:limit]]

    def get_avoided_payloads(self, waf_name: str = "") -> List[str]:
        """Get payloads to avoid (frequently blocked)."""
        blocked = [pi for pi in self._payload_intel.values()
                    if pi.blocked_count > pi.success_count]
        if waf_name:
            blocked = [pi for pi in blocked if waf_name in pi.blocked_by]
        return [pi.payload for pi in blocked]

    def get_stealth_recommendations(self) -> List[str]:
        """Get stealth recommendations from learning history."""
        recommendations = []
        if not self._stealth_learnings:
            return ["No stealth data yet — proceed with default caution"]

        # Analyze detection patterns
        by_type: Dict[str, int] = {}
        for sl in self._stealth_learnings:
            dt = sl.get("detection_type", "unknown")
            by_type[dt] = by_type.get(dt, 0) + 1

        for dtype, count in sorted(by_type.items(), key=lambda x: -x[1]):
            if count >= 3:
                recommendations.append(
                    f"Frequent {dtype} detections ({count}x) — "
                    f"increase stealth for this action type"
                )

        return recommendations

    def get_technology_profile(self, tech: str) -> Dict[str, Any]:
        """Get learned intelligence about a technology."""
        return self._technology_profiles.get(tech.lower(), {
            "technology": tech,
            "known_vectors": [],
            "effective_payloads": [],
            "blocked_payloads": [],
            "success_rate": 0.0,
        })

    # ── Internal Updates ──────────────────────

    def _update_methodology(self, record: LearningRecord):
        key = record.attack_vector
        if key not in self._methodologies:
            self._methodologies[key] = MethodologyEntry(
                id=f"meth_{key}",
                name=key.replace("_", " ").title(),
                attack_vector=key,
            )
        meth = self._methodologies[key]
        meth.total_uses += 1
        if record.event_type == "success":
            meth.successful_uses += 1
            meth.last_success = time.time()
        meth.success_rate = meth.successful_uses / max(meth.total_uses, 1)

    def _update_methodology_success(self, vector: str, tech: str):
        if vector not in self._methodologies:
            self._methodologies[vector] = MethodologyEntry(
                id=f"meth_{vector}", name=vector, attack_vector=vector)
        m = self._methodologies[vector]
        m.total_uses += 1
        m.successful_uses += 1
        m.success_rate = m.successful_uses / max(m.total_uses, 1)
        m.last_success = time.time()
        if tech and tech not in m.best_against:
            m.best_against.append(tech)

    def _update_methodology_failure(self, vector: str):
        if vector not in self._methodologies:
            self._methodologies[vector] = MethodologyEntry(
                id=f"meth_{vector}", name=vector, attack_vector=vector)
        m = self._methodologies[vector]
        m.total_uses += 1
        m.success_rate = m.successful_uses / max(m.total_uses, 1)

    def _update_payload_intel(self, record: LearningRecord, payload: str):
        if payload not in self._payload_intel:
            self._payload_intel[payload] = PayloadIntelligence(
                payload=payload, payload_type=record.attack_vector)
        pi = self._payload_intel[payload]
        if record.event_type == "success":
            pi.success_count += 1
        elif record.event_type == "failure":
            pi.failure_count += 1

    def _record_payload_success(self, payload: str, vector: str, tech: str):
        if payload not in self._payload_intel:
            self._payload_intel[payload] = PayloadIntelligence(
                payload=payload, payload_type=vector)
        pi = self._payload_intel[payload]
        pi.success_count += 1
        if tech and tech not in pi.effective_against:
            pi.effective_against.append(tech)

    def _record_payload_blocked(self, payload: str, vector: str, blocker: str):
        if payload not in self._payload_intel:
            self._payload_intel[payload] = PayloadIntelligence(
                payload=payload, payload_type=vector)
        pi = self._payload_intel[payload]
        pi.blocked_count += 1
        if blocker and blocker not in pi.blocked_by:
            pi.blocked_by.append(blocker)

    # ── Persistence ───────────────────────────

    def save(self):
        if not self._persist_dir:
            return
        self._persist_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "methodologies": {k: {
                "id": m.id, "name": m.name, "attack_vector": m.attack_vector,
                "success_rate": m.success_rate, "total_uses": m.total_uses,
                "best_against": m.best_against,
            } for k, m in self._methodologies.items()},
            "stats": {"total_records": len(self._records)},
            "saved_at": time.time(),
        }
        (self._persist_dir / "learning_state.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8")

    def get_summary(self) -> Dict[str, Any]:
        total = len(self._records)
        successes = sum(1 for r in self._records if r.event_type == "success")
        failures = sum(1 for r in self._records if r.event_type == "failure")
        fps = sum(1 for r in self._records if r.event_type == "false_positive")
        return {
            "total_records": total,
            "successes": successes,
            "failures": failures,
            "false_positives": fps,
            "success_rate": round(successes / max(total, 1), 3),
            "methodologies_tracked": len(self._methodologies),
            "payloads_tracked": len(self._payload_intel),
            "stealth_learnings": len(self._stealth_learnings),
        }
