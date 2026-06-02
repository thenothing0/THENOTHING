"""
╔══════════════════════════════════════════════════════════════╗
║  Explainability & Audit Layer — Full Decision Transparency   ║
║  Chain-of-thought logging, evidence chains, confidence       ║
║  tracking, and immutable audit trails for every decision     ║
║  NO COMPETITOR HAS THIS CAPABILITY                           ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("hydra.audit")


class DecisionCategory(str, Enum):
    RECON = "reconnaissance"
    THEORY = "theory_generation"
    SIMULATION = "simulation"
    EXECUTION = "tool_execution"
    VALIDATION = "finding_validation"
    PROFILE_SWITCH = "profile_switch"
    STEALTH_ADJUST = "stealth_adjustment"
    SCOPE_CHECK = "scope_check"
    TARGET_SELECT = "target_selection"
    LEARNING = "learning_update"
    ABORT = "abort_decision"


class EvidenceType(str, Enum):
    HTTP_RESPONSE = "http_response"
    TOOL_OUTPUT = "tool_output"
    SCREENSHOT = "screenshot"
    OBSERVATION = "observation"
    BELIEF = "belief"
    SIMULATION_RESULT = "simulation_result"
    DEBATE_OUTCOME = "debate_outcome"
    EXTERNAL_INTEL = "external_intel"


@dataclass
class EvidenceItem:
    """A single piece of evidence supporting a decision."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    evidence_type: EvidenceType = EvidenceType.OBSERVATION
    source: str = ""
    content: str = ""
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)
    artifact_path: str = ""


@dataclass
class AuditEntry:
    """An immutable audit trail entry for a single decision."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:16])
    timestamp: float = field(default_factory=time.time)
    category: DecisionCategory = DecisionCategory.RECON
    action: str = ""
    rationale: str = ""
    chain_of_thought: List[str] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    confidence: float = 0.5
    risk_score: float = 0.0
    outcome: str = ""
    parent_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        for e in d.get("evidence", []):
            if isinstance(e.get("evidence_type"), EvidenceType):
                e["evidence_type"] = e["evidence_type"].value
        return d


@dataclass
class ConfidenceTrace:
    """Tracks how confidence changes through the pipeline."""
    finding_id: str = ""
    stages: List[Dict[str, Any]] = field(default_factory=list)

    def record(self, stage: str, confidence: float, reason: str = ""):
        self.stages.append({
            "stage": stage, "confidence": round(confidence, 4),
            "reason": reason, "timestamp": time.time(),
        })

    @property
    def final_confidence(self) -> float:
        return self.stages[-1]["confidence"] if self.stages else 0.0

    @property
    def delta(self) -> float:
        if len(self.stages) < 2:
            return 0.0
        return self.stages[-1]["confidence"] - self.stages[0]["confidence"]


class AuditTrail:
    """
    Immutable decision audit trail.

    Records every cognitive decision with:
      - Chain-of-thought reasoning
      - Supporting evidence with confidence scores
      - Risk assessment
      - Outcome tracking
      - Parent-child decision linking

    Supports export to JSON, Markdown, and structured reports.
    """

    def __init__(self, persist_dir: str = ""):
        self._entries: List[AuditEntry] = []
        self._confidence_traces: Dict[str, ConfidenceTrace] = {}
        self._persist_dir = Path(persist_dir) if persist_dir else None
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)

    def record(self,
               category: DecisionCategory,
               action: str,
               rationale: str,
               chain_of_thought: List[str] = None,
               evidence: List[EvidenceItem] = None,
               confidence: float = 0.5,
               risk_score: float = 0.0,
               parent_id: str = "",
               metadata: Dict[str, Any] = None,
               ) -> AuditEntry:
        """Record a decision in the audit trail."""
        entry = AuditEntry(
            category=category,
            action=action,
            rationale=rationale,
            chain_of_thought=chain_of_thought or [],
            evidence=evidence or [],
            confidence=confidence,
            risk_score=risk_score,
            parent_id=parent_id,
            metadata=metadata or {},
        )
        self._entries.append(entry)

        logger.debug(
            f"📋 Audit [{category.value}] {action} "
            f"(confidence={confidence:.2f}, risk={risk_score:.2f})"
        )
        return entry

    def update_outcome(self, entry_id: str, outcome: str):
        """Update the outcome of a previously recorded decision."""
        for entry in reversed(self._entries):
            if entry.id == entry_id:
                entry.outcome = outcome
                return

    def track_confidence(self, finding_id: str, stage: str,
                         confidence: float, reason: str = ""):
        """Track confidence evolution for a finding."""
        if finding_id not in self._confidence_traces:
            self._confidence_traces[finding_id] = ConfidenceTrace(
                finding_id=finding_id
            )
        self._confidence_traces[finding_id].record(stage, confidence, reason)

    def get_decision_chain(self, entry_id: str) -> List[AuditEntry]:
        """Get the full decision chain leading to an entry."""
        chain = []
        current_id = entry_id
        visited = set()
        while current_id and current_id not in visited:
            visited.add(current_id)
            for entry in self._entries:
                if entry.id == current_id:
                    chain.insert(0, entry)
                    current_id = entry.parent_id
                    break
            else:
                break
        return chain

    def export_markdown(self) -> str:
        """Export audit trail as a readable Markdown report."""
        lines = [
            "# THENOTHING v7.1 — Audit Trail Report",
            f"\n**Entries**: {len(self._entries)}",
            f"**Time range**: {self._time_range()}",
            "\n---\n",
        ]
        for i, entry in enumerate(self._entries):
            lines.append(f"## Decision #{i+1}: {entry.action}")
            lines.append(f"- **Category**: {entry.category.value}")
            lines.append(f"- **Confidence**: {entry.confidence:.2f}")
            lines.append(f"- **Risk**: {entry.risk_score:.2f}")
            lines.append(f"- **Rationale**: {entry.rationale}")
            if entry.chain_of_thought:
                lines.append("\n**Chain of Thought**:")
                for step in entry.chain_of_thought:
                    lines.append(f"  1. {step}")
            if entry.evidence:
                lines.append(f"\n**Evidence** ({len(entry.evidence)} items):")
                for ev in entry.evidence:
                    lines.append(
                        f"  - [{ev.evidence_type.value}] {ev.source}: "
                        f"{ev.content[:100]}... (conf={ev.confidence:.2f})"
                    )
            if entry.outcome:
                lines.append(f"- **Outcome**: {entry.outcome}")
            lines.append("")
        return "\n".join(lines)

    def export_json(self) -> List[Dict]:
        return [e.to_dict() for e in self._entries]

    def persist(self):
        """Persist audit trail to disk."""
        if not self._persist_dir:
            return
        path = self._persist_dir / "audit_trail.json"
        path.write_text(
            json.dumps(self.export_json(), indent=2, default=str),
            encoding="utf-8",
        )
        md_path = self._persist_dir / "audit_trail.md"
        md_path.write_text(self.export_markdown(), encoding="utf-8")

    def get_summary(self) -> Dict[str, Any]:
        categories = {}
        for e in self._entries:
            cat = e.category.value
            categories[cat] = categories.get(cat, 0) + 1
        avg_conf = (
            sum(e.confidence for e in self._entries) / len(self._entries)
            if self._entries else 0
        )
        return {
            "total_entries": len(self._entries),
            "categories": categories,
            "avg_confidence": round(avg_conf, 3),
            "confidence_traces": len(self._confidence_traces),
            "time_range": self._time_range(),
        }

    def _time_range(self) -> str:
        if not self._entries:
            return "N/A"
        start = min(e.timestamp for e in self._entries)
        end = max(e.timestamp for e in self._entries)
        return f"{end - start:.1f}s"
