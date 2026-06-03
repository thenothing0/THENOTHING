"""
Capability Catalog v2 (Phase G) — capability-centric orchestration modeling.

Replaces tool-centric modeling: the catalog's entries are CAPABILITIES, each mapping
to many interchangeable tools. This is the orchestration layer's view of "what the
system can do", independent of which concrete tool is installed.

Capability modeling ONLY — nothing here executes a tool. Read-only, deterministic.
Coexists with the recon `CapabilityRegistry` (recon-fusion sources) and the Phase-F
`ToolCapabilityRegistry`; v2 is the broad orchestration catalog.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

_DEFAULT_CATALOG = Path(__file__).resolve().parents[2] / "capabilities" / "capability_catalog.yaml"

CATEGORIES = ("reconnaissance", "web", "api", "cloud", "source_code",
              "secrets", "mobile", "infrastructure", "verification")


@dataclass
class CapabilityEntry:
    capability_id: str
    category: str = "reconnaissance"
    supported_target_types: List[str] = field(default_factory=list)
    supported_finding_types: List[str] = field(default_factory=list)
    verification_coverage: int = 0
    offline_runnable: bool = False
    confidence_weight: float = 0.4
    tools: List[str] = field(default_factory=list)

    @property
    def is_verification(self) -> bool:
        return self.category == "verification" or self.verification_coverage > 0

    def to_dict(self) -> Dict:
        return {
            "capability_id": self.capability_id, "category": self.category,
            "supported_target_types": self.supported_target_types,
            "supported_finding_types": self.supported_finding_types,
            "verification_coverage": self.verification_coverage,
            "offline_runnable": self.offline_runnable,
            "confidence_weight": self.confidence_weight, "tools": self.tools,
        }


class CapabilityCatalog:
    def __init__(self, catalog_path: Optional[Path | str] = None):
        self.catalog_path = Path(catalog_path) if catalog_path else _DEFAULT_CATALOG
        self._caps: Dict[str, CapabilityEntry] = {}
        self._loaded = False

    def load(self) -> "CapabilityCatalog":
        if self._loaded or yaml is None:
            self._loaded = True
            return self
        data = yaml.safe_load(self.catalog_path.read_text(encoding="utf-8")) or {}
        for c in data.get("capabilities", []):
            cid = c.get("id")
            if not cid:
                continue
            self._caps[cid] = CapabilityEntry(
                capability_id=cid, category=c.get("category", "reconnaissance"),
                supported_target_types=list(c.get("target_types") or []),
                supported_finding_types=list(c.get("finding_types") or []),
                verification_coverage=int(c.get("verification_coverage", 0)),
                offline_runnable=bool(c.get("offline_runnable", False)),
                confidence_weight=float(c.get("confidence_weight", 0.4)),
                tools=list(c.get("tools") or []))
        self._loaded = True
        return self

    # ── queries (deterministic) ──────────────────────────────────────────────
    def all(self) -> List[CapabilityEntry]:
        self.load()
        return [self._caps[k] for k in sorted(self._caps)]

    def get(self, capability_id: str) -> Optional[CapabilityEntry]:
        self.load()
        return self._caps.get(capability_id)

    def by_category(self, category: str) -> List[CapabilityEntry]:
        return [c for c in self.all() if c.category == category]

    def by_target_type(self, target_type: str) -> List[CapabilityEntry]:
        return [c for c in self.all() if target_type in c.supported_target_types]

    def by_finding_type(self, finding_type: str) -> List[CapabilityEntry]:
        return [c for c in self.all() if finding_type in c.supported_finding_types]

    def categories(self) -> List[str]:
        return sorted({c.category for c in self.all()})

    def all_tools(self) -> List[str]:
        seen: Dict[str, None] = {}
        for c in self.all():
            for t in c.tools:
                seen.setdefault(t, None)
        return sorted(seen)

    def count(self) -> int:
        return len(self.all())

    def category_counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for c in self.all():
            out[c.category] = out.get(c.category, 0) + 1
        return out
