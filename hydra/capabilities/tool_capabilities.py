"""
ToolCapabilityRegistry (Phase F) — capability modeling for tool expansion.

Declares the tool-expansion space (recon / web / cloud / verification) so future
tools slot into the architecture without redesign. This phase ships only the
**capability layer** — no tools are integrated/executed here.

Each tool records its category, the capability it serves, the finding types it
supports, and the vulnerability classes it can *verify*. **Historical effectiveness
is not stored here** — it is read on demand from the derived
`VerificationLearningStore` (keyed by method == tool name), keeping this registry a
pure, declarative catalog. Read-only; never touches the wiki / confidence / promotion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

_DEFAULT_CATALOG = Path(__file__).resolve().parents[2] / "capabilities" / "tool_capabilities.yaml"


@dataclass
class ToolCapability:
    id: str                       # stable, e.g. "tool.idor_verifier"
    name: str = ""
    category: str = "recon"       # recon | web | cloud | verification
    capability: str = ""          # the recon/verify capability it serves
    supported_finding_types: List[str] = field(default_factory=list)
    verifies: List[str] = field(default_factory=list)   # vuln classes it can validate

    @property
    def verification_coverage(self) -> int:
        return len(self.verifies)

    @property
    def is_verifier(self) -> bool:
        return self.category == "verification" or bool(self.verifies)

    def to_dict(self, effectiveness: Optional[Dict] = None) -> Dict:
        d = {
            "id": self.id, "name": self.name, "category": self.category,
            "capability": self.capability,
            "supported_finding_types": self.supported_finding_types,
            "verifies": self.verifies, "verification_coverage": self.verification_coverage,
        }
        if effectiveness is not None:
            d["historical_effectiveness"] = effectiveness
        return d


class ToolCapabilityRegistry:
    def __init__(self, catalog_path: Optional[Path | str] = None):
        self.catalog_path = Path(catalog_path) if catalog_path else _DEFAULT_CATALOG
        self._tools: Dict[str, ToolCapability] = {}
        self._loaded = False

    def load(self) -> "ToolCapabilityRegistry":
        if self._loaded or yaml is None:
            self._loaded = True
            return self
        data = yaml.safe_load(self.catalog_path.read_text(encoding="utf-8")) or {}
        for t in data.get("tools", []):
            tid = t.get("id")
            if not tid:
                continue
            self._tools[tid] = ToolCapability(
                id=tid, name=t.get("name", tid.replace("tool.", "")),
                category=t.get("category", "recon"), capability=t.get("capability", ""),
                supported_finding_types=list(t.get("supported_finding_types") or []),
                verifies=list(t.get("verifies") or []))
        self._loaded = True
        return self

    # ── queries (deterministic) ──────────────────────────────────────────────
    def all(self) -> List[ToolCapability]:
        self.load()
        return [self._tools[k] for k in sorted(self._tools)]

    def get(self, tool_id: str) -> Optional[ToolCapability]:
        self.load()
        return self._tools.get(tool_id)

    def by_category(self, category: str) -> List[ToolCapability]:
        return [t for t in self.all() if t.category == category]

    def by_finding_type(self, finding_type: str) -> List[ToolCapability]:
        return [t for t in self.all() if finding_type in t.supported_finding_types]

    def verification_tools(self) -> List[ToolCapability]:
        return [t for t in self.all() if t.is_verifier]

    def categories(self) -> List[str]:
        return sorted({t.category for t in self.all()})

    def effectiveness(self, tool_id: str, verification_store) -> Dict:
        """Historical verification effectiveness for a tool, read from the derived
        verification-learning store (method == tool name). Never stored in this catalog."""
        tool = self.get(tool_id)
        if tool is None:
            return {}
        for m in verification_store.method_stats():
            if m["method"] == tool.name:
                return {"attempts": m["attempts"], "success_rate": m["success_rate"],
                        "confidence": m["confidence"]}
        return {"attempts": 0, "success_rate": 0.0, "confidence": 0.5}
