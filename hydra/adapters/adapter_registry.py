"""
Adapter Registry + Execution Profiles + Adapter Model (Phase K).

Transforms the capability-centric tool catalog (Phase G) into deterministic, executable
ADAPTER DEFINITIONS — without ever introducing execution, exploitation, autonomous
actions, or wiki mutation. Adapters are SYNTHESIZED (one per capability×tool pair) from
the capability catalog and a declarative profile/schema config
(`adapters/adapter_catalog.yaml`).

Invariants (unchanged): read-only over the catalog/config; promotion.py & confidence.py
untouched; offline-first; deterministic; rebuildable; advisory-by-default. Only SAFE
execution profiles are permitted — any unsupported (offensive) profile raises.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from hydra.capabilities.capability_catalog import CapabilityCatalog, CapabilityEntry

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

_DEFAULT_CONFIG = Path(__file__).resolve().parent / "adapter_catalog.yaml"

# ── Execution profiles (declarative + enforced) ─────────────────────────────────
SAFE_PROFILES = ("offline", "passive", "validation", "simulation")
UNSUPPORTED_PROFILES = ("exploitation", "persistence", "destructive", "weaponized")


class ProfileError(ValueError):
    """Raised when an execution profile is unsupported / unsafe."""


def validate_profile(profile: str) -> str:
    """Return the profile if it is a declared SAFE profile, else raise ProfileError.
    Unsupported (offensive) profiles are rejected explicitly — never silently dropped."""
    if profile in UNSUPPORTED_PROFILES:
        raise ProfileError(f"unsupported (offensive) execution profile: {profile!r}")
    if profile not in SAFE_PROFILES:
        raise ProfileError(f"unknown execution profile: {profile!r} (safe: {list(SAFE_PROFILES)})")
    return profile


def derive_profile(cap: CapabilityEntry) -> str:
    """Deterministic default execution profile for a capability's adapters.

    verification capability → validation · offline-runnable → offline · otherwise →
    passive (online collection is passive, never active exploitation)."""
    if cap.is_verification:
        return "validation"
    if cap.offline_runnable:
        return "offline"
    return "passive"


# ── Adapter model ───────────────────────────────────────────────────────────────
@dataclass
class AdapterDefinition:
    adapter_id: str
    capability_id: str
    tool_name: str
    category: str
    execution_profile: str
    version: str = "1.0"
    health_status: str = "unknown"      # static; live health comes from ToolHealthStore
    timeout_seconds: int = 120
    offline_supported: bool = False
    validation_supported: bool = False
    simulation_supported: bool = True    # every adapter supports a sandboxed simulate()
    confidence_weight: float = 0.4
    input_schema: Dict[str, str] = field(default_factory=dict)
    output_schema: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, str] = field(default_factory=dict)

    @property
    def supported_inputs(self) -> List[str]:
        return sorted(self.input_schema)

    @property
    def supported_outputs(self) -> List[str]:
        return sorted(self.output_schema)

    def to_dict(self) -> Dict:
        """Deterministic serialization (stable key order, sorted schemas)."""
        return {
            "adapter_id": self.adapter_id,
            "capability_id": self.capability_id,
            "tool_name": self.tool_name,
            "category": self.category,
            "execution_profile": self.execution_profile,
            "version": self.version,
            "health_status": self.health_status,
            "timeout_seconds": self.timeout_seconds,
            "offline_supported": self.offline_supported,
            "validation_supported": self.validation_supported,
            "simulation_supported": self.simulation_supported,
            "confidence_weight": self.confidence_weight,
            "supported_inputs": self.supported_inputs,
            "supported_outputs": self.supported_outputs,
            "input_schema": dict(sorted(self.input_schema.items())),
            "output_schema": dict(sorted(self.output_schema.items())),
            "metadata": dict(sorted(self.metadata.items())),
        }


def make_adapter_id(capability_id: str, tool: str) -> str:
    """Stable, human-readable, deterministic adapter id."""
    return f"{capability_id}::{tool}"


# ── Registry ──────────────────────────────────────────────────────────────────
class AdapterRegistry:
    """Read-only registry of synthesized adapter definitions. No execution."""

    def __init__(self, config_path: Optional[Path | str] = None,
                 catalog: Optional[CapabilityCatalog] = None):
        self.config_path = Path(config_path) if config_path else _DEFAULT_CONFIG
        self.catalog = (catalog or CapabilityCatalog())
        self._adapters: Dict[str, AdapterDefinition] = {}
        self._config: Dict = {}
        self._loaded = False

    def load(self) -> "AdapterRegistry":
        if self._loaded:
            return self
        self.catalog.load()
        self._config = {}
        if yaml is not None and self.config_path.exists():
            self._config = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        cat_defaults = self._config.get("category_defaults", {})
        overrides = self._config.get("overrides", {}) or {}

        for cap in self.catalog.all():               # deterministic (sorted) iteration
            cdef = cat_defaults.get(cap.category, {})
            base_profile = derive_profile(cap)
            for tool in cap.tools:
                aid = make_adapter_id(cap.capability_id, tool)
                ov = overrides.get(aid, {}) or {}
                profile = validate_profile(ov.get("execution_profile", base_profile))
                self._adapters[aid] = AdapterDefinition(
                    adapter_id=aid,
                    capability_id=cap.capability_id,
                    tool_name=tool,
                    category=cap.category,
                    execution_profile=profile,
                    version=str(ov.get("version", "1.0")),
                    timeout_seconds=int(ov.get("timeout_seconds", cdef.get("timeout_seconds", 120))),
                    offline_supported=bool(cap.offline_runnable),
                    validation_supported=bool(cap.is_verification),
                    simulation_supported=True,
                    confidence_weight=float(cap.confidence_weight),
                    input_schema=dict(ov.get("input_schema", cdef.get("input_schema", {})) or {}),
                    output_schema=dict(ov.get("output_schema", cdef.get("output_schema", {})) or {}),
                    metadata={"synthesized": "true", "profile_source":
                              "override" if "execution_profile" in ov else "derived"},
                )
        self._loaded = True
        return self

    # ── queries (deterministic, read-only) ──────────────────────────────────────
    def all_adapters(self) -> List[AdapterDefinition]:
        self.load()
        return [self._adapters[k] for k in sorted(self._adapters)]

    def get_adapter(self, adapter_id: str) -> Optional[AdapterDefinition]:
        self.load()
        return self._adapters.get(adapter_id)

    def adapters_for_capability(self, capability_id: str) -> List[AdapterDefinition]:
        return [a for a in self.all_adapters() if a.capability_id == capability_id]

    def adapters_for_category(self, category: str) -> List[AdapterDefinition]:
        return [a for a in self.all_adapters() if a.category == category]

    def supported_profiles(self) -> List[str]:
        return list(SAFE_PROFILES)

    def count(self) -> int:
        return len(self.all_adapters())

    def adapter_coverage(self) -> Dict:
        adapters = self.all_adapters()
        by_category: Dict[str, int] = {}
        by_profile: Dict[str, int] = {}
        caps_with_adapter: set = set()
        offline = validation = 0
        for a in adapters:
            by_category[a.category] = by_category.get(a.category, 0) + 1
            by_profile[a.execution_profile] = by_profile.get(a.execution_profile, 0) + 1
            caps_with_adapter.add(a.capability_id)
            offline += 1 if a.offline_supported else 0
            validation += 1 if a.validation_supported else 0
        total_caps = self.catalog.count()
        return {
            "total_adapters": len(adapters),
            "total_capabilities": total_caps,
            "capabilities_with_adapter": len(caps_with_adapter),
            "capability_adapter_coverage_pct":
                round(100 * len(caps_with_adapter) / total_caps, 1) if total_caps else 0.0,
            "adapters_by_category": dict(sorted(by_category.items())),
            "adapters_by_profile": dict(sorted(by_profile.items())),
            "offline_supported": offline,
            "validation_supported": validation,
            "supported_profiles": list(SAFE_PROFILES),
            "unsupported_profiles": list(UNSUPPORTED_PROFILES),
        }
