"""
Source model + execution policy for the capability registry.

A `Source` is a declarative description of where a capability's data can come
from (crt.sh, subfinder, FOFA, GitHub dorks, ...). The registry declares the
FULL recon knowledge space — current and future — independent of what is
installed on this machine.

Two hard invariants:
  * **Stable id**: every source has an immutable `id` (e.g. `source.fofa`) that
    is the primary key everywhere (YAML, confidence inputs, Phase-D performance
    schema). Display `name` is cosmetic and may change.
  * **Offline-first**: `ExecutionPolicy` defaults to offline. A source only runs
    if `runnable(policy)` allows it — network sources require explicit online
    mode AND, when needed, an available API key. This keeps the whole pipeline
    runnable offline with cached evidence / fixtures.

The trust + historical-performance block exists from day one so Phase-D
source-learning needs no migration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Set


class SourceCategory(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    CODE_INTELLIGENCE = "code_intelligence"
    CLOUD_INTELLIGENCE = "cloud_intelligence"
    THREAT_INTELLIGENCE = "threat_intelligence"
    CONTACT_INTELLIGENCE = "contact_intelligence"

    @classmethod
    def from_str(cls, raw: Any) -> "SourceCategory":
        try:
            return cls(str(raw or "passive").strip().lower())
        except ValueError:
            return cls.PASSIVE


class SourceUnavailable(Exception):
    """Raised when a declared source cannot run under the current policy/adapter state."""


@dataclass
class Source:
    """A declarative recon source. `id` is the immutable primary key."""
    id: str                                  # e.g. "source.fofa" — never the display name
    name: str = ""                           # cosmetic display name
    category: SourceCategory = SourceCategory.PASSIVE
    source_type: str = ""                    # free text: certificate_transparency, enumeration, ...
    passive: bool = True
    requires_network: bool = True
    requires_api_key: bool = False
    offline_capable: bool = False            # has a local binary or cached/fixture adapter
    # ── trust & historical performance (present day one; populated in Phase D) ──
    trust_score: float = 0.4
    discoveries: int = 0
    unique_assets: int = 0
    duplicates: int = 0
    confidence_weight: float = 0.4
    success_rate: float = 0.0
    average_value: float = 0.0
    rate_limit: Optional[str] = None

    def __post_init__(self):
        if not self.id:
            raise ValueError("Source.id is required (stable identifier)")
        if not isinstance(self.category, SourceCategory):
            self.category = SourceCategory.from_str(self.category)
        if not self.name:
            self.name = self.id.replace("source.", "")

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Source":
        sid = d.get("id") or (f"source.{_slug(d['name'])}" if d.get("name") else None)
        if not sid:
            raise ValueError(f"source entry missing id and name: {d}")
        known = {f for f in cls.__dataclass_fields__}  # noqa: F821
        kwargs = {k: v for k, v in d.items() if k in known}
        kwargs["id"] = sid
        if "category" in kwargs:
            kwargs["category"] = SourceCategory.from_str(kwargs["category"])
        return cls(**kwargs)

    def runnable(self, policy: "ExecutionPolicy") -> bool:
        """Whether this source may execute under the given policy."""
        if policy.mode == "offline":
            return self.offline_capable
        # online mode
        if self.requires_api_key and self.id not in policy.available_keys \
                and self.name not in policy.available_keys:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "id": self.id, "name": self.name, "category": self.category.value,
            "source_type": self.source_type, "passive": self.passive,
            "requires_network": self.requires_network, "requires_api_key": self.requires_api_key,
            "offline_capable": self.offline_capable, "trust_score": self.trust_score,
            "discoveries": self.discoveries, "unique_assets": self.unique_assets,
            "duplicates": self.duplicates, "confidence_weight": self.confidence_weight,
            "success_rate": self.success_rate, "average_value": self.average_value,
            "rate_limit": self.rate_limit,
        }
        return d


@dataclass
class ExecutionPolicy:
    """Controls which sources may run. Offline-first by default."""
    mode: str = "offline"                    # "offline" | "online"
    available_keys: Set[str] = field(default_factory=set)

    @classmethod
    def offline(cls) -> "ExecutionPolicy":
        return cls(mode="offline")

    @classmethod
    def online(cls, available_keys: Optional[Set[str]] = None) -> "ExecutionPolicy":
        return cls(mode="online", available_keys=set(available_keys or set()))


def _slug(name: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")
