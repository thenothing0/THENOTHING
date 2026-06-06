"""
FederationRegistry + PeerRecord (Phase N).

Tracks trusted peer Hydra instances using FEDERATION METADATA ONLY (name, advertised
version/protocol, capability & adapter counts, categories). Never stores credentials or
secrets. Peer ids are deterministic (derived from a stable identity string), so the same
instance always resolves to the same id.

Every peer fact is an append-only `peer_announcement` event in KnowledgeExchangeStore, so
the registry is fully rebuildable. Trust and health are DERIVED, deterministic functions of
the event log (protocol compatibility + exchange history) — advisory only, never influencing
promotion / confidence / wiki.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hydra.federation.safety import (
    FEDERATION_PROTOCOL_VERSION,
    assert_safe,
    deterministic_id,
    semver_compatible,
)
from hydra.federation.store import EV_PEER, KnowledgeExchangeStore

# How many recorded exchanges saturate the experience component of trust.
_TRUST_SATURATION = 10
# A peer unseen for longer than this (seconds) is "stale" (only when `now` supplied).
_STALE_WINDOW = 30 * 24 * 3600


@dataclass
class PeerRecord:
    peer_id: str
    name: str
    version: str = "0.0.0"
    protocol_version: str = "0.0.0"
    capability_count: int = 0
    adapter_count: int = 0
    categories: List[str] = field(default_factory=list)
    exchanges: int = 0
    last_seen: Optional[float] = None
    compatible: bool = False
    trust_score: float = 0.0
    health: str = "unknown"

    def to_dict(self) -> Dict:
        return {
            "peer_id": self.peer_id, "name": self.name, "version": self.version,
            "protocol_version": self.protocol_version,
            "capability_count": self.capability_count, "adapter_count": self.adapter_count,
            "categories": list(self.categories), "exchanges": self.exchanges,
            "last_seen": self.last_seen, "compatible": self.compatible,
            "trust_score": self.trust_score, "health": self.health,
        }


class FederationRegistry:
    def __init__(self, store: Optional[KnowledgeExchangeStore] = None):
        self.store = store or KnowledgeExchangeStore()

    @staticmethod
    def peer_id_for(name: str, endpoint: str = "") -> str:
        """Deterministic peer id from a stable identity string (no clock, no secrets)."""
        return deterministic_id("peer", str(name).strip().lower(), str(endpoint).strip().lower())

    # ── write (announce) ─────────────────────────────────────────────────────────
    def register_peer(self, name: str, version: str = "0.0.0",
                      protocol_version: str = FEDERATION_PROTOCOL_VERSION,
                      capability_count: int = 0, adapter_count: int = 0,
                      categories: Optional[List[str]] = None, endpoint: str = "",
                      occurred_at: Optional[float] = None,
                      exchange_id: Optional[str] = None) -> PeerRecord:
        """Record a peer announcement (metadata only). Idempotent on identical content."""
        if not name:
            raise ValueError("peer name is required")
        peer_id = self.peer_id_for(name, endpoint)
        payload = {
            "name": str(name), "version": str(version),
            "protocol_version": str(protocol_version),
            "capability_count": int(capability_count),
            "adapter_count": int(adapter_count),
            "categories": sorted(set(categories or [])),
        }
        assert_safe(payload, where="peer announcement")
        self.store.record(EV_PEER, payload, peer_id=peer_id,
                          exchange_id=exchange_id, occurred_at=occurred_at)
        return self.get_peer(peer_id) or self._build(peer_id, payload, occurred_at, 0)

    # ── derived reads (deterministic) ─────────────────────────────────────────────
    def _build(self, peer_id: str, payload: Dict, last_seen: Optional[float],
               exchanges: int, now: Optional[float] = None) -> PeerRecord:
        proto = str(payload.get("protocol_version", "0.0.0"))
        compatible = semver_compatible(proto)
        experience = min(1.0, exchanges / _TRUST_SATURATION) if _TRUST_SATURATION else 0.0
        trust = round((0.5 if compatible else 0.0) + 0.5 * experience, 4)
        if not compatible:
            health = "incompatible"
        elif now is not None and last_seen is not None and (now - last_seen) > _STALE_WINDOW:
            health = "stale"
        elif exchanges > 0:
            health = "active"
        else:
            health = "announced"
        return PeerRecord(
            peer_id=peer_id, name=str(payload.get("name", "")),
            version=str(payload.get("version", "0.0.0")), protocol_version=proto,
            capability_count=int(payload.get("capability_count", 0)),
            adapter_count=int(payload.get("adapter_count", 0)),
            categories=list(payload.get("categories", [])),
            exchanges=exchanges, last_seen=last_seen, compatible=compatible,
            trust_score=trust, health=health)

    def peers(self, now: Optional[float] = None) -> List[PeerRecord]:
        counts = self.store.import_counts_by_peer()
        out = [self._build(a["peer_id"], a["payload"], a["last_seen"],
                           counts.get(a["peer_id"], 0), now)
               for a in self.store.latest_peer_announcements()]
        out.sort(key=lambda p: p.peer_id)
        return out

    def get_peer(self, peer_id: str, now: Optional[float] = None) -> Optional[PeerRecord]:
        for p in self.peers(now):
            if p.peer_id == peer_id:
                return p
        return None

    def compatible_peers(self, now: Optional[float] = None) -> List[PeerRecord]:
        return [p for p in self.peers(now) if p.compatible]

    @staticmethod
    def is_compatible(protocol_version: str) -> bool:
        return semver_compatible(protocol_version)

    def summary(self, now: Optional[float] = None) -> Dict:
        peers = self.peers(now)
        compatible = [p for p in peers if p.compatible]
        mean_trust = round(sum(p.trust_score for p in peers) / len(peers), 4) if peers else 0.0
        return {
            "total_peers": len(peers),
            "compatible_peers": len(compatible),
            "incompatible_peers": len(peers) - len(compatible),
            "active_peers": sum(1 for p in peers if p.health == "active"),
            "mean_trust": mean_trust,
            "local_protocol_version": FEDERATION_PROTOCOL_VERSION,
            "peers": [p.to_dict() for p in peers],
        }
