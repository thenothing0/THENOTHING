"""
Hydra Federation Layer — Phase N: Federated Knowledge Exchange & Intelligence Mesh

Provides the machinery for exchanging aggregated, anonymized intelligence
digests between trusted Hydra instances. All state is derived; no canonical
knowledge ever leaves the local node.
"""

from .registry import FederationRegistry, PeerRecord
from .store import KnowledgeExchangeStore
from .digest import (
    KnowledgeDigestGenerator,
    CapabilityDigest,
    SourceDigest,
    VerificationDigest,
    PluginDigest,
)
from .intelligence import IntelligenceMesh
from .consensus import ConsensusEngine
from .marketplace import FederationMarketplace

__all__ = [
    "FederationRegistry",
    "PeerRecord",
    "KnowledgeExchangeStore",
    "KnowledgeDigestGenerator",
    "CapabilityDigest",
    "SourceDigest",
    "VerificationDigest",
    "PluginDigest",
    "IntelligenceMesh",
    "ConsensusEngine",
    "FederationMarketplace",
]
