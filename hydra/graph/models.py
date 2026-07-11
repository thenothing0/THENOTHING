"""Knowledge graph data models — typed entities and relationships."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class EntityType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    HOST = "host"
    ORGANIZATION = "organization"
    PRODUCT = "product"
    VENDOR = "vendor"
    TECHNOLOGY = "technology"
    SERVICE = "service"
    CVE = "cve"
    CWE = "cwe"
    CAPEC = "capec"
    ATTACK_TECHNIQUE = "attack_technique"
    ATTACK_TACTIC = "attack_tactic"
    VULNERABILITY = "vulnerability"
    IOC = "ioc"
    MALWARE = "malware"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"


class RelationshipType(str, Enum):
    HOSTS = "hosts"
    USES = "uses"
    RUNS = "runs"
    DISCOVERED_IN = "discovered_in"
    TARGETS = "targets"
    EXPLOITS = "exploits"
    AFFECTS = "affects"
    MITIGATED_BY = "mitigated_by"
    DETECTED_BY = "detected_by"
    RELATED_TO = "related_to"
    BELONGS_TO = "belongs_to"


@dataclass
class Node:
    """A typed entity in the knowledge graph."""

    id: str
    type: EntityType
    name: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    source: str = ""
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if isinstance(self.type, str):
            self.type = EntityType(self.type)
        self.confidence = max(0.0, min(1.0, self.confidence))

    def merge(self, other: Node) -> None:
        """Merge another node's data into this one (higher confidence wins for conflicts)."""
        if other.confidence > self.confidence:
            self.confidence = other.confidence
            self.source = other.source
        for k, v in other.attributes.items():
            if k not in self.attributes:
                self.attributes[k] = v
        if other.timestamp > self.timestamp:
            self.timestamp = other.timestamp


@dataclass
class Edge:
    """A typed, directed relationship in the knowledge graph."""

    source: str
    target: str
    relationship: RelationshipType
    confidence: float = 1.0
    evidence: List[str] = field(default_factory=list)
    provenance: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if isinstance(self.relationship, str):
            self.relationship = RelationshipType(self.relationship)
        self.confidence = max(0.0, min(1.0, self.confidence))

    @property
    def key(self) -> tuple:
        """Unique identity for deduplication."""
        return (self.source, self.target, self.relationship.value)

    def merge(self, other: Edge) -> None:
        """Merge another edge's data into this one."""
        if other.confidence > self.confidence:
            self.confidence = other.confidence
        for e in other.evidence:
            if e not in self.evidence:
                self.evidence.append(e)
        for p in other.provenance:
            if p not in self.provenance:
                self.provenance.append(p)
        if other.timestamp > self.timestamp:
            self.timestamp = other.timestamp


@dataclass
class GraphStats:
    """Summary statistics for a knowledge graph."""

    node_count: int = 0
    edge_count: int = 0
    node_types: Dict[str, int] = field(default_factory=dict)
    edge_types: Dict[str, int] = field(default_factory=dict)
    avg_degree: float = 0.0
    density: float = 0.0
    connected_components: int = 0
