"""
╔══════════════════════════════════════════════════════════════╗
║  World Model Engine — Cognitive Target Modeling             ║
║  Builds internal model of target: architecture, trust       ║
║  boundaries, auth flows, privilege hierarchies, services    ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.world_model")


class EntityType(str, Enum):
    APPLICATION = "application"
    API_ENDPOINT = "api_endpoint"
    SERVICE = "service"
    DATABASE = "database"
    IDENTITY = "identity"
    ROLE = "role"
    SESSION = "session"
    TOKEN = "token"
    PERMISSION = "permission"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    DOMAIN = "domain"
    FORM = "form"
    WORKFLOW = "workflow"
    TRUST_BOUNDARY = "trust_boundary"


class RelationType(str, Enum):
    AUTHENTICATES = "authenticates"
    AUTHORIZES = "authorizes"
    TRUSTS = "trusts"
    DEPENDS_ON = "depends_on"
    CONNECTS_TO = "connects_to"
    CONTAINS = "contains"
    MANAGES = "manages"
    EXPOSES = "exposes"
    INHERITS = "inherits"
    ESCALATES_TO = "escalates_to"
    TRANSITIONS_TO = "transitions_to"
    PROCESSES = "processes"


@dataclass
class WorldEntity:
    """An entity in the target's world model."""
    id: str
    name: str
    entity_type: EntityType
    properties: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    confidence: float = 0.5
    discovered_at: float = field(default_factory=time.time)
    source: str = ""  # recon, osint, crawl, inference


@dataclass
class WorldRelation:
    """A relationship between entities."""
    source_id: str
    target_id: str
    relation_type: RelationType
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    bidirectional: bool = False


@dataclass
class TrustBoundary:
    """A trust boundary between system zones."""
    id: str
    name: str
    inside: List[str] = field(default_factory=list)   # entity IDs inside
    outside: List[str] = field(default_factory=list)   # entity IDs outside
    auth_required: bool = True
    enforcement: str = ""  # firewall, jwt, session, api_key, mTLS


@dataclass
class AttackSurface:
    """Computed attack surface for a target."""
    total_endpoints: int = 0
    auth_endpoints: int = 0
    unauth_endpoints: int = 0
    trust_boundaries: int = 0
    privilege_levels: int = 0
    external_services: int = 0
    high_value_targets: List[str] = field(default_factory=list)
    weakness_indicators: List[Dict[str, Any]] = field(default_factory=list)


class WorldModelEngine:
    """
    Cognitive Target Modeling Engine.

    Builds a continuously evolving internal model of the target:
    - Application architecture
    - Trust boundaries
    - Authentication flows
    - Authorization hierarchies
    - Privilege relationships
    - Infrastructure dependencies
    - User workflows
    - Business processes
    - API relationships
    - Cloud trust chains
    - Service interactions

    Transitions the system from 'scanning targets' to 'understanding systems'.
    """

    def __init__(self):
        self._entities: Dict[str, WorldEntity] = {}
        self._relations: List[WorldRelation] = []
        self._boundaries: Dict[str, TrustBoundary] = {}
        self._adjacency: Dict[str, List[Tuple[str, RelationType]]] = {}

    # ── Entity Management ─────────────────

    def add_entity(self, entity: WorldEntity) -> str:
        self._entities[entity.id] = entity
        if entity.id not in self._adjacency:
            self._adjacency[entity.id] = []
        return entity.id

    def add_relation(self, relation: WorldRelation):
        self._relations.append(relation)
        self._adjacency.setdefault(relation.source_id, []).append(
            (relation.target_id, relation.relation_type))
        if relation.bidirectional:
            self._adjacency.setdefault(relation.target_id, []).append(
                (relation.source_id, relation.relation_type))

    def add_trust_boundary(self, boundary: TrustBoundary):
        self._boundaries[boundary.id] = boundary

    # ── Shorthand Builders ────────────────

    def entity(self, id: str, name: str, etype: EntityType, **props) -> WorldEntity:
        e = WorldEntity(id=id, name=name, entity_type=etype, properties=props)
        self.add_entity(e)
        return e

    def relate(self, source: str, target: str, rtype: RelationType,
               confidence: float = 0.5, **props) -> WorldRelation:
        r = WorldRelation(source_id=source, target_id=target,
                          relation_type=rtype, confidence=confidence, properties=props)
        self.add_relation(r)
        return r

    # ── Queries ───────────────────────────

    def get_entity(self, entity_id: str) -> Optional[WorldEntity]:
        return self._entities.get(entity_id)

    def get_entities_by_type(self, etype: EntityType) -> List[WorldEntity]:
        return [e for e in self._entities.values() if e.entity_type == etype]

    def get_neighbors(self, entity_id: str,
                      relation_filter: Optional[RelationType] = None) -> List[WorldEntity]:
        """Get all entities connected to the given entity."""
        neighbors = []
        for target_id, rtype in self._adjacency.get(entity_id, []):
            if relation_filter and rtype != relation_filter:
                continue
            entity = self._entities.get(target_id)
            if entity:
                neighbors.append(entity)
        return neighbors

    def find_path(self, from_id: str, to_id: str,
                  max_depth: int = 10) -> Optional[List[str]]:
        """Find shortest path between two entities (BFS)."""
        if from_id not in self._entities or to_id not in self._entities:
            return None
        visited: Set[str] = set()
        queue = [(from_id, [from_id])]
        while queue:
            current, path = queue.pop(0)
            if current == to_id:
                return path
            if current in visited or len(path) > max_depth:
                continue
            visited.add(current)
            for next_id, _ in self._adjacency.get(current, []):
                if next_id not in visited:
                    queue.append((next_id, path + [next_id]))
        return None

    def find_escalation_paths(self, from_role: str) -> List[List[str]]:
        """Find all privilege escalation paths from a role."""
        paths = []
        def walk(current: str, path: List[str], visited: Set[str]):
            for target_id, rtype in self._adjacency.get(current, []):
                if target_id in visited:
                    continue
                if rtype in (RelationType.ESCALATES_TO, RelationType.INHERITS, RelationType.MANAGES):
                    new_path = path + [target_id]
                    paths.append(new_path)
                    walk(target_id, new_path, visited | {target_id})
        walk(from_role, [from_role], {from_role})
        return paths

    def get_trust_violations(self) -> List[Dict[str, Any]]:
        """Find potential trust boundary violations."""
        violations = []
        for boundary in self._boundaries.values():
            inside_set = set(boundary.inside)
            for entity_id in boundary.inside:
                for target_id, rtype in self._adjacency.get(entity_id, []):
                    if target_id not in inside_set and rtype in (
                        RelationType.CONNECTS_TO, RelationType.EXPOSES, RelationType.TRUSTS
                    ):
                        violations.append({
                            "boundary": boundary.name,
                            "source": entity_id,
                            "target": target_id,
                            "relation": rtype.value,
                            "issue": f"Entity {entity_id} crosses trust boundary '{boundary.name}' "
                                     f"via {rtype.value} to {target_id}",
                        })
        return violations

    # ── Inference ─────────────────────────

    def infer_auth_flow(self) -> List[Dict[str, Any]]:
        """Infer authentication flows from the model."""
        flows = []
        for entity in self.get_entities_by_type(EntityType.API_ENDPOINT):
            auth_entities = self.get_neighbors(entity.id, RelationType.AUTHENTICATES)
            authz_entities = self.get_neighbors(entity.id, RelationType.AUTHORIZES)
            if not auth_entities and not authz_entities:
                flows.append({
                    "endpoint": entity.name,
                    "issue": "No authentication or authorization relationship found",
                    "severity": "high",
                })
            elif not authz_entities:
                flows.append({
                    "endpoint": entity.name,
                    "auth": [a.name for a in auth_entities],
                    "issue": "Authenticated but no authorization check",
                    "severity": "medium",
                })
        return flows

    def infer_attack_surface(self) -> AttackSurface:
        """Compute the target's attack surface from the world model."""
        endpoints = self.get_entities_by_type(EntityType.API_ENDPOINT)
        services = self.get_entities_by_type(EntityType.SERVICE)
        roles = self.get_entities_by_type(EntityType.ROLE)

        auth_eps = 0
        unauth_eps = 0
        for ep in endpoints:
            if self.get_neighbors(ep.id, RelationType.AUTHENTICATES):
                auth_eps += 1
            else:
                unauth_eps += 1

        high_value = []
        for ep in endpoints:
            props = ep.properties
            if props.get("method") in ("DELETE", "PUT", "PATCH") or "admin" in ep.name.lower():
                high_value.append(ep.name)

        weaknesses = []
        auth_issues = self.infer_auth_flow()
        for issue in auth_issues:
            weaknesses.append(issue)

        trust_violations = self.get_trust_violations()
        for tv in trust_violations:
            weaknesses.append(tv)

        return AttackSurface(
            total_endpoints=len(endpoints),
            auth_endpoints=auth_eps,
            unauth_endpoints=unauth_eps,
            trust_boundaries=len(self._boundaries),
            privilege_levels=len(roles),
            external_services=len(services),
            high_value_targets=high_value,
            weakness_indicators=weaknesses,
        )

    # ── Population from Recon ─────────────

    def populate_from_crawl(self, endpoints: List[Dict[str, Any]]):
        """Populate the model from crawl/recon data."""
        for ep in endpoints:
            e = self.entity(
                id=f"ep_{ep.get('path', '')}_{ep.get('method', 'GET')}",
                name=f"{ep.get('method', 'GET')} {ep.get('path', '')}",
                etype=EntityType.API_ENDPOINT,
                method=ep.get("method", "GET"),
                path=ep.get("path", ""),
                auth_required=ep.get("auth_required", False),
            )
            if ep.get("auth_required"):
                auth_id = "auth_system"
                if auth_id not in self._entities:
                    self.entity(auth_id, "Authentication System", EntityType.SERVICE)
                self.relate(e.id, auth_id, RelationType.AUTHENTICATES)

    def populate_from_technologies(self, techs: List[str]):
        """Populate the model from detected technologies."""
        for tech in techs:
            self.entity(f"tech_{tech.lower().replace(' ', '_')}", tech,
                        EntityType.SERVICE, technology=True)

    # ── Summary ───────────────────────────

    @property
    def entity_count(self) -> int:
        return len(self._entities)

    @property
    def relation_count(self) -> int:
        return len(self._relations)

    def get_summary(self) -> Dict[str, Any]:
        by_type = {}
        for e in self._entities.values():
            by_type[e.entity_type.value] = by_type.get(e.entity_type.value, 0) + 1
        return {
            "entities": self.entity_count,
            "relations": self.relation_count,
            "trust_boundaries": len(self._boundaries),
            "by_type": by_type,
        }
