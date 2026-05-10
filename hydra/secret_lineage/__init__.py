"""
╔══════════════════════════════════════════════════════════════╗
║  Secret Lineage Tracker — Credential Propagation Mapping    ║
║  Tracks secrets from origin → propagation → infrastructure  ║
║  → attack path with full chain visualization                ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("hydra.secret_lineage")


class SecretType(str, Enum):
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    JWT = "jwt"
    DATABASE_URL = "database_url"
    PRIVATE_KEY = "private_key"
    OAUTH_SECRET = "oauth_secret"
    SERVICE_ACCOUNT = "service_account"
    ENV_VARIABLE = "env_variable"
    CI_TOKEN = "ci_token"
    CLOUD_CREDENTIAL = "cloud_credential"
    SESSION_TOKEN = "session_token"
    WEBHOOK_SECRET = "webhook_secret"


class PropagationStage(str, Enum):
    ORIGIN = "origin"           # Where the secret was first created
    STORAGE = "storage"         # Where it's stored (env, vault, config)
    PIPELINE = "pipeline"       # CI/CD pipeline exposure
    DEPLOYMENT = "deployment"   # Deployment artifact exposure
    RUNTIME = "runtime"         # Runtime exposure (headers, logs, responses)
    LATERAL = "lateral"         # Lateral movement to other systems
    EXFILTRATION = "exfiltration"  # External exposure


@dataclass
class SecretNode:
    """A node in the secret lineage graph."""
    id: str
    name: str
    stage: PropagationStage
    description: str = ""
    system: str = ""               # github, ci_pipeline, k8s, aws, api_server
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class SecretEdge:
    """Propagation path between nodes."""
    source: str
    target: str
    mechanism: str = ""            # env_injection, config_file, api_call, deployment
    confidence: float = 0.5
    evidence: str = ""


@dataclass
class SecretChain:
    """A complete secret propagation chain."""
    secret_type: SecretType
    secret_id: str
    value_hint: str = ""           # First/last chars only for identification
    nodes: List[SecretNode] = field(default_factory=list)
    edges: List[SecretEdge] = field(default_factory=list)
    risk_score: float = 0.0
    blast_radius: int = 0          # Number of systems affected
    remediation: List[str] = field(default_factory=list)


class SecretLineageTracker:
    """
    Secret Lineage Tracking Engine.

    Tracks the full lifecycle of discovered secrets:
      origin → storage → pipeline → deployment → runtime → lateral

    Example chain:
      GitHub Secret → CI Pipeline → Deployment Token → Cloud Account → Internal API

    Capabilities:
      - Secret origin identification
      - Propagation path mapping
      - Privilege inheritance tracking
      - Environment variable exposure chains
      - Blast radius estimation
      - Remediation chain generation
    """

    def __init__(self):
        self._chains: Dict[str, SecretChain] = {}
        self._nodes: Dict[str, SecretNode] = {}
        self._edges: List[SecretEdge] = []

    def register_secret(self, secret_type: SecretType, secret_id: str,
                        origin: str, system: str, value_hint: str = "",
                        confidence: float = 0.7) -> SecretChain:
        """Register a newly discovered secret and create its lineage chain."""
        chain = SecretChain(
            secret_type=secret_type,
            secret_id=secret_id,
            value_hint=value_hint,
        )

        # Create origin node
        origin_node = SecretNode(
            id=f"{secret_id}_origin",
            name=origin,
            stage=PropagationStage.ORIGIN,
            system=system,
            confidence=confidence,
            description=f"Secret first discovered in {system}",
        )
        chain.nodes.append(origin_node)
        self._nodes[origin_node.id] = origin_node
        self._chains[secret_id] = chain

        logger.info(f"Registered secret lineage: {secret_type.value} from {system}")
        return chain

    def add_propagation(self, secret_id: str, target_name: str,
                        stage: PropagationStage, system: str,
                        mechanism: str = "", evidence: str = "",
                        confidence: float = 0.5) -> Optional[SecretNode]:
        """Add a propagation step to a secret's lineage."""
        chain = self._chains.get(secret_id)
        if not chain:
            logger.warning(f"Unknown secret: {secret_id}")
            return None

        node = SecretNode(
            id=f"{secret_id}_{stage.value}_{len(chain.nodes)}",
            name=target_name,
            stage=stage,
            system=system,
            confidence=confidence,
            description=f"Secret propagated to {target_name} via {mechanism}",
        )
        chain.nodes.append(node)
        self._nodes[node.id] = node

        # Create edge from previous node
        if len(chain.nodes) >= 2:
            prev = chain.nodes[-2]
            edge = SecretEdge(
                source=prev.id, target=node.id,
                mechanism=mechanism, confidence=confidence,
                evidence=evidence,
            )
            chain.edges.append(edge)
            self._edges.append(edge)

        # Recalculate risk
        self._calculate_risk(chain)
        return node

    def build_chain_from_finding(self, finding: Dict[str, Any]) -> Optional[SecretChain]:
        """
        Automatically build a lineage chain from a security finding.

        Infers propagation based on finding metadata.
        """
        secret_type = self._classify_secret(finding)
        if not secret_type:
            return None

        source = finding.get("source", "unknown")
        secret_id = f"{secret_type.value}_{hash(finding.get('value', ''))}"
        value = finding.get("value", "")
        hint = f"{value[:4]}...{value[-4:]}" if len(value) > 8 else "***"

        chain = self.register_secret(
            secret_type=secret_type,
            secret_id=secret_id,
            origin=source,
            system=finding.get("system", "unknown"),
            value_hint=hint,
        )

        # Auto-infer propagation based on source
        if source == "github":
            self.add_propagation(secret_id, "CI/CD Pipeline", PropagationStage.PIPELINE,
                                  "github_actions", "env_injection",
                                  "Secret referenced in GitHub Actions workflow")
            self.add_propagation(secret_id, "Deployment", PropagationStage.DEPLOYMENT,
                                  "container", "build_arg",
                                  "Secret used during container build")
        elif source == "js_bundle":
            self.add_propagation(secret_id, "Browser Client", PropagationStage.RUNTIME,
                                  "browser", "hardcoded",
                                  "Secret hardcoded in JavaScript bundle")
        elif source == "config_file":
            self.add_propagation(secret_id, "Application Runtime", PropagationStage.RUNTIME,
                                  "application", "config_load",
                                  "Secret loaded from configuration file")
        elif source == "http_response":
            self.add_propagation(secret_id, "API Response", PropagationStage.RUNTIME,
                                  "api_server", "response_body",
                                  "Secret exposed in HTTP response body")
            self.add_propagation(secret_id, "External Access", PropagationStage.EXFILTRATION,
                                  "internet", "api_response",
                                  "Secret accessible via public API")

        return chain

    def get_chain(self, secret_id: str) -> Optional[SecretChain]:
        return self._chains.get(secret_id)

    def get_all_chains(self) -> List[SecretChain]:
        return list(self._chains.values())

    def get_critical_chains(self, min_risk: float = 0.7) -> List[SecretChain]:
        """Get chains with risk score above threshold."""
        return [c for c in self._chains.values() if c.risk_score >= min_risk]

    def generate_remediation(self, secret_id: str) -> List[str]:
        """Generate remediation steps for a secret chain."""
        chain = self._chains.get(secret_id)
        if not chain:
            return []

        steps = []
        steps.append(f"1. Revoke/rotate the {chain.secret_type.value}")

        for node in chain.nodes:
            if node.stage == PropagationStage.ORIGIN:
                if node.system == "github":
                    steps.append(f"2. Remove from GitHub repository: {node.name}")
                    steps.append("3. Scrub from git history (git filter-branch or BFG)")
                elif node.system == "config_file":
                    steps.append(f"2. Remove from config file: {node.name}")
            elif node.stage == PropagationStage.PIPELINE:
                steps.append(f"4. Update CI/CD pipeline to use secret manager instead of env vars")
            elif node.stage == PropagationStage.DEPLOYMENT:
                steps.append(f"5. Redeploy affected services with rotated credentials")
            elif node.stage == PropagationStage.RUNTIME:
                steps.append(f"6. Clear runtime caches and invalidate sessions")
            elif node.stage == PropagationStage.EXFILTRATION:
                steps.append(f"7. URGENT: Assume compromise — audit access logs for the secret")

        steps.append(f"8. Monitor for unauthorized usage of the {chain.secret_type.value}")
        chain.remediation = steps
        return steps

    def _classify_secret(self, finding: Dict[str, Any]) -> Optional[SecretType]:
        """Classify a finding into a SecretType."""
        stype = finding.get("secret_type", "").lower()
        mapping = {
            "aws": SecretType.CLOUD_CREDENTIAL,
            "api_key": SecretType.API_KEY,
            "jwt": SecretType.JWT,
            "database": SecretType.DATABASE_URL,
            "private_key": SecretType.PRIVATE_KEY,
            "oauth": SecretType.OAUTH_SECRET,
            "github_token": SecretType.ACCESS_TOKEN,
            "bearer": SecretType.ACCESS_TOKEN,
            "session": SecretType.SESSION_TOKEN,
            "webhook": SecretType.WEBHOOK_SECRET,
            "service_account": SecretType.SERVICE_ACCOUNT,
        }
        for key, value in mapping.items():
            if key in stype:
                return value
        return SecretType.API_KEY if stype else None

    def _calculate_risk(self, chain: SecretChain):
        """Calculate risk score based on propagation depth and stages."""
        base = 0.3
        # More propagation = higher risk
        base += min(len(chain.nodes) * 0.1, 0.3)
        # Critical stages boost risk
        stages = {n.stage for n in chain.nodes}
        if PropagationStage.EXFILTRATION in stages:
            base += 0.3
        if PropagationStage.LATERAL in stages:
            base += 0.2
        if PropagationStage.RUNTIME in stages:
            base += 0.1
        # Secret type severity
        if chain.secret_type in (SecretType.PRIVATE_KEY, SecretType.CLOUD_CREDENTIAL):
            base += 0.2
        elif chain.secret_type in (SecretType.DATABASE_URL, SecretType.SERVICE_ACCOUNT):
            base += 0.15

        chain.risk_score = min(round(base, 2), 1.0)
        chain.blast_radius = len(chain.nodes)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_chains": len(self._chains),
            "total_nodes": len(self._nodes),
            "critical_chains": len(self.get_critical_chains()),
            "by_type": {},
        }
