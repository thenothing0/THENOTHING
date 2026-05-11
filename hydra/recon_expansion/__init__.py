"""
╔══════════════════════════════════════════════════════════════╗
║  Autonomous Recon Expansion Engine                           ║
║  Recursive asset inference, naming-pattern prediction,       ║
║  hidden asset discovery, trust-boundary expansion            ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import re
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.recon_expansion")


@dataclass
class InferredAsset:
    """An asset predicted by the expansion engine."""
    name: str
    asset_type: str = "domain"      # domain, url, ip, api, service
    inference_method: str = ""      # naming_pattern, port_prediction, service_inference
    confidence: float = 0.3
    reasoning: str = ""
    source_asset: str = ""          # The asset that triggered this inference
    verified: bool = False


# ── Naming Pattern Rules ──────────────────────

NAMING_PATTERNS = [
    # (regex_match, replacements, reasoning)
    (r"^api\.", [
        ("admin-api.", "API prefix suggests admin API"),
        ("internal-api.", "API prefix suggests internal API"),
        ("staging-api.", "API prefix suggests staging API"),
    ]),
    (r"^app\.", [
        ("admin.", "App prefix suggests admin panel"),
        ("staging.", "App suggests staging env"),
        ("api.", "App suggests API backend"),
    ]),
    (r"^www\.", [
        ("admin.", "WWW suggests admin panel"),
        ("api.", "WWW suggests API"),
        ("staging.", "WWW suggests staging"),
        ("dev.", "WWW suggests dev"),
    ]),
    (r"prod", [
        ("staging", "Production suggests staging"),
        ("dev", "Production suggests dev"),
        ("uat", "Production suggests UAT"),
    ]),
    (r"-v\d+", [
        ("-v1", "Versioned API suggests v1"),
        ("-v2", "Versioned API suggests v2"),
    ]),
    (r"^mail\.", [
        ("webmail.", "Mail suggests webmail"),
        ("smtp.", "Mail suggests SMTP"),
        ("imap.", "Mail suggests IMAP"),
    ]),
    (r"^(vpn|remote)\.", [
        ("sso.", "VPN suggests SSO portal"),
        ("auth.", "VPN suggests auth portal"),
    ]),
]

# Service inference from discovered assets
SERVICE_INFERENCES = {
    "grafana": ["prometheus", "alertmanager", "loki"],
    "jenkins": ["gitlab", "artifactory", "sonarqube", "nexus"],
    "kubernetes-dashboard": ["etcd", "kubelet", "kube-apiserver"],
    "gitlab": ["registry", "mattermost", "pages"],
    "jira": ["confluence", "bitbucket", "bamboo"],
    "elasticsearch": ["kibana", "logstash", "cerebro"],
    "consul": ["vault", "nomad"],
    "argocd": ["tekton", "flux"],
    "harbor": ["trivy", "clair"],
}

# Cloud-specific inferences
CLOUD_INFERENCES = {
    "s3.amazonaws.com": [
        ("ec2", "S3 suggests EC2 instances", 0.4),
        ("rds", "S3 suggests RDS databases", 0.3),
        ("lambda", "S3 suggests Lambda functions", 0.3),
    ],
    "azurewebsites.net": [
        ("blob.core.windows.net", "Azure App suggests Blob storage", 0.4),
        ("database.windows.net", "Azure App suggests SQL Database", 0.3),
    ],
    "run.app": [
        ("storage.googleapis.com", "Cloud Run suggests GCS buckets", 0.4),
        ("cloudfunctions.net", "Cloud Run suggests Cloud Functions", 0.3),
    ],
}

# Port-based service predictions
PORT_PREDICTIONS = {
    80: [8080, 8443, 443],
    443: [8443, 8080, 3000, 4443],
    22: [2222],
    3306: [5432, 27017, 6379],
    8080: [8081, 8443, 9090],
    9090: [9091, 3000],  # Prometheus → Grafana
}


class ReconExpansionEngine:
    """
    Autonomous Reconnaissance Expansion Engine.

    Recursively expands the attack surface by:
      - Inferring hidden assets from naming patterns
      - Predicting related services from discovered infrastructure
      - Expanding trust boundaries based on cloud/K8s topology
      - Discovering forgotten/legacy assets from naming conventions
      - Correlating cross-domain relationships

    Example:
      Detected: corp-admin-api
      Infer: SSO portals, staging systems, K8s dashboards, CI/CD, Grafana, internal APIs
    """

    def __init__(self):
        self._discovered: Set[str] = set()
        self._inferred: List[InferredAsset] = []
        self._expansion_history: List[Dict[str, Any]] = []

    def expand(self, assets: List[str],
               asset_types: Optional[Dict[str, str]] = None) -> List[InferredAsset]:
        """
        Expand attack surface from known assets.

        Returns list of inferred assets not yet discovered.
        """
        asset_types = asset_types or {}
        self._discovered.update(assets)
        new_inferred = []

        for asset in assets:
            # Naming pattern expansion
            new_inferred.extend(self._naming_pattern_expansion(asset))

            # Service inference
            new_inferred.extend(self._service_inference(asset))

            # Cloud infrastructure expansion
            new_inferred.extend(self._cloud_expansion(asset))

            # Subdomain pattern expansion
            new_inferred.extend(self._subdomain_pattern_expansion(asset, assets))

        # Deduplicate and filter already-discovered
        seen = set()
        unique = []
        for inferred in new_inferred:
            if inferred.name not in self._discovered and inferred.name not in seen:
                seen.add(inferred.name)
                unique.append(inferred)

        self._inferred.extend(unique)
        self._expansion_history.append({
            "timestamp": time.time(),
            "input_assets": len(assets),
            "new_inferred": len(unique),
        })

        logger.info(f"🔍 Recon expansion: {len(assets)} assets → {len(unique)} inferred")
        return unique

    def _naming_pattern_expansion(self, asset: str) -> List[InferredAsset]:
        """Infer assets from naming patterns."""
        results = []
        for pattern, replacements, *_ in NAMING_PATTERNS:
            if re.search(pattern, asset):
                for replacement, reasoning in replacements:
                    inferred_name = re.sub(pattern, replacement, asset, count=1)
                    if inferred_name != asset:
                        results.append(InferredAsset(
                            name=inferred_name,
                            inference_method="naming_pattern",
                            confidence=0.3,
                            reasoning=reasoning,
                            source_asset=asset,
                        ))
        return results

    def _service_inference(self, asset: str) -> List[InferredAsset]:
        """Infer related services from discovered services."""
        results = []
        asset_lower = asset.lower()

        for service, related in SERVICE_INFERENCES.items():
            if service in asset_lower:
                base_domain = self._extract_base_domain(asset)
                for rel_service in related:
                    inferred = f"{rel_service}.{base_domain}" if base_domain else rel_service
                    results.append(InferredAsset(
                        name=inferred,
                        asset_type="service",
                        inference_method="service_inference",
                        confidence=0.25,
                        reasoning=f"{service} typically runs alongside {rel_service}",
                        source_asset=asset,
                    ))
        return results

    def _cloud_expansion(self, asset: str) -> List[InferredAsset]:
        """Infer cloud resources from cloud-hosted assets."""
        results = []
        for cloud_pattern, inferences in CLOUD_INFERENCES.items():
            if cloud_pattern in asset:
                for service, reasoning, confidence in inferences:
                    results.append(InferredAsset(
                        name=f"{self._extract_prefix(asset)}.{service}",
                        asset_type="cloud_resource",
                        inference_method="cloud_inference",
                        confidence=confidence,
                        reasoning=reasoning,
                        source_asset=asset,
                    ))
        return results

    def _subdomain_pattern_expansion(self, asset: str,
                                      all_assets: List[str]) -> List[InferredAsset]:
        """Infer subdomains from patterns across discovered domains."""
        results = []
        # Extract common prefixes
        prefixes: Dict[str, int] = {}
        for a in all_assets:
            parts = a.split(".")
            if len(parts) > 2:
                prefix = parts[0]
                prefixes[prefix] = prefixes.get(prefix, 0) + 1

        # Common prefixes to try
        common_prefixes = ["admin", "staging", "dev", "test", "internal",
                           "api", "dashboard", "portal", "sso", "auth",
                           "monitoring", "metrics", "logs", "ci", "cd",
                           "vpn", "mail", "docs", "wiki", "git"]

        base_domain = self._extract_base_domain(asset)
        if base_domain:
            existing_prefixes = set(prefixes.keys())
            for prefix in common_prefixes:
                if prefix not in existing_prefixes:
                    results.append(InferredAsset(
                        name=f"{prefix}.{base_domain}",
                        inference_method="common_prefix",
                        confidence=0.15,
                        reasoning=f"Common subdomain prefix '{prefix}' not yet discovered",
                        source_asset=asset,
                    ))

        return results[:10]  # Limit to avoid explosion

    # ── Helpers ───────────────────────────────

    @staticmethod
    def _extract_base_domain(asset: str) -> str:
        parts = asset.replace("https://", "").replace("http://", "").split("/")[0].split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return asset

    @staticmethod
    def _extract_prefix(asset: str) -> str:
        parts = asset.replace("https://", "").replace("http://", "").split(".")
        return parts[0] if parts else asset

    async def suggest_expansion(self, observations, beliefs) -> List[Dict[str, Any]]:
        """Suggest expansion actions based on cognitive state."""
        actions = []
        # Extract assets from observations
        assets = []
        for obs in observations:
            if hasattr(obs, 'data'):
                asset = obs.data.get("domain", "") or obs.data.get("asset", "")
                if asset:
                    assets.append(asset)

        if assets:
            inferred = self.expand(assets)
            for inf in inferred[:5]:
                actions.append({
                    "type": "verify_inferred_asset",
                    "asset": inf.name,
                    "confidence": inf.confidence,
                    "reasoning": inf.reasoning,
                })
        return actions

    def mark_verified(self, asset_name: str, exists: bool):
        """Mark an inferred asset as verified or not."""
        for inf in self._inferred:
            if inf.name == asset_name:
                inf.verified = exists
                if exists:
                    self._discovered.add(asset_name)
                    logger.info(f"✅ Inferred asset verified: {asset_name}")

    def get_summary(self) -> Dict[str, Any]:
        verified = sum(1 for i in self._inferred if i.verified)
        return {
            "discovered_assets": len(self._discovered),
            "inferred_assets": len(self._inferred),
            "verified": verified,
            "expansion_rounds": len(self._expansion_history),
        }
