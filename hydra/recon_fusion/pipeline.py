"""
Recon knowledge fusion pipeline.

    Source Collection -> Normalization -> Deduplication -> Evidence Aggregation
    -> Confidence Scoring -> Asset Intelligence -> Knowledge Graph Update

Raw tool output NEVER becomes knowledge directly — it always flows through this
pipeline, which is capability-first (selects sources by capability + offline-first
policy) and pure enough to run fully offline against cached fixtures.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from hydra.capabilities import CapabilityRegistry, ExecutionPolicy
from hydra.capabilities import adapters as _adapters
from hydra.capabilities.sources import SourceUnavailable
from hydra.knowledge.confidence import score_from_sources
from hydra.knowledge.schema import slugify
from hydra.recon_fusion.asset import AssetIntelligence
from hydra.recon_fusion.normalize import dedup

logger = logging.getLogger("hydra.recon_fusion.pipeline")


@dataclass
class FusionResult:
    domain: str
    capability: str
    assets: List[AssetIntelligence] = field(default_factory=list)
    sources_run: List[str] = field(default_factory=list)
    sources_skipped: List[str] = field(default_factory=list)
    raw_count: int = 0
    materialized: List[str] = field(default_factory=list)  # wiki page paths

    def summary(self) -> Dict:
        breakdown: Dict[str, int] = {}
        for a in self.assets:
            c = a.confidence.value if hasattr(a.confidence, "value") else a.confidence
            breakdown[c] = breakdown.get(c, 0) + 1
        return {
            "domain": self.domain,
            "capability": self.capability,
            "unique_assets": len(self.assets),
            "raw_observations": self.raw_count,
            "sources_run": self.sources_run,
            "sources_skipped": self.sources_skipped,
            "confidence_breakdown": breakdown,
        }


class ReconFusionPipeline:
    def __init__(self, registry: Optional[CapabilityRegistry] = None):
        self.registry = (registry or CapabilityRegistry()).load()

    def run(
        self,
        domain: str,
        capability: str = "discover_subdomains",
        policy: Optional[ExecutionPolicy] = None,
        target: Optional[str] = None,
        fixtures_dirs: Optional[Sequence[Path]] = None,
        materialize: bool = False,
    ) -> FusionResult:
        policy = policy or ExecutionPolicy.offline()
        cap = self.registry.get(capability)
        if not cap:
            raise KeyError(f"unknown capability: {capability}")
        output_type = cap.outputs[0] if cap.outputs else "subdomain"
        weights = cap.source_weights()

        result = FusionResult(domain=domain, capability=capability)

        # 1. Collect (capability-first, policy-gated)
        rows: List[tuple] = []
        for source in cap.runnable_sources(policy):
            try:
                vals = _adapters.collect(source, domain, policy, fixtures_dirs)
            except SourceUnavailable:
                result.sources_skipped.append(source.id)
                continue
            if vals:
                result.sources_run.append(source.id)
                rows.extend((v, source.id) for v in vals)
            else:
                result.sources_skipped.append(source.id)
        result.raw_count = len(rows)

        # 2-4. Normalize + dedup + aggregate evidence
        grouped = dedup(rows, output_type)

        # 5-6. Score + build Asset Intelligence
        target_slug = slugify(target or _base_domain(domain))
        for asset_value, srcs in grouped.items():
            result.assets.append(AssetIntelligence(
                asset=asset_value,
                type=_asset_type_for(output_type),
                sources=srcs,
                confidence=score_from_sources(srcs, weights),
                related_targets=[target_slug] if target_slug else [],
            ))

        # 7. Graph update (canonical wiki write, then index rebuild) — opt-in
        if materialize and result.assets:
            from hydra.knowledge.bridge import materialize_assets  # lazy: avoid import cycle
            result.materialized = materialize_assets(result.assets)

        logger.info("recon_fusion: %s/%s -> %d assets", domain, capability, len(result.assets))
        return result


def _asset_type_for(output_type: str) -> str:
    return {"subdomain": "subdomain", "url": "url", "endpoint": "url",
            "ip": "ip", "cloud_bucket": "cloud_bucket"}.get(output_type, "subdomain")


def _base_domain(domain: str) -> str:
    d = (domain or "").strip().lower().lstrip("*.").rstrip(".")
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d
