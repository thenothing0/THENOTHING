"""
hydra.recon_fusion — recon as knowledge acquisition (Phase A).

Turns multi-source reconnaissance into validated Asset Intelligence through a
fixed pipeline (Collect→Normalize→Dedup→Aggregate→Score→AssetIntel→Graph),
capability-first and offline-first.
"""

from hydra.recon_fusion.asset import AssetIntelligence  # noqa: F401
from hydra.recon_fusion.pipeline import FusionResult, ReconFusionPipeline  # noqa: F401
