"""
Source adapters — turn a declared `Source` into actual collected values.

Resolution order (offline-first):
  1. Cached/fixture adapter — if cached evidence exists for (source, domain).
     This is what keeps the whole pipeline runnable offline.
  2. Local-tool adapter — wraps an existing MCP tool (subfinder/amass/...).
  3. None — the source is declared but has no adapter yet (Phase E network
     adapters). The pipeline records it as skipped; selecting it explicitly in
     online mode raises SourceUnavailable.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Sequence

from hydra.capabilities.adapters import cached as _cached
from hydra.capabilities.adapters import local_tools as _local
from hydra.capabilities.sources import ExecutionPolicy, Source, SourceUnavailable


def collect(
    source: Source,
    domain: str,
    policy: Optional[ExecutionPolicy] = None,
    fixtures_dirs: Optional[Sequence[Path]] = None,
) -> List[str]:
    """Collect raw values for one source. Empty list if no adapter / no data."""
    policy = policy or ExecutionPolicy.offline()

    # 1. cached evidence (always offline-capable)
    vals = _cached.collect(source, domain, fixtures_dirs)
    if vals:
        return vals

    # 2. local tool wrapper (offline_capable sources only)
    if source.offline_capable and _local.supports(source):
        return _local.collect(source, domain)

    # 3. no adapter
    if policy.mode == "online" and source.requires_network and not source.offline_capable:
        raise SourceUnavailable(
            f"{source.id}: no adapter yet (Phase E network adapter required)")
    return []


def has_adapter(source: Source, domain: str = "", fixtures_dirs=None) -> bool:
    if _cached.collect(source, domain, fixtures_dirs):
        return True
    return source.offline_capable and _local.supports(source)
