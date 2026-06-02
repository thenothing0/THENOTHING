"""
Normalization + deduplication for recon fusion.

Raw source output is messy (schemes, ports, paths, trailing dots, casing,
wildcards). Normalization yields a stable canonical key per asset so that the
same host found by different sources deduplicates correctly. Junk that isn't a
valid host/URL is dropped — raw output never becomes knowledge unfiltered.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")


def normalize_host(value: str) -> Optional[str]:
    """Canonicalize a host: strip scheme/path/port/wildcard, lowercase. None if invalid."""
    if not value:
        return None
    v = value.strip().lower()
    v = re.sub(r"^[a-z0-9+.\-]+://", "", v)      # strip scheme
    v = v.split("/")[0]                           # strip path
    v = v.split("@")[-1]                          # strip userinfo
    v = v.split(":")[0]                           # strip port
    v = v.lstrip("*.").rstrip(".")                # strip wildcard + trailing dot
    if not v or not _HOST_RE.match(v) or "." not in v:
        return None
    return v


def normalize_url(value: str) -> Optional[str]:
    """Light URL normalization: require scheme, lowercase host, drop fragments."""
    if not value:
        return None
    v = value.strip()
    if not re.match(r"^https?://", v, re.IGNORECASE):
        return None
    v = v.split("#")[0]
    return v.rstrip("/") or v


def normalize_value(value: str, output_type: str) -> Optional[str]:
    """Dispatch by capability output type."""
    if output_type in ("url", "endpoint"):
        return normalize_url(value)
    # subdomain / live_host / asset / host / dns_record default to host normalization
    return normalize_host(value)


def dedup(rows: List[Tuple[str, str]], output_type: str = "subdomain") -> Dict[str, List[str]]:
    """Group (raw_value, source_id) rows into {normalized_asset: [distinct source ids]}.

    Independence is by source id (the stable key); a source counts once per asset.
    """
    grouped: Dict[str, set] = {}
    for raw, source_id in rows:
        norm = normalize_value(raw, output_type)
        if not norm or not source_id:
            continue
        grouped.setdefault(norm, set()).add(source_id)
    return {asset: sorted(srcs) for asset, srcs in sorted(grouped.items())}
