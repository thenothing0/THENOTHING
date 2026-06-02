"""
hydra.capabilities — capability-first reconnaissance (Phase A).

Tools are implementation details; the system reasons over capabilities
(discover_subdomains, http_probe, dns_intelligence, ...). Each capability
declares its sources in `capabilities/*.yaml`; the registry resolves sources
and an offline-first ExecutionPolicy gates which may run.
"""

from hydra.capabilities.registry import Capability, CapabilityRegistry  # noqa: F401
from hydra.capabilities.sources import (  # noqa: F401
    ExecutionPolicy,
    Source,
    SourceCategory,
    SourceUnavailable,
)
