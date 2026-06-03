"""
hydra.adapters — Adapter Framework & Sandboxed Tool Integrations (Phase K).

Transforms the capability-centric tool catalog into deterministic, executable ADAPTER
DEFINITIONS, with a sandboxed runtime, event-sourced tool-health learning, capability
exercise metrics, and learning-driven adapter selection.

This layer is INFRASTRUCTURE + ORCHESTRATION + OBSERVABILITY ONLY. It introduces NO
offensive execution, NO exploitation, NO autonomous actions, and NO wiki mutation. Only
SAFE execution profiles (offline / passive / validation / simulation) are permitted;
unsupported (offensive) profiles are rejected. All state is derived/disposable under
`data/` and rebuildable; promotion.py and confidence.py are untouched.
"""

from hydra.adapters.adapter_registry import (  # noqa: F401
    SAFE_PROFILES,
    UNSUPPORTED_PROFILES,
    AdapterDefinition,
    AdapterRegistry,
    ProfileError,
    make_adapter_id,
    validate_profile,
)
from hydra.adapters.intelligence import (  # noqa: F401
    AdapterIntelligence,
    CapabilityExerciseAnalyzer,
    CapabilityExerciseReport,
    RuntimeAnalytics,
)
from hydra.adapters.runtime import (  # noqa: F401
    AdapterRuntimeError,
    RuntimeResult,
    SandboxedAdapterRuntime,
)
from hydra.adapters.selection import AdapterScore, AdapterSelector  # noqa: F401
from hydra.adapters.tool_health import AdapterHealth, ToolHealthStore  # noqa: F401
