"""
SandboxedAdapterRuntime (Phase K).

A sandboxed coordination layer over adapter definitions. It performs adapter validation,
input validation, output normalization, timeout tracking, and execution accounting — but
it NEVER launches a real tool, exploits a target, performs offensive activity, or mutates
the wiki. The only operations it exposes are dry_run(), simulate(), and validate().

  * dry_run()  — resolve + validate the adapter and return the execution PLAN that WOULD
                 run (no process is ever spawned). Accounted as an `execution` health event.
  * simulate() — produce a schema-shaped synthetic output (no real data). Accounted as a
                 `simulation` health event.
  * validate() — validate adapter + inputs against the declared schema. Accounted as a
                 `validation` health event.

Timeout tracking is structural: a measured/injected duration over the adapter's declared
`timeout_seconds` is recorded as a `timeout` outcome. Deterministic given an injected clock.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from hydra.adapters.adapter_registry import (
    AdapterDefinition,
    AdapterRegistry,
    validate_profile,
)
from hydra.adapters.tool_health import (
    EV_EXECUTION,
    EV_SIMULATION,
    EV_VALIDATION,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    OUTCOME_TIMEOUT,
    ToolHealthStore,
)

# Schema type token → a synthetic, deterministic default value (never real data).
_SCHEMA_DEFAULTS: Dict[str, object] = {
    "str": "", "int": 0, "float": 0.0, "bool": False, "list": [], "dict": {},
}


class AdapterRuntimeError(ValueError):
    """Raised when an adapter cannot be resolved for a sandboxed operation."""


@dataclass
class RuntimeResult:
    adapter_id: str
    operation: str                 # validate | dry_run | simulate
    ok: bool
    outcome: str                   # success | failure | timeout
    profile: str = ""
    executed: bool = False         # ALWAYS False — nothing is ever really executed
    runtime_ms: float = 0.0
    missing_inputs: List[str] = field(default_factory=list)
    plan: Dict = field(default_factory=dict)
    output: Dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> Dict:
        return {
            "adapter_id": self.adapter_id, "operation": self.operation, "ok": self.ok,
            "outcome": self.outcome, "profile": self.profile, "executed": self.executed,
            "runtime_ms": round(self.runtime_ms, 4), "missing_inputs": self.missing_inputs,
            "plan": self.plan, "output": self.output, "error": self.error,
        }


class SandboxedAdapterRuntime:
    def __init__(self, registry: Optional[AdapterRegistry] = None,
                 health: Optional[ToolHealthStore] = None,
                 clock: Optional[Callable[[], float]] = None):
        self.registry = (registry or AdapterRegistry()).load()
        self.health = health or ToolHealthStore()
        self.clock = clock or time.perf_counter

    # ── helpers ──────────────────────────────────────────────────────────────────
    def _require(self, adapter_id: str) -> AdapterDefinition:
        a = self.registry.get_adapter(adapter_id)
        if a is None:
            raise AdapterRuntimeError(f"unknown adapter: {adapter_id}")
        return a

    @staticmethod
    def _missing(adapter: AdapterDefinition, inputs: Dict) -> List[str]:
        return sorted(k for k in adapter.input_schema if k not in (inputs or {}))

    @staticmethod
    def _normalize_output(adapter: AdapterDefinition, raw: Optional[Dict]) -> Dict:
        """Coerce a (possibly partial) result into the declared output schema, filling
        missing fields with schema-typed synthetic defaults. Deterministic."""
        raw = raw or {}
        out: Dict[str, object] = {}
        for key, typ in sorted(adapter.output_schema.items()):
            out[key] = raw.get(key, _SCHEMA_DEFAULTS.get(str(typ), None))
        return out

    def _account(self, adapter: AdapterDefinition, event_type: str, outcome: str,
                 runtime_ms: float) -> None:
        self.health.record(adapter.adapter_id, event_type, outcome, runtime_ms=runtime_ms,
                           capability_id=adapter.capability_id, category=adapter.category)

    def _timed_outcome(self, adapter: AdapterDefinition, ok: bool,
                       runtime_ms: float) -> str:
        if runtime_ms > adapter.timeout_seconds * 1000.0:
            return OUTCOME_TIMEOUT
        return OUTCOME_SUCCESS if ok else OUTCOME_FAILURE

    # ── sandboxed operations ──────────────────────────────────────────────────────
    def validate(self, adapter_id: str, inputs: Optional[Dict] = None) -> RuntimeResult:
        """Validate the adapter (profile safe) + inputs (required fields present)."""
        t0 = self.clock()
        adapter = self._require(adapter_id)
        validate_profile(adapter.execution_profile)   # raises on unsupported profile
        missing = self._missing(adapter, inputs or {})
        runtime_ms = (self.clock() - t0) * 1000.0
        ok = not missing
        outcome = self._timed_outcome(adapter, ok, runtime_ms)
        self._account(adapter, EV_VALIDATION, outcome, runtime_ms)
        return RuntimeResult(
            adapter_id=adapter_id, operation="validate", ok=ok, outcome=outcome,
            profile=adapter.execution_profile, runtime_ms=runtime_ms,
            missing_inputs=missing,
            error="" if ok else f"missing required inputs: {missing}")

    def dry_run(self, adapter_id: str, inputs: Optional[Dict] = None) -> RuntimeResult:
        """Return the execution PLAN that WOULD run. Nothing is ever executed."""
        t0 = self.clock()
        adapter = self._require(adapter_id)
        validate_profile(adapter.execution_profile)
        missing = self._missing(adapter, inputs or {})
        ok = not missing
        plan = {
            "tool": adapter.tool_name, "capability_id": adapter.capability_id,
            "execution_profile": adapter.execution_profile,
            "timeout_seconds": adapter.timeout_seconds,
            "would_execute": False,                     # SANDBOXED — never true
            "resolved_inputs": dict(sorted((inputs or {}).items())),
            "expected_outputs": adapter.supported_outputs,
        }
        runtime_ms = (self.clock() - t0) * 1000.0
        outcome = self._timed_outcome(adapter, ok, runtime_ms)
        self._account(adapter, EV_EXECUTION, outcome, runtime_ms)
        return RuntimeResult(
            adapter_id=adapter_id, operation="dry_run", ok=ok, outcome=outcome,
            profile=adapter.execution_profile, executed=False, runtime_ms=runtime_ms,
            missing_inputs=missing, plan=plan,
            error="" if ok else f"missing required inputs: {missing}")

    def simulate(self, adapter_id: str, inputs: Optional[Dict] = None,
                 sample_output: Optional[Dict] = None) -> RuntimeResult:
        """Produce a schema-shaped SYNTHETIC output (no real data, no execution)."""
        t0 = self.clock()
        adapter = self._require(adapter_id)
        validate_profile(adapter.execution_profile)
        if not adapter.simulation_supported:
            raise AdapterRuntimeError(f"adapter does not support simulation: {adapter_id}")
        missing = self._missing(adapter, inputs or {})
        ok = not missing
        output = self._normalize_output(adapter, sample_output)
        runtime_ms = (self.clock() - t0) * 1000.0
        outcome = self._timed_outcome(adapter, ok, runtime_ms)
        self._account(adapter, EV_SIMULATION, outcome, runtime_ms)
        return RuntimeResult(
            adapter_id=adapter_id, operation="simulate", ok=ok, outcome=outcome,
            profile=adapter.execution_profile, executed=False, runtime_ms=runtime_ms,
            missing_inputs=missing, output=output,
            error="" if ok else f"missing required inputs: {missing}")
