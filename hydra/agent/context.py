"""ContextBuilder — assembles a read-only AgentContext for the planner.

Gathers, best-effort and bounded, from whatever HYDRA surfaces are available:
knowledge graph, scope, findings, reports, available tools, plus the agent's own
recent commands and failures. Every external call is guarded — a missing or slow
surface degrades to an empty field, never an exception. Strictly read-only: it
never modifies the graph, scope, or any store.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hydra.agent import prompts

_MAX = 20


@dataclass
class AgentContext:
    """Everything the planner is allowed to see. Read-only snapshot."""

    objective: str = ""
    target: str = ""
    known_targets: list[str] = field(default_factory=list)
    scope: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    reports: list[dict] = field(default_factory=list)
    tools: dict[str, bool] = field(default_factory=dict)
    recent_commands: list[str] = field(default_factory=list)
    recent_failures: list[str] = field(default_factory=list)
    knowledge_hits: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "target": self.target,
            "known_targets": list(self.known_targets),
            "scope": list(self.scope),
            "findings": list(self.findings),
            "reports": list(self.reports),
            "tools": dict(self.tools),
            "recent_commands": list(self.recent_commands),
            "recent_failures": list(self.recent_failures),
            "knowledge_hits": list(self.knowledge_hits),
        }


class ContextBuilder:
    """Builds an :class:`AgentContext` from optional HYDRA surfaces (read-only)."""

    def __init__(self, facade: Any = None):
        self._facade = facade

    def build(
        self,
        objective: str,
        target: str = "",
        recent_commands: list[str] | None = None,
        recent_failures: list[str] | None = None,
    ) -> AgentContext:
        target = target or prompts.extract_target(objective)
        recent_commands = list(recent_commands or [])[-_MAX:]
        recent_failures = list(recent_failures or [])[-_MAX:]

        ctx = AgentContext(
            objective=objective,
            target=target,
            recent_commands=recent_commands,
            recent_failures=recent_failures,
        )
        ctx.known_targets = self._known_targets(recent_commands, target)
        if self._facade is not None and target:
            ctx.knowledge_hits = self._safe(lambda: self._facade.search_knowledge(target), [])[:_MAX]
        if self._facade is not None:
            ctx.reports = self._safe(lambda: self._facade.list_reports(), [])[:_MAX]
            ctx.tools = self._safe(lambda: self._facade.check_tools(), {})
        return ctx

    # ── Helpers ──

    def _known_targets(self, recent_commands: list[str], target: str) -> list[str]:
        seen: list[str] = []
        for cmd in recent_commands:
            tgt = prompts.extract_target(cmd)
            if tgt and tgt not in seen:
                seen.append(tgt)
        if target and target not in seen:
            seen.append(target)
        return seen[:_MAX]

    @staticmethod
    def _safe(fn, default):
        try:
            value = fn()
            return value if value is not None else default
        except Exception:
            return default
