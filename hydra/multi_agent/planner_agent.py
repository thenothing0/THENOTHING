"""PlannerAgent — decomposition, sequencing and priorities for the team.

Offline and rule-based (reuses the single-agent engine's ``prompts`` tables). It
produces role-tagged :class:`AgentTask` objects carrying REAL HYDRA commands, with
dependencies and priorities, and NEVER executes anything. Specialist roles then own
execution.
"""

from __future__ import annotations

from typing import Any

from hydra.agent import prompts
from hydra.multi_agent.models import AgentRole, AgentTask, MessageType, MTaskState

# Which specialist role owns each capability step.
_STEP_ROLE: dict[str, AgentRole] = {
    "scope": AgentRole.RECON,
    "recon": AgentRole.RECON,
    "scan": AgentRole.WEB,
    "attack": AgentRole.WEB,
    "knowledge": AgentRole.KNOWLEDGE,
    "report": AgentRole.REPORT,
    "status": AgentRole.KNOWLEDGE,
}

_NETWORK_HINTS = ("network", "infra", "infrastructure", "port", "nmap", "internal")


def _mark_initial(tasks: list[AgentTask]) -> None:
    done = {t.id for t in tasks if t.state == MTaskState.COMPLETED}
    for task in tasks:
        if task.is_terminal:
            continue
        task.state = MTaskState.READY if all(d in done for d in task.depends_on) else MTaskState.WAITING


def build_task_plan(objective: str) -> list[AgentTask]:
    """Decompose an objective into role-tagged tasks over real commands."""
    target = prompts.extract_target(objective)
    steps = prompts.detect_steps(objective)
    vulns = prompts.extract_vuln_classes(objective) or list(prompts.DEFAULT_SCAN_CLASSES)
    want_network = any(h in objective.lower() for h in _NETWORK_HINTS)

    tasks: list[AgentTask] = []
    scope_id: str | None = None
    recon_id: str | None = None
    offensive: list[str] = []

    def add(desc, command, role, priority, confidence, parallel, deps=None):
        task = AgentTask(description=desc, command=command, role=role, priority=priority,
                         confidence=confidence, parallel_safe=parallel, depends_on=deps or [])
        tasks.append(task)
        return task

    for step in steps:
        if step in ("scope", "recon", "scan", "attack") and not target:
            continue
        role = _STEP_ROLE.get(step, AgentRole.KNOWLEDGE)
        priority, conf, parallel = prompts.STEP_META.get(step, (5, 0.5, False))

        if step == "scope":
            scope_id = add(f"Register scope for {target}", f"/scope {target}", role,
                           priority, conf, parallel).id
        elif step == "recon":
            deps = [scope_id] if scope_id else []
            recon_id = add(f"Recon {target}", f"/recon {target}", role, priority, conf,
                           parallel, deps).id
            if want_network:
                add(f"Network recon {target}", f"/recon {target}", AgentRole.NETWORK,
                    priority - 1, conf, parallel, list(deps))
        elif step == "scan":
            deps = [recon_id] if recon_id else ([scope_id] if scope_id else [])
            for vuln in vulns:
                offensive.append(
                    add(f"Scan {target} for {vuln}", f"/scan {target} {vuln}", role,
                        priority, conf, parallel, list(deps)).id)
        elif step == "attack":
            deps = [recon_id] if recon_id else ([scope_id] if scope_id else [])
            offensive.append(
                add(f"Attack {target}", f"/attack {target} --classes={','.join(vulns)}",
                    role, priority, conf, parallel, list(deps)).id)
        elif step == "knowledge":
            add(f"Knowledge lookup {target or objective.strip()}",
                f"/search {target or objective.strip()}", role, priority, conf, True)
        elif step == "report":
            add("Aggregate reports", "/reports", role, priority, conf, parallel, list(offensive))
        elif step == "status":
            add("System status", "/status", role, priority, conf, parallel)

    if not tasks:
        add("System status", "/status", AgentRole.KNOWLEDGE, 9, 0.95, True)

    _mark_initial(tasks)
    return tasks


class PlannerAgent:
    """Wraps :func:`build_task_plan` and (optionally) announces on the message bus."""

    role = AgentRole.PLANNER

    def __init__(self, agent_id: str = "planner-1", message_bus=None):
        self.agent_id = agent_id
        self._bus = message_bus

    def plan(self, objective: str, context: Any = None) -> list[AgentTask]:
        tasks = build_task_plan(objective)
        if self._bus is not None:
            try:
                self._bus.publish_from(self.agent_id, MessageType.PLANNING_UPDATE,
                                       {"tasks": len(tasks)})
            except Exception:
                pass
        return tasks
