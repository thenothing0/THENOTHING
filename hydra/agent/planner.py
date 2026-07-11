"""Planner — turns a natural-language objective into an ExecutionPlan.

Offline and rule-based (no LLM, no network). It decomposes the objective into
an ordered set of :class:`Task` objects whose ``command`` fields are REAL HYDRA
command strings, with dependencies, priorities and confidence. It also performs
dynamic replanning from reflections.

The planner NEVER executes anything — it only produces plans.
"""

from __future__ import annotations

from typing import Any

from hydra.agent import prompts
from hydra.agent.models import (
    ExecutionPlan,
    Goal,
    ReflectionAction,
    Task,
    TaskState,
)


class Planner:
    """Rule-based goal decomposition and replanning over real HYDRA commands."""

    def __init__(self, confidence_floor: float = 0.2):
        self.confidence_floor = confidence_floor

    # ── Planning ──

    def plan(self, objective: str, context: Any = None) -> ExecutionPlan:
        """Decompose ``objective`` into an ordered :class:`ExecutionPlan`."""
        target = prompts.extract_target(objective)
        goal = Goal(objective=objective.strip(), target=target)
        steps = prompts.detect_steps(objective)
        vuln_classes = prompts.extract_vuln_classes(objective) or list(
            prompts.DEFAULT_SCAN_CLASSES
        )
        ctx_boost = self._context_boost(context, target)

        tasks: list[Task] = []
        scope_id: str | None = None
        recon_id: str | None = None
        offensive_ids: list[str] = []

        for step in steps:
            if step in ("scope", "recon", "scan", "attack") and not target:
                continue  # these steps require a target
            priority, base_conf, parallel = prompts.STEP_META.get(step, (5, 0.5, False))
            confidence = min(0.99, round(base_conf + ctx_boost, 3))

            if step == "scope":
                task = self._task(f"Register scope for {target}", f"/scope {target}",
                                  priority, confidence, parallel)
                scope_id = task.id
                tasks.append(task)
            elif step == "recon":
                deps = [scope_id] if scope_id else []
                task = self._task(f"Reconnaissance on {target}", f"/recon {target}",
                                  priority, confidence, parallel, deps)
                recon_id = task.id
                tasks.append(task)
            elif step == "scan":
                deps = [recon_id] if recon_id else ([scope_id] if scope_id else [])
                for vuln in vuln_classes:
                    task = self._task(f"Scan {target} for {vuln}",
                                      f"/scan {target} {vuln}", priority, confidence,
                                      parallel, list(deps))
                    offensive_ids.append(task.id)
                    tasks.append(task)
            elif step == "attack":
                deps = [recon_id] if recon_id else ([scope_id] if scope_id else [])
                classes = ",".join(vuln_classes)
                task = self._task(f"Attack campaign on {target}",
                                  f"/attack {target} --classes={classes}",
                                  priority, confidence, parallel, list(deps))
                offensive_ids.append(task.id)
                tasks.append(task)
            elif step == "knowledge":
                query = target or objective.strip()
                task = self._task(f"Search knowledge for {query}",
                                  f"/search {query}", priority, confidence, parallel)
                tasks.append(task)
            elif step == "report":
                deps = list(offensive_ids)
                task = self._task("List reports", "/reports", priority, confidence,
                                  parallel, deps)
                tasks.append(task)
            elif step == "status":
                task = self._task("System status", "/status", priority, confidence, parallel)
                tasks.append(task)

        if not tasks:
            # No target and no actionable step — degrade to a status probe.
            tasks.append(self._task("System status", "/status", 9, 0.95, True))

        self._mark_initial_states(tasks)
        return ExecutionPlan(
            goal=goal, tasks=tasks,
            stop_conditions=list(prompts.STOP_CONDITIONS),
        )

    # ── Replanning ──

    def replan(self, plan: ExecutionPlan, reflections: list, context: Any = None
               ) -> ExecutionPlan:
        """Update ``plan`` in place from task reflections; bump revision."""
        for reflection in reflections:
            task = plan.task_by_id(getattr(reflection, "task_id", ""))
            if task is None:
                continue
            action = getattr(reflection, "action", ReflectionAction.CONTINUE)
            if action == ReflectionAction.RETRY:
                if task.attempts < task.max_attempts:
                    task.state = TaskState.WAITING
                    task.error = ""
            elif action == ReflectionAction.ALTERNATIVE:
                alt = getattr(reflection, "alternative_command", "")
                if alt:
                    task.command = alt
                    task.state = TaskState.WAITING
                    task.error = ""
            elif action == ReflectionAction.ABORT:
                for other in plan.tasks:
                    if not other.is_terminal:
                        other.state = TaskState.CANCELLED
                break
        plan.revision += 1
        self._mark_initial_states(plan.tasks)
        return plan

    # ── Helpers ──

    def _task(self, description: str, command: str, priority: int, confidence: float,
              parallel: bool, depends_on: list[str] | None = None) -> Task:
        return Task(
            description=description,
            command=command,
            priority=priority,
            confidence=confidence,
            parallel_safe=parallel,
            depends_on=depends_on or [],
        )

    def _mark_initial_states(self, tasks: list[Task]) -> None:
        """A task with no unmet deps is READY; otherwise WAITING."""
        done = {t.id for t in tasks if t.state == TaskState.COMPLETED}
        for task in tasks:
            if task.is_terminal:
                continue
            if all(dep in done for dep in task.depends_on):
                task.state = TaskState.READY
            else:
                task.state = TaskState.WAITING

    def _context_boost(self, context: Any, target: str) -> float:
        """Small confidence boost when prior knowledge exists for the target."""
        if context is None or not target:
            return 0.0
        try:
            known = getattr(context, "known_targets", None)
            if known is None and isinstance(context, dict):
                known = context.get("known_targets")
            if known and target in known:
                return 0.1
        except Exception:
            return 0.0
        return 0.0
