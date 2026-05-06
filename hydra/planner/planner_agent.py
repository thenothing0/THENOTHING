"""
╔══════════════════════════════════════════════════════════════╗
║  Planner Agent — Strategic Decision Maker above Coordinator ║
║  Adaptive replanning, AI-enhanced strategy, scope-aware     ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional

from hydra.planner.task_decomposer import (
    TaskDecomposer, ExecutionPlan, PlanStep,
    PlanStatus, TaskConfidence,
)

logger = logging.getLogger("hydra.planner.agent")


class PlannerAgent:
    """
    Strategic Planner Agent — sits above the Coordinator.
    
    Responsibilities:
      1. Break high-level goals into subtasks
      2. Dynamically generate workflows
      3. Adapt strategy based on findings
      4. Prioritize scans based on confidence
      5. Optimize scan order
      6. Perform recursive planning
    """

    def __init__(self, bus=None, ai_router=None, attack_graph=None):
        self.bus = bus
        self.ai = ai_router
        self.attack_graph = attack_graph
        self.decomposer = TaskDecomposer()
        self._active_plans: Dict[str, ExecutionPlan] = {}

    async def create_plan(
        self, target: str,
        goal: str = "Perform full security assessment",
        scope_context: Optional[Dict[str, Any]] = None,
    ) -> ExecutionPlan:
        """Create an execution plan for a target."""
        if self.ai:
            enhanced = await self._ai_enhanced_planning(
                target, goal, scope_context
            )
            if enhanced:
                goal = enhanced

        plan = self.decomposer.decompose(goal, target, scope_context)

        if scope_context:
            plan = self._apply_scope_restrictions(plan, scope_context)

        plan = self._optimize_step_order(plan)
        self._active_plans[plan.plan_id] = plan
        plan.status = PlanStatus.ACTIVE

        if self.bus:
            await self.bus.set_state(f"plan:{plan.plan_id}", {
                "plan_id": plan.plan_id, "target": target,
                "goal": goal, "status": plan.status,
                "total_steps": len(plan.steps),
                "revision": plan.revision,
            })

        logger.info(
            f"📋 Plan created: {plan.plan_id} — "
            f"{len(plan.steps)} steps, rev {plan.revision}"
        )
        return plan

    async def replan(
        self, plan_id: str,
        findings: List[Dict[str, Any]],
        reason: str = "adaptive",
    ) -> Optional[ExecutionPlan]:
        """Dynamically replan based on new findings."""
        plan = self._active_plans.get(plan_id)
        if not plan:
            return None

        plan.status = PlanStatus.REPLANNING
        plan.revision += 1
        plan.updated_at = time.time()

        adaptation = {
            "revision": plan.revision, "reason": reason,
            "timestamp": time.time(),
            "trigger_findings": len(findings),
            "added_steps": [], "reprioritized": [],
        }

        new_steps = self._generate_adaptive_steps(plan, findings)
        for step in new_steps:
            plan.steps.append(step)
            adaptation["added_steps"].append(step.id)

        reprioritized = self._reprioritize_pending(plan, findings)
        adaptation["reprioritized"] = reprioritized

        plan.adaptations.append(adaptation)
        plan.status = PlanStatus.ACTIVE

        logger.info(
            f"🔄 Replanned: {plan_id} → rev {plan.revision}, "
            f"+{len(new_steps)} steps"
        )
        return plan

    def _generate_adaptive_steps(
        self, plan: ExecutionPlan, findings: List[Dict[str, Any]]
    ) -> List[PlanStep]:
        """Generate new steps based on findings."""
        new_steps = []
        counter = len(plan.steps)

        for finding in findings:
            severity = str(finding.get("severity", "")).lower()
            f_type = str(finding.get("type", "")).lower()

            if severity in ("critical", "high"):
                step_id = f"{plan.plan_id}:adaptive-{counter:03d}"
                counter += 1
                new_steps.append(PlanStep(
                    id=step_id, phase="adaptive_investigation",
                    task_type="deep_investigation",
                    agent_type="exploit_hypothesis", priority=0,
                    confidence=TaskConfidence.HIGH,
                    parameters={"finding": finding, "mode": "deep"},
                ))

            if "ssrf" in f_type:
                step_id = f"{plan.plan_id}:adaptive-{counter:03d}"
                counter += 1
                new_steps.append(PlanStep(
                    id=step_id, phase="adaptive_ssrf",
                    task_type="ssrf_chain_analysis",
                    agent_type="exploit_hypothesis", priority=0,
                    parameters={"trigger": finding},
                ))

            if any(k in f_type for k in ["auth", "login", "credential"]):
                step_id = f"{plan.plan_id}:adaptive-{counter:03d}"
                counter += 1
                new_steps.append(PlanStep(
                    id=step_id, phase="adaptive_auth",
                    task_type="auth_chain_analysis",
                    agent_type="exploit_hypothesis", priority=1,
                    parameters={"trigger": finding},
                ))

        return new_steps

    def _reprioritize_pending(
        self, plan: ExecutionPlan, findings: List[Dict[str, Any]]
    ) -> List[str]:
        has_critical = any(
            f.get("severity", "").lower() in ("critical", "high")
            for f in findings
        )
        reprioritized = []
        for step in plan.steps:
            if step.status != PlanStatus.PENDING:
                continue
            if has_critical and step.agent_type in ("validation", "reporting"):
                step.priority = min(step.priority, 0 if step.agent_type == "validation" else 1)
                reprioritized.append(step.id)
        return reprioritized

    def _apply_scope_restrictions(
        self, plan: ExecutionPlan, scope: Dict[str, Any]
    ) -> ExecutionPlan:
        forbidden = scope.get("forbidden_testing", [])
        filtered = []
        for step in plan.steps:
            blocked = any(
                f.lower() in step.task_type.lower() for f in forbidden
            )
            if not blocked:
                filtered.append(step)
            else:
                logger.info(f"🚫 Step blocked by scope: {step.task_type}")
        rate_limit = scope.get("rate_limit")
        if rate_limit:
            for step in filtered:
                step.parameters["rate_limit"] = rate_limit
        plan.steps = filtered
        return plan

    def _optimize_step_order(self, plan: ExecutionPlan) -> ExecutionPlan:
        from collections import defaultdict
        phases: Dict[str, List[PlanStep]] = defaultdict(list)
        for step in plan.steps:
            phases[step.phase].append(step)
        for phase_steps in phases.values():
            phase_steps.sort(key=lambda s: s.priority)
        return plan

    async def _ai_enhanced_planning(
        self, target: str, goal: str,
        scope: Optional[Dict[str, Any]]
    ) -> Optional[str]:
        if not self.ai:
            return None
        prompt = (
            f"Security assessment planner. Target: {target}\n"
            f"Goal: {goal}\nScope: {json.dumps(scope) if scope else 'None'}\n"
            f"Enhance with tactical recommendations (1-2 sentences)."
        )
        try:
            return await self.ai.query(
                prompt, task_type="reasoning", max_tokens=200
            )
        except Exception as e:
            logger.warning(f"AI planning failed: {e}")
            return None

    def get_plan(self, plan_id: str) -> Optional[ExecutionPlan]:
        return self._active_plans.get(plan_id)

    def get_next_executable_steps(self, plan_id: str) -> List[PlanStep]:
        plan = self._active_plans.get(plan_id)
        if not plan:
            return []
        completed = {
            s.id for s in plan.steps
            if s.status == PlanStatus.COMPLETED
        }
        ready = [
            s for s in plan.steps
            if s.status == PlanStatus.PENDING
            and all(d in completed for d in s.depends_on)
        ]
        ready.sort(key=lambda s: s.priority)
        return ready

    def mark_step_completed(
        self, plan_id: str, step_id: str, result: Dict[str, Any]
    ):
        plan = self._active_plans.get(plan_id)
        if not plan:
            return
        for step in plan.steps:
            if step.id == step_id:
                step.status = PlanStatus.COMPLETED
                step.result = result
                break

    def mark_step_failed(self, plan_id: str, step_id: str, error: str):
        plan = self._active_plans.get(plan_id)
        if not plan:
            return
        for step in plan.steps:
            if step.id == step_id:
                step.retry_count += 1
                if step.retry_count >= step.max_retries:
                    step.status = PlanStatus.FAILED
                else:
                    step.status = PlanStatus.PENDING
                break

    def get_plan_progress(self, plan_id: str) -> Dict[str, Any]:
        plan = self._active_plans.get(plan_id)
        if not plan:
            return {}
        total = len(plan.steps)
        completed = sum(1 for s in plan.steps if s.status == PlanStatus.COMPLETED)
        failed = sum(1 for s in plan.steps if s.status == PlanStatus.FAILED)
        return {
            "plan_id": plan_id, "target": plan.target,
            "goal": plan.goal, "status": plan.status,
            "revision": plan.revision, "total_steps": total,
            "completed": completed, "failed": failed,
            "pending": total - completed - failed,
            "progress_pct": round(completed / max(total, 1) * 100, 1),
            "adaptations": len(plan.adaptations),
        }
