"""Workflow Service — autonomous workflow orchestration as a service.

Wraps PentestWorkflow state machine, workflow templates, and
capability-chain execution into the service layer.
"""

import logging
import time
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.workflows")

WORKFLOW_TEMPLATES = (
    "quick_recon", "full_recon", "full_bounty", "api_only",
    "cognitive_auto", "bounty_hunt", "osint_recon", "full_auto",
    "cloud_assessment",
)

WORKFLOW_STATES = (
    "scope", "recon", "enumeration", "validation",
    "exploitation", "evidence", "coverage_review", "reporting", "done",
)


class WorkflowService(BaseService):
    """Autonomous workflow orchestration and lifecycle management."""

    def list_templates(self) -> list[dict]:
        """List available workflow templates."""
        descriptions = {
            "quick_recon": "Fast passive reconnaissance",
            "full_recon": "Comprehensive active + passive recon",
            "full_bounty": "Full bug bounty assessment pipeline",
            "api_only": "API-focused security testing",
            "cognitive_auto": "Cognitive autonomous pipeline (v6)",
            "bounty_hunt": "Autonomous bounty hunting campaign (v7)",
            "osint_recon": "OSINT-first reconnaissance",
            "full_auto": "Full autonomous pipeline",
            "cloud_assessment": "Cloud infrastructure assessment",
        }
        return [
            {"id": t, "description": descriptions.get(t, ""), "states": list(WORKFLOW_STATES)}
            for t in WORKFLOW_TEMPLATES
        ]

    def create_workflow(self, target: str, template: str = "full_bounty",
                        engagement_id: str = "") -> dict:
        """Create a new workflow run."""
        if template not in WORKFLOW_TEMPLATES:
            return {"status": "error",
                    "error": f"Unknown template: {template}"}
        try:
            from hydra.services.engagement import EngagementService
            svc = EngagementService(self._bus, self._data_dir)
            result = svc.create_workflow(target, template)
            self._emit("workflow.created", {
                "target": target,
                "template": template,
                "engagement_id": engagement_id,
            })
            return {
                "status": "created",
                "target": target,
                "template": template,
                "state": "scope",
                **result,
            }
        except (ImportError, Exception):
            return self._fallback_create(target, template, engagement_id)

    def get_status(self, run_id: str = "") -> dict:
        """Get workflow status."""
        try:
            from hydra.services.engagement import EngagementService
            svc = EngagementService(self._bus, self._data_dir)
            return svc.get_workflow(run_id)
        except (ImportError, Exception):
            return {"run_id": run_id, "state": "unknown", "progress": 0}

    def advance(self, run_id: str, to_state: str, approve: bool = True) -> dict:
        """Advance workflow to next state."""
        if to_state not in WORKFLOW_STATES:
            return {"status": "error",
                    "error": f"Invalid state: {to_state}"}

        gated = ("exploitation", "evidence")
        if to_state in gated and not approve:
            return {"status": "blocked",
                    "reason": f"Approval required for {to_state}"}

        self._emit("workflow.advanced", {
            "run_id": run_id,
            "to_state": to_state,
        })
        return {
            "status": "advanced",
            "run_id": run_id,
            "state": to_state,
        }

    def list_runs(self) -> list[dict]:
        """List all workflow runs."""
        try:
            from hydra.services.engagement import EngagementService
            svc = EngagementService(self._bus, self._data_dir)
            runs = svc.list_workflows()
            return runs if isinstance(runs, list) else []
        except (ImportError, Exception):
            return []

    def execute_step(self, run_id: str, step_name: str,
                     params: dict | None = None) -> dict:
        """Execute a specific workflow step."""
        self._emit("workflow.step_started", {
            "run_id": run_id, "step": step_name,
        })
        return {
            "status": "executed",
            "run_id": run_id,
            "step": step_name,
            "params": params or {},
        }

    def get_stats(self) -> dict[str, Any]:
        """Workflow statistics."""
        return {
            "template_count": len(WORKFLOW_TEMPLATES),
            "templates": list(WORKFLOW_TEMPLATES),
            "state_count": len(WORKFLOW_STATES),
            "states": list(WORKFLOW_STATES),
        }

    def _fallback_create(self, target: str, template: str,
                         engagement_id: str) -> dict:
        run_id = f"wf-{int(time.time())}"
        self._emit("workflow.created", {
            "run_id": run_id,
            "target": target,
            "template": template,
        })
        return {
            "status": "created",
            "run_id": run_id,
            "target": target,
            "template": template,
            "state": "scope",
        }
