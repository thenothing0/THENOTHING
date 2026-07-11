"""Router Service — multi-model AI routing as a service.

Wraps AIRouter with provider management, model selection,
and task-type routing exposed through the service layer.
"""

import logging
from typing import Any

from hydra.services.base import BaseService

logger = logging.getLogger("hydra.services.router")

TASK_TYPES = (
    "reasoning", "exploit_hypothesis", "cve_mapping",
    "report_generation", "scoring", "classification",
    "code_analysis", "extraction", "ttp_extraction",
    "vulnerability_analysis", "recon_planning",
)

MODEL_TIERS = {
    "fast": {"description": "Low-latency, cost-efficient", "examples": ["gpt-4o-mini", "claude-haiku-4-5"]},
    "balanced": {"description": "Good balance of quality and speed", "examples": ["gpt-4o", "claude-sonnet-4"]},
    "deep": {"description": "Maximum reasoning depth", "examples": ["o1", "claude-opus-4"]},
}


class RouterService(BaseService):
    """Multi-model AI routing and provider management."""

    def query(self, prompt: str, task_type: str = "reasoning",
              model: str = "", context: str = "") -> dict:
        """Route a query to the best available model."""
        if task_type not in TASK_TYPES:
            task_type = "reasoning"
        try:
            from hydra.ai.router import AIRouter
            router = AIRouter()
            result = router.query(prompt, task_type=task_type)
            self._emit("router.query_completed", {
                "task_type": task_type,
                "model": result.get("model", "unknown"),
            })
            return result
        except (ImportError, Exception) as e:
            return self._fallback_query(prompt, task_type, str(e))

    def select_model(self, task_type: str = "reasoning") -> dict:
        """Select the best model for a task type without querying."""
        try:
            from hydra.ai.router import AIRouter
            router = AIRouter()
            provider = router._select_provider(task_type)
            return {
                "task_type": task_type,
                "provider": provider.get("id", "unknown") if isinstance(provider, dict) else str(provider),
                "tier": self._infer_tier(task_type),
            }
        except (ImportError, Exception):
            return {
                "task_type": task_type,
                "provider": "fallback",
                "tier": self._infer_tier(task_type),
            }

    def list_providers(self) -> list[dict]:
        """List available AI providers."""
        try:
            from hydra.ai.router import AIRouter
            router = AIRouter()
            providers = router.list_providers()
            return providers if isinstance(providers, list) else []
        except (ImportError, Exception):
            return self._fallback_providers()

    def get_provider_health(self) -> dict:
        """Get health status of all providers."""
        try:
            from hydra.ai.router import AIRouter
            router = AIRouter()
            return router.get_health()
        except (ImportError, Exception):
            return {"status": "unknown", "providers": []}

    def list_task_types(self) -> list[dict]:
        """List supported task types with descriptions."""
        descriptions = {
            "reasoning": "General reasoning and analysis",
            "exploit_hypothesis": "Vulnerability hypothesis generation",
            "cve_mapping": "CVE identification and mapping",
            "report_generation": "Security report writing",
            "scoring": "Severity and risk scoring",
            "classification": "Vulnerability classification",
            "code_analysis": "Source code security review",
            "extraction": "Field extraction from text",
            "ttp_extraction": "MITRE ATT&CK TTP extraction",
            "vulnerability_analysis": "Deep vulnerability analysis",
            "recon_planning": "Reconnaissance strategy planning",
        }
        return [
            {"type": t, "description": descriptions.get(t, ""),
             "tier": self._infer_tier(t)}
            for t in TASK_TYPES
        ]

    def list_model_tiers(self) -> list[dict]:
        """List model tiers and their characteristics."""
        return [
            {"tier": k, **v} for k, v in MODEL_TIERS.items()
        ]

    def get_stats(self) -> dict[str, Any]:
        """Router statistics."""
        return {
            "task_type_count": len(TASK_TYPES),
            "task_types": list(TASK_TYPES),
            "tier_count": len(MODEL_TIERS),
            "tiers": list(MODEL_TIERS.keys()),
        }

    def _infer_tier(self, task_type: str) -> str:
        deep_tasks = ("exploit_hypothesis", "vulnerability_analysis", "code_analysis")
        fast_tasks = ("classification", "scoring", "extraction")
        if task_type in deep_tasks:
            return "deep"
        if task_type in fast_tasks:
            return "fast"
        return "balanced"

    def _fallback_query(self, prompt: str, task_type: str, error: str) -> dict:
        self._emit("router.query_completed", {
            "task_type": task_type, "model": "fallback", "fallback": True,
        })
        return {
            "status": "fallback",
            "task_type": task_type,
            "model": "none",
            "response": "",
            "error": error,
        }

    def _fallback_providers(self) -> list[dict]:
        return [
            {"id": "anthropic", "status": "unknown", "models": ["claude-sonnet-4", "claude-opus-4"]},
            {"id": "openai", "status": "unknown", "models": ["gpt-4o", "gpt-4o-mini"]},
            {"id": "ollama", "status": "unknown", "models": ["llama3", "codellama"]},
        ]
