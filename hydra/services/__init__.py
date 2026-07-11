"""
Application Services — business logic wrappers over HYDRA Core stores.

The ServiceContainer lazily creates all services with shared store instances.
Services emit events via EventBus after every state change.
"""

import logging
from pathlib import Path
from typing import Any

from hydra.services.event_bus import EventBus
from hydra.observability.telemetry import telemetry
from hydra.observability.health import health as health_registry

logger = logging.getLogger("hydra.services")


class ServiceContainer:
    """Creates all services with shared store instances. Lazy initialization."""

    def __init__(self, event_bus: EventBus | None = None, data_dir: str | None = None):
        self._bus = event_bus or EventBus()
        self._data_dir = Path(data_dir) if data_dir else Path("data")
        self._cache: dict[str, Any] = {}

    @property
    def event_bus(self) -> EventBus:
        return self._bus

    def _make(self, key, cls_path, cls_name):
        if key not in self._cache:
            import importlib
            with telemetry.timer(f"service.init.{key}"):
                mod = importlib.import_module(cls_path)
                cls = getattr(mod, cls_name)
                self._cache[key] = cls(self._bus, self._data_dir)
            svc = self._cache[key]
            if hasattr(svc, "get_health"):
                health_registry.register(key, svc.get_health)
        return self._cache[key]

    @property
    def system(self):
        return self._make("system", "hydra.services.system", "SystemService")

    @property
    def engagement(self):
        return self._make("engagement", "hydra.services.engagement", "EngagementService")

    @property
    def findings(self):
        return self._make("findings", "hydra.services.findings", "FindingsService")

    @property
    def knowledge(self):
        return self._make("knowledge", "hydra.services.knowledge", "KnowledgeService")

    @property
    def coverage(self):
        return self._make("coverage", "hydra.services.coverage", "CoverageService")

    @property
    def session(self):
        return self._make("session", "hydra.services.session", "SessionService")

    @property
    def scan(self):
        return self._make("scan", "hydra.services.scan", "ScanService")

    @property
    def learning(self):
        return self._make("learning", "hydra.services.learning", "LearningService")

    @property
    def monitor(self):
        return self._make("monitor", "hydra.services.monitor", "RuntimeMonitor")

    @property
    def updates(self):
        return self._make("updates", "hydra.services.updates", "UpdateChecker")

    @property
    def ingest(self):
        return self._make("ingest", "hydra.services.ingest", "IngestService")

    @property
    def extraction(self):
        return self._make("extraction", "hydra.services.extraction", "ExtractionService")

    @property
    def report_store(self):
        return self._make("report_store", "hydra.services.report_store", "ReportStoreService")

    @property
    def graph(self):
        return self._make("graph", "hydra.services.graph", "GraphService")

    @property
    def ttp(self):
        return self._make("ttp", "hydra.services.ttp", "TTPService")

    @property
    def memory(self):
        return self._make("memory", "hydra.services.memory", "MemoryService")

    @property
    def agents(self):
        return self._make("agents", "hydra.services.agents", "AgentService")

    @property
    def workflows(self):
        return self._make("workflows", "hydra.services.workflows", "WorkflowService")

    @property
    def router(self):
        return self._make("router", "hydra.services.router", "RouterService")

    @property
    def search(self):
        return self._make("search", "hydra.services.search", "SearchService")

    # ── Phase 10 services ──

    @property
    def learning_loop(self):
        return self._make("learning_loop", "hydra.services.learning_loop", "LearningLoopService")

    @property
    def confidence(self):
        return self._make("confidence", "hydra.services.confidence", "ConfidenceService")

    @property
    def quality(self):
        return self._make("quality", "hydra.services.quality", "QualityService")

    @property
    def reasoning(self):
        return self._make("reasoning", "hydra.services.reasoning", "ReasoningService")

    @property
    def context_intel(self):
        return self._make("context_intel", "hydra.services.context_intel", "ContextIntelService")

    @property
    def dual_intel(self):
        return self._make("dual_intel", "hydra.services.dual_intel", "DualIntelService")

    @property
    def collaboration(self):
        return self._make("collaboration", "hydra.services.collaboration", "CollaborationService")

    @property
    def skill_evolution(self):
        return self._make("skill_evolution", "hydra.services.skill_evolution", "SkillEvolutionService")

    @property
    def knowledge_builder(self):
        return self._make("knowledge_builder", "hydra.services.knowledge_builder", "KnowledgeBuilderService")

    @property
    def knowledge_sync(self):
        return self._make("knowledge_sync", "hydra.services.knowledge_sync", "KnowledgeSyncService")

    @property
    def copilot(self):
        return self._make("copilot", "hydra.services.copilot", "CopilotService")

    @property
    def campaign(self):
        return self._make("campaign", "hydra.services.campaign", "CampaignService")

    # ── Phase 11 services ──

    @property
    def knowledge_graph_engine(self):
        return self._make("knowledge_graph_engine", "hydra.services.knowledge_graph_engine", "KnowledgeGraphEngineService")

    # ── Autonomous Agent Engine (additive; distinct from swarm `.agents`) ──

    @property
    def agent_engine(self):
        return self._make("agent_engine", "hydra.agent.service", "AgentService")
