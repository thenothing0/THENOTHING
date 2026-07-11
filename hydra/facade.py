"""Application Facade — single entry point for multi-step workflows.

The Facade coordinates services for complex operations.
The Presentation API delegates here; it never orchestrates services directly.
"""

from __future__ import annotations

from hydra.commands.dispatcher import CommandDispatcher, CommandContext
from hydra.commands.registry import CommandRegistry
from hydra.commands.result import CommandResult
from hydra.observability.telemetry import telemetry
from hydra.registry.capability import CapabilityRegistry
from hydra.services.event_bus import EventBus


class HydraFacade:

    def __init__(
        self,
        services,
        registry: CapabilityRegistry,
        event_bus: EventBus,
        command_registry: CommandRegistry,
    ):
        self._svc = services
        self._reg = registry
        self._bus = event_bus
        self._cmd_registry = command_registry
        self._dispatcher = CommandDispatcher(
            command_registry,
            CommandContext(services, event_bus, cmd_registry=command_registry),
        )
        self._dispatcher.set_chat_handler(self._handle_chat)
        self._ai_session = None

    # ── Command execution ──

    def execute_command(self, raw: str) -> CommandResult:
        with telemetry.timer("facade.execute_command"):
            return self._dispatcher.execute(raw)

    def complete_command(self, partial: str) -> list[str]:
        return self._dispatcher.complete(partial)

    # ── System ──

    def get_status(self) -> dict:
        return self._svc.system.get_health()

    def check_tools(self) -> dict[str, bool]:
        return self._svc.system.check_tools()

    # ── Engagement ──

    def list_engagements(self) -> list:
        return self._svc.engagement.list_engagements()

    def get_engagement(self, eid: str):
        return self._svc.engagement.get_engagement(eid)

    def create_engagement(self, **kw):
        return self._svc.engagement.create_engagement(**kw)

    # ── Findings ──

    def list_findings(self, eid: str, state: str = "") -> list:
        return self._svc.findings.list_findings(eid, state)

    def get_finding(self, fid: str):
        return self._svc.findings.get_finding(fid)

    def transition_finding(self, fid: str, to_state: str):
        return self._svc.findings.transition(fid, to_state)

    # ── Coverage ──

    def get_coverage(self, eid: str) -> dict:
        return self._svc.coverage.get_summary(eid)

    def next_targets(self, eid: str, limit: int = 10) -> list:
        return self._svc.coverage.next_targets(eid, limit)

    # ── Knowledge ──

    def search_knowledge(self, query: str, limit: int = 10) -> list:
        return self._svc.knowledge.search(query, limit)

    def get_wiki_page(self, slug: str):
        return self._svc.knowledge.get_page(slug)

    # ── Intel / Ingestion ──

    def ingest_text(self, text: str, **kw):
        return self._svc.ingest.ingest_text(text, **kw)

    def ingest_file(self, path: str, **kw):
        return self._svc.ingest.ingest_file(path, **kw)

    def ingest_batch(self, items: list[dict]):
        return self._svc.ingest.ingest_batch(items)

    def get_ingest_stats(self):
        return self._svc.ingest.get_stats()

    # ── Report Store ──

    def list_reports(self, **kw):
        return self._svc.report_store.list_reports(**kw)

    def get_report(self, slug: str):
        return self._svc.report_store.get_report(slug)

    def get_report_stats(self):
        return self._svc.report_store.get_stats()

    def aggregate_reports(self, by: str = "vuln_class"):
        if by == "target":
            return self._svc.report_store.aggregate_by_target()
        return self._svc.report_store.aggregate_by_vuln_class()

    # ── Extraction ──

    def extract_field(self, text: str, field_type: str, model: str = ""):
        return self._svc.extraction.extract_field(text, field_type, model=model)

    def extract_all(self, text: str, model: str = ""):
        return self._svc.extraction.extract_all(text, model=model)

    # ── Graph ──

    def graph_neighbors(self, slug: str, **kw):
        return self._svc.graph.neighbors(slug, **kw)

    def graph_path(self, source: str, target: str):
        return self._svc.graph.shortest_path(source, target)

    def graph_subgraph(self, center: str, depth: int = 2):
        return self._svc.graph.subgraph(center, depth=depth)

    def graph_stats(self):
        return self._svc.graph.get_stats()

    # ── TTP ──

    def extract_ttps(self, text: str):
        return self._svc.ttp.extract_ttps(text)

    def ttp_coverage(self, **kw):
        return self._svc.ttp.get_coverage(**kw)

    def generate_playbook(self, findings: list[dict]):
        return self._svc.ttp.generate_playbook(findings)

    # ── Memory ──

    def memory_recall(self, query: str, **kw):
        return self._svc.memory.recall(query, **kw)

    def memory_record(self, kind: str, content: str, **kw):
        return self._svc.memory.record(kind, content, **kw)

    # ── Agents ──

    def list_agents(self):
        return self._svc.agents.list_agents()

    def spawn_agent(self, agent_type: str, task: dict):
        return self._svc.agents.spawn_agent(agent_type, task)

    def detect_target_type(self, target: str):
        return self._svc.agents.detect_target_type(target)

    def get_agent_stats(self):
        return self._svc.agents.get_stats()

    # ── Workflows ──

    def list_workflow_templates(self):
        return self._svc.workflows.list_templates()

    def create_workflow(self, target: str, **kw):
        return self._svc.workflows.create_workflow(target, **kw)

    def advance_workflow(self, run_id: str, to_state: str, **kw):
        return self._svc.workflows.advance(run_id, to_state, **kw)

    def get_workflow_stats(self):
        return self._svc.workflows.get_stats()

    # ── Router ──

    def router_query(self, prompt: str, **kw):
        return self._svc.router.query(prompt, **kw)

    def router_select_model(self, task_type: str = "reasoning"):
        return self._svc.router.select_model(task_type)

    def list_router_providers(self):
        return self._svc.router.list_providers()

    def get_router_stats(self):
        return self._svc.router.get_stats()

    # ── Search ──

    def hybrid_search(self, query: str, **kw):
        return self._svc.search.search(query, **kw)

    def search_suggest(self, partial: str, **kw):
        return self._svc.search.suggest(partial, **kw)

    def search_facets(self, query: str = ""):
        return self._svc.search.get_facets(query)

    def get_search_stats(self):
        return self._svc.search.get_stats()

    # ── Learning Loop ──

    def process_learning(self, activity_type: str, **kw):
        return self._svc.learning_loop.process_activity(activity_type, **kw)

    def get_learning_stats(self):
        return self._svc.learning_loop.get_stats()

    def get_improvement_queue(self):
        return self._svc.learning_loop.get_improvement_queue()

    # ── Confidence ──

    def score_confidence(self, slug: str, **kw):
        return self._svc.confidence.score(slug, **kw)

    def rank_by_confidence(self, slugs: list[str]):
        return self._svc.confidence.rank(slugs)

    def get_confidence_stats(self):
        return self._svc.confidence.get_stats()

    # ── Quality ──

    def audit_quality(self, **kw):
        return self._svc.quality.audit(**kw)

    def check_page_quality(self, slug: str):
        return self._svc.quality.check_page(slug)

    def get_quality_health(self):
        return self._svc.quality.get_health_score()

    # ── Reasoning ──

    def generate_hypotheses(self, observations: list[dict], **kw):
        return self._svc.reasoning.generate_hypotheses(observations, **kw)

    def list_hypotheses(self, **kw):
        return self._svc.reasoning.list_hypotheses(**kw)

    def update_hypothesis(self, hypothesis_id: str, evidence: str, supports: bool):
        return self._svc.reasoning.update_hypothesis(hypothesis_id, evidence, supports)

    def get_reasoning_stats(self):
        return self._svc.reasoning.get_stats()

    # ── Context Intelligence ──

    def enrich_context(self, **kw):
        return self._svc.context_intel.enrich(**kw)

    def get_target_history(self, target: str):
        return self._svc.context_intel.get_target_history(target)

    def get_vuln_intel(self, vuln_class: str):
        return self._svc.context_intel.get_vuln_intel(vuln_class)

    def get_context_stats(self):
        return self._svc.context_intel.get_stats()

    # ── Dual Intelligence ──

    def analyze_dual_intel(self, vuln_class: str, **kw):
        return self._svc.dual_intel.analyze(vuln_class, **kw)

    def get_offensive_intel(self, vuln_class: str):
        return self._svc.dual_intel.get_offensive_intel(vuln_class)

    def get_defensive_intel(self, vuln_class: str):
        return self._svc.dual_intel.get_defensive_intel(vuln_class)

    def compare_perspectives(self, vuln_class: str):
        return self._svc.dual_intel.compare_perspectives(vuln_class)

    def get_dual_intel_stats(self):
        return self._svc.dual_intel.get_stats()

    # ── Collaboration ──

    def create_collab_task(self, description: str, **kw):
        return self._svc.collaboration.create_task(description, **kw)

    def complete_collab_task(self, task_id: str, result: dict):
        return self._svc.collaboration.complete_task(task_id, result)

    def share_finding_collab(self, finding: dict, **kw):
        return self._svc.collaboration.share_finding(finding, **kw)

    def get_collab_stats(self):
        return self._svc.collaboration.get_stats()

    # ── Skill Evolution ──

    def register_evolving_skill(self, name: str, **kw):
        return self._svc.skill_evolution.register_skill(name, **kw)

    def record_skill_outcome(self, skill_id: str, success: bool, **kw):
        return self._svc.skill_evolution.record_outcome(skill_id, success, **kw)

    def rank_evolving_skills(self, **kw):
        return self._svc.skill_evolution.rank_skills(**kw)

    def get_skill_evolution_stats(self):
        return self._svc.skill_evolution.get_stats()

    # ── Knowledge Builder ──

    def add_knowledge_node(self, node_id: str, node_type: str, **kw):
        return self._svc.knowledge_builder.add_node(node_id, node_type, **kw)

    def add_knowledge_edge(self, source: str, target: str, edge_type: str, **kw):
        return self._svc.knowledge_builder.add_edge(source, target, edge_type, **kw)

    def find_knowledge_gaps(self):
        return self._svc.knowledge_builder.find_gaps()

    def build_graph_from_findings(self, findings: list[dict]):
        return self._svc.knowledge_builder.build_from_findings(findings)

    def get_knowledge_builder_stats(self):
        return self._svc.knowledge_builder.get_stats()

    # ── Knowledge Sync ──

    def create_sync_snapshot(self, **kw):
        return self._svc.knowledge_sync.create_snapshot(**kw)

    def sync_to_peer(self, peer_id: str, **kw):
        return self._svc.knowledge_sync.sync_to_peer(peer_id, **kw)

    def sync_from_peer(self, peer_id: str, **kw):
        return self._svc.knowledge_sync.sync_from_peer(peer_id, **kw)

    def get_sync_stats(self):
        return self._svc.knowledge_sync.get_stats()

    # ── Copilot ──

    def copilot_suggest(self, **kw):
        return self._svc.copilot.suggest(**kw)

    def copilot_set_mode(self, mode: str):
        return self._svc.copilot.set_mode(mode)

    def copilot_explain(self, topic: str):
        return self._svc.copilot.explain(topic)

    def get_copilot_stats(self):
        return self._svc.copilot.get_stats()

    # ── Campaign ──

    def create_campaign(self, target: str, **kw):
        return self._svc.campaign.create_campaign(target, **kw)

    def start_campaign(self, campaign_id: str):
        return self._svc.campaign.start_campaign(campaign_id)

    def advance_campaign_phase(self, campaign_id: str):
        return self._svc.campaign.advance_phase(campaign_id)

    def get_campaign_stats(self):
        return self._svc.campaign.get_stats()

    # ── Workflow (legacy) ──

    def get_workflow(self, run_id: str):
        return self._svc.engagement.get_workflow(run_id)

    # ── Complex multi-step operations ──

    def start_recon(self, target: str, depth: int = 3) -> dict:
        """Scope check → emit → delegate to ScanService."""
        self._bus.emit("workflow.recon_started", {"target": target})
        return self._svc.scan.execute_recon(target, depth=depth)

    def run_campaign(self, target: str, classes: str = "") -> dict:
        """Crawl → scan classes → correlate → save → report."""
        return self._svc.scan.execute_campaign(target, classes)

    # ── Session ──

    def save_session(self, sid: str, data: dict):
        return self._svc.session.save(sid, data)

    def load_session(self, sid: str):
        return self._svc.session.load(sid)

    # ── Learning ──

    def record_lesson(self, **kw):
        return self._svc.learning.record(**kw)

    def search_lessons(self, query: str, **kw):
        return self._svc.learning.search(query, **kw)

    # ── Monitor ──

    def get_monitor_snapshot(self) -> dict:
        return self._svc.monitor.get_snapshot()

    # ── Updates ──

    def check_updates(self, force: bool = False) -> dict:
        return self._svc.updates.check(force=force)

    # ── Provider management ──

    def list_providers(self) -> list[dict]:
        session = self.get_ai_session()
        return session._pm.list_providers()

    def get_provider_health(self) -> dict:
        session = self.get_ai_session()
        return session._provider.get_all_health()

    def switch_provider(self, provider_id: str):
        session = self.get_ai_session()
        session.switch_provider(provider_id)

    def switch_model(self, model_id: str):
        session = self.get_ai_session()
        session.switch_model(model_id)

    # ── Theme ──

    def list_themes(self) -> list[str]:
        from control_center.tui.themes import list_themes
        return list_themes()

    # ── AI Session ──

    def get_ai_session(self):
        if self._ai_session is None:
            from hydra.ai.session import AISession
            from hydra.ai.context import ContextManager
            from hydra.ai.providers import ProviderManager
            pm = ProviderManager()
            cm = ContextManager()
            self._ai_session = AISession(pm, cm, self._bus)
        return self._ai_session

    def _handle_chat(self, raw: str) -> CommandResult:
        """Handle natural language input by sending to AI session."""
        session = self.get_ai_session()
        self._bus.emit("ai.chat_started", {"message": raw[:100]})
        try:
            response = session.send(raw, stream=False)
            self._bus.emit("ai.chat_completed", {"length": len(response)})
            return CommandResult.success({"type": "chat", "message": response})
        except Exception as e:
            return CommandResult.success({"type": "chat", "message": f"(AI unavailable: {e})"})
