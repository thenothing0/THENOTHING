"""Presentation API — the stable contract between any UI and HYDRA.

Returns only view models (presentation/models.py). Delegates all
orchestration to HydraFacade. Subscribes to EventBus for push updates.
"""

from __future__ import annotations

from typing import Callable

from hydra.commands.result import CommandResult
from hydra.facade import HydraFacade
from hydra.presentation.models import (
    AISessionView,
    CommandInfo,
    CoverageView,
    EngagementView,
    FindingDetailView,
    FindingView,
    KnowledgeHit,
    ProviderInfo,
    SystemStatus,
    ToolView,
    WikiPageView,
    WorkflowView,
)
from hydra.registry.capability import CapabilityRegistry, CapabilityType
from hydra.services.event_bus import EventBus


class PresentationAPI:
    """Thin, stable interface consumed by any presentation client (TUI, CLI, web)."""

    def __init__(
        self,
        facade: HydraFacade,
        registry: CapabilityRegistry,
        event_bus: EventBus,
    ):
        self._facade = facade
        self._registry = registry
        self._bus = event_bus

    # ── Commands ──

    def execute_command(self, raw: str) -> CommandResult:
        return self._facade.execute_command(raw)

    def complete_command(self, partial: str) -> list[str]:
        return self._facade.complete_command(partial)

    def list_commands(self) -> list[CommandInfo]:
        caps = self._registry.query(type=CapabilityType.COMMAND)
        return [
            CommandInfo(
                name=c.id,
                description=c.description,
                category=c.metadata.get("category", ""),
                usage=c.metadata.get("usage", ""),
            )
            for c in caps
        ]

    # ── System ──

    def get_status(self) -> SystemStatus:
        raw = self._facade.get_status()
        return SystemStatus(
            healthy=raw.get("healthy", True),
            version=raw.get("version", ""),
            data_dir=raw.get("data_dir", ""),
            wiki_pages=raw.get("wiki_pages", 0),
            tools_available=raw.get("tools_available", 0),
            tools_total=raw.get("tools_total", 0),
        )

    def list_tools(self) -> list[ToolView]:
        tools = self._facade.check_tools()
        return [ToolView(name=k, available=v) for k, v in tools.items()]

    # ── Engagement ──

    def list_engagements(self) -> list[EngagementView]:
        raw = self._facade.list_engagements()
        return [
            EngagementView(
                id=e.get("engagement_id", e.get("id", "")),
                name=e.get("name", ""),
                client=e.get("client", ""),
                scope=e.get("scope", ""),
                state=e.get("state", ""),
                owner=e.get("owner", ""),
            )
            for e in raw
        ]

    # ── Findings ──

    def list_findings(self, eid: str, state: str = "") -> list[FindingView]:
        raw = self._facade.list_findings(eid, state)
        return [
            FindingView(
                id=f.get("finding_id", f.get("id", "")),
                title=f.get("title", ""),
                severity=f.get("severity", "info"),
                state=f.get("state", "draft"),
                vuln_class=f.get("vuln_class", ""),
                endpoint=f.get("endpoint", ""),
                engagement_id=eid,
            )
            for f in raw
        ]

    def get_finding(self, fid: str) -> FindingDetailView | None:
        raw = self._facade.get_finding(fid)
        if raw is None:
            return None
        return FindingDetailView(
            id=raw.get("finding_id", raw.get("id", "")),
            title=raw.get("title", ""),
            severity=raw.get("severity", "info"),
            state=raw.get("state", "draft"),
            vuln_class=raw.get("vuln_class", ""),
            endpoint=raw.get("endpoint", ""),
            method=raw.get("method", ""),
            parameter=raw.get("parameter", ""),
            payload=raw.get("payload", ""),
            impact=raw.get("impact", ""),
            remediation=raw.get("remediation", ""),
            cwe=raw.get("cwe", ""),
            owasp=raw.get("owasp", ""),
            cvss_vector=raw.get("cvss_vector", ""),
            cvss_score=raw.get("cvss_score", 0.0),
            evidence=raw.get("evidence", []),
        )

    # ── Workflow ──

    def get_workflow(self, run_id: str) -> WorkflowView | None:
        raw = self._facade.get_workflow(run_id)
        if raw is None:
            return None
        return WorkflowView(
            run_id=raw.get("run_id", ""),
            state=raw.get("state", ""),
            target=raw.get("target", ""),
            engagement_id=raw.get("engagement_id", ""),
            history=raw.get("history", []),
        )

    # ── Coverage ──

    def get_coverage(self, eid: str) -> CoverageView:
        raw = self._facade.get_coverage(eid)
        return CoverageView(
            total=raw.get("total", 0),
            tested=raw.get("tested", 0),
            passed=raw.get("passed", 0),
            failed=raw.get("failed", 0),
            coverage_pct=raw.get("coverage_pct", 0.0),
            risk_score=raw.get("risk_score", 0.0),
        )

    # ── Knowledge ──

    def search_knowledge(self, query: str) -> list[KnowledgeHit]:
        raw = self._facade.search_knowledge(query)
        return [
            KnowledgeHit(
                slug=h.get("slug", h.get("page", "")),
                title=h.get("title", ""),
                type=h.get("type", ""),
                score=h.get("score", 0.0),
                snippet=h.get("snippet", ""),
            )
            for h in raw
        ]

    def get_wiki_page(self, slug: str) -> WikiPageView | None:
        raw = self._facade.get_wiki_page(slug)
        if raw is None:
            return None
        return WikiPageView(
            slug=raw.get("slug", slug),
            title=raw.get("title", ""),
            content=raw.get("content", ""),
            type=raw.get("type", ""),
            stage=raw.get("stage", ""),
            links=raw.get("links", []),
        )

    # ── AI Session ──

    def get_ai_session_info(self) -> AISessionView:
        return AISessionView()

    def list_providers(self) -> list[ProviderInfo]:
        caps = self._registry.query(type=CapabilityType.PROVIDER)
        return [
            ProviderInfo(
                id=c.id,
                name=c.name,
                available=c.metadata.get("available", False),
                models=c.metadata.get("models", []),
            )
            for c in caps
        ]

    # ── Events ──

    def on_event(self, event_type: str, callback: Callable) -> str:
        return self._bus.subscribe(event_type, callback)

    def off_event(self, sub_id: str) -> None:
        self._bus.unsubscribe(sub_id)
