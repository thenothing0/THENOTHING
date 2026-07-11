"""View models — pure data containers for the Presentation API.

These are the ONLY types the presentation layer returns. They carry no
business logic and no references to HYDRA internals.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SystemStatus:
    healthy: bool = True
    version: str = ""
    data_dir: str = ""
    wiki_pages: int = 0
    tools_available: int = 0
    tools_total: int = 0
    active_engagement: str | None = None
    active_workflow: str | None = None


@dataclass
class CommandInfo:
    name: str
    description: str
    category: str = ""
    usage: str = ""


@dataclass
class EngagementView:
    id: str
    name: str
    client: str = ""
    scope: str = ""
    state: str = ""
    owner: str = ""
    created: str = ""


@dataclass
class FindingView:
    id: str
    title: str
    severity: str = "info"
    state: str = "draft"
    vuln_class: str = ""
    endpoint: str = ""
    engagement_id: str = ""


@dataclass
class FindingDetailView:
    id: str
    title: str
    severity: str = "info"
    state: str = "draft"
    vuln_class: str = ""
    endpoint: str = ""
    method: str = ""
    parameter: str = ""
    payload: str = ""
    impact: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    evidence: list[dict] = field(default_factory=list)
    engagement_id: str = ""


@dataclass
class WorkflowView:
    run_id: str
    state: str = ""
    target: str = ""
    engagement_id: str = ""
    history: list[dict] = field(default_factory=list)


@dataclass
class CoverageView:
    total: int = 0
    tested: int = 0
    passed: int = 0
    failed: int = 0
    coverage_pct: float = 0.0
    risk_score: float = 0.0


@dataclass
class KnowledgeHit:
    slug: str
    title: str = ""
    type: str = ""
    score: float = 0.0
    snippet: str = ""


@dataclass
class WikiPageView:
    slug: str
    title: str = ""
    content: str = ""
    type: str = ""
    stage: str = ""
    links: list[str] = field(default_factory=list)


@dataclass
class ToolView:
    name: str
    available: bool = False
    category: str = ""


@dataclass
class AISessionView:
    provider: str = ""
    model: str = ""
    messages: int = 0
    context_used: int = 0
    context_max: int = 0


@dataclass
class ProviderInfo:
    id: str
    name: str
    available: bool = False
    models: list[str] = field(default_factory=list)
