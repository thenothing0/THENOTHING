"""Phase H — agent registry, planner, router, intelligence (deterministic, advisory)."""

import time


from hydra.agents.planner import AgentIntelligence, AgentPlanner, AgentRouter
from hydra.agents.registry import AgentRegistry
from hydra.capabilities.source_learning import (
    EV_CONFIRMED,
    EV_DISCOVERY,
    SourceLearningStore,
)
from hydra.knowledge.verification import VerificationLearningStore

_EXPECTED_AGENTS = {"recon_agent", "attack_surface_agent", "cloud_agent",
                    "verification_agent", "correlation_agent", "reporting_agent"}


# ── registry ──────────────────────────────────────────────────────────────────
def test_agent_catalog_has_six_agents():
    reg = AgentRegistry().load()
    assert reg.count() == 6
    assert {a.agent_id for a in reg.all()} == _EXPECTED_AGENTS
    # ordered by priority desc
    prios = [a.priority for a in reg.all()]
    assert prios == sorted(prios, reverse=True)


def test_agent_owns_capabilities_by_category():
    reg = AgentRegistry().load()
    recon = reg.get("recon_agent")
    owned = {c.category for c in recon.owned_capabilities(reg.capabilities)}
    assert owned <= {"reconnaissance", "infrastructure"} and owned
    # knowledge agents own no catalog capabilities
    assert reg.get("correlation_agent").owned_capabilities(reg.capabilities) == []


# ── planning (deterministic) ──────────────────────────────────────────────────
def test_plan_orders_by_priority_and_assigns_caps():
    plan = AgentPlanner().plan("acme.com", "api", prior_findings=2)
    ids = [s.agent_id for s in plan.steps]
    assert ids[0] == "recon_agent"
    assert "cloud_agent" not in ids                 # cloud not relevant to api
    assert {"correlation_agent", "reporting_agent"} <= set(ids)  # knowledge agents always
    recon = next(s for s in plan.steps if s.agent_id == "recon_agent")
    assert recon.assigned_capabilities and 0.0 <= recon.expected_value <= 1.0


def test_plan_target_type_changes_agents():
    cloud = [s.agent_id for s in AgentPlanner().plan("acme.com", "cloud").steps]
    assert "cloud_agent" in cloud
    # web/api recon agents are not relevant to a mobile target (mobile→{mobile,secrets,
    # verification}); cloud_agent still applies via its secrets capabilities.
    mobile = [s.agent_id for s in AgentPlanner().plan("acme.com", "mobile").steps]
    assert "recon_agent" not in mobile and "attack_surface_agent" not in mobile
    assert "verification_agent" in mobile


def test_plan_deterministic():
    a = AgentPlanner().plan("acme.com", "web", 1)
    b = AgentPlanner().plan("acme.com", "web", 1)
    assert a.to_dict() == b.to_dict()


# ── routing (Target→Agent→Capability→Tool) ────────────────────────────────────
def test_route_maps_to_tools(tmp_path):
    learn = SourceLearningStore(tmp_path / "l.db")
    ver = VerificationLearningStore(tmp_path / "v.db")
    for _ in range(20):
        learn.record_source_event("source.subfinder", EV_DISCOVERY)
    for _ in range(15):
        learn.record_source_event("source.subfinder", EV_CONFIRMED)
    rt = AgentRouter(learning=learn, verification=ver, now=time.time()).route("acme.com", "api")
    recon = next(r for r in rt["routes"] if r["agent_id"] == "recon_agent")
    tool = next(c["tool"] for c in recon["capabilities"] if c["capability"] == "subdomain_discovery")
    assert tool == "subfinder"                       # learning-selected
    # knowledge agents route to no tools
    corr = next(r for r in rt["routes"] if r["agent_id"] == "correlation_agent")
    assert corr["capabilities"] == []


def test_route_deterministic(tmp_path):
    learn = SourceLearningStore(tmp_path / "l.db")
    ver = VerificationLearningStore(tmp_path / "v.db")
    a = AgentRouter(learning=learn, verification=ver, now=1000.0).route("acme.com", "web")
    b = AgentRouter(learning=learn, verification=ver, now=1000.0).route("acme.com", "web")
    assert a == b


# ── intelligence (read-only analytics) ────────────────────────────────────────
def test_agent_intelligence_report(tmp_path):
    learn = SourceLearningStore(tmp_path / "l.db")
    ver = VerificationLearningStore(tmp_path / "v.db")
    for _ in range(30):
        learn.record_source_event("source.subfinder", EV_DISCOVERY)
    intel = AgentIntelligence(learning=learn, verification=ver).report()
    assert intel["agent_count"] == 6
    cov = intel["workflow_coverage"]
    assert 0 < cov["coverage_pct"] <= 100
    assert "mobile" in cov["uncovered_categories"]   # no agent owns mobile
    # recon_agent (subfinder events) is most effective
    assert intel["agent_effectiveness"][0]["agent_id"] == "recon_agent"
    assert "attack_surface_agent" in intel["under_utilized_agents"]


def test_capability_ownership_orphans_and_overlaps(tmp_path):
    intel = AgentIntelligence().report()
    own = intel["capability_ownership"]
    assert own["owned"] <= own["total"]
    # mobile capabilities are orphans (no agent owns the mobile category)
    assert any("mobile" in AgentIntelligence().catalog.get(c).category for c in own["orphan_capabilities"])


def test_rebuild_identical_intelligence(tmp_path):
    seq = [("source.subfinder", EV_DISCOVERY)] * 5

    def run(tag):
        learn = SourceLearningStore(tmp_path / f"l{tag}.db")
        ver = VerificationLearningStore(tmp_path / f"v{tag}.db")
        for sid, ev in seq:
            learn.record_source_event(sid, ev)
        return AgentIntelligence(learning=learn, verification=ver).report()

    assert run("a") == run("b")


def test_unknown_agent_get():
    assert AgentRegistry().load().get("nope") is None
