"""
Agent Workflow Harness (Pillar 5) — mitigates Risk #2.

The cognitive engine (Observe→Reason→Plan→Execute→Validate→Learn) was
entirely untested. These tests exercise the deterministic backbone of that
loop end-to-end with NO external LLM calls and NO network:

    Plan        → HTNPlanner decomposes a goal into primitive tasks
    Scope/Guard → ScopePolicyEngine + GuardrailsEngine gate the target
    Execute     → tool selection is derived from planner primitives
    Validate    → ConsensusEngine reaches a weighted verdict
    Learn(skill)→ DynamicSkillActivator ranks skills from a fingerprint

Everything here is deterministic so behavioral regressions fail loudly.
"""

import asyncio


from hydra.planner.htn import HTNPlanner
from hydra.scope import ScopePolicyEngine
from hydra.consensus import ConsensusEngine, AgentVote, VoteType
from hydra.guardrails import GuardrailsEngine, ActionType, RiskLevel
from hydra.skills import Skill, SkillCategory, SkillRegistry
from hydra.skills.activation_engine import DynamicSkillActivator, TechnologyFingerprint


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── Plan ─────────────────────────────────────────────────────────────────

def test_planner_decomposes_full_assessment_into_primitives():
    planner = HTNPlanner()
    tasks = planner.plan("full_assessment", "example.com")
    assert all(t.is_primitive() for t in tasks)
    names = [t.name for t in tasks]
    # Recon → scan → hunt → validate → report phases all present.
    assert "subdomain_enum" in names
    assert "nuclei_scan" in names
    assert "build_report" in names


def test_scope_directive_prunes_disabled_tasks():
    planner = HTNPlanner()
    full = planner.plan("recon", "example.com")
    pruned = planner.plan("recon", "example.com", scope_directives=["DISABLE:port_scan"])
    assert "port_scan" in [t.name for t in full]
    assert "port_scan" not in [t.name for t in pruned]


# ── Execute (tool selection) ───────────────────────────────────────────────

def test_tool_selection_follows_primitive_mapping():
    """Each recon primitive maps to its documented tool — this is the
    'tool selection' contract the executor relies on."""
    planner = HTNPlanner()
    tasks = planner.plan("quick_recon", "example.com")
    tool_by_task = {t.name: t.parameters.get("tool") for t in tasks}
    assert tool_by_task["subdomain_enum"] == "subfinder"
    assert tool_by_task["http_probe"] == "httpx"
    assert tool_by_task["nuclei_scan"] == "nuclei"


# ── Scope + Guardrails ─────────────────────────────────────────────────────

def test_scope_engine_blocks_out_of_scope():
    engine = ScopePolicyEngine()
    _run(engine.load_scope(platform="custom", raw_scope={
        "program": "t", "platform": "custom",
        "in_scope": [{"asset": "*.example.com", "type": "url"}],
        "out_of_scope": [{"asset": "admin.example.com", "type": "url"}],
    }))
    assert engine.validate_target("api.example.com").allowed is True
    assert engine.validate_target("admin.example.com").allowed is False


def test_guardrails_block_prohibited_actions():
    g = GuardrailsEngine()
    g.load_from_scope_assets(
        in_scope=[{"asset": "*.example.com", "asset_type": "wildcard"}],
        out_of_scope=["evil.com"],
    )
    # In-scope passive recon → allowed.
    assert g.check_target("api.example.com").allowed is True
    # Out-of-scope → prohibited.
    oos = g.check_target("evil.com")
    assert oos.allowed is False and oos.scope_violation is True
    # DoS is absolutely prohibited regardless of scope.
    dos = g.check_action(ActionType.DOS_TESTING, target="api.example.com")
    assert dos.allowed is False and dos.risk_level == RiskLevel.PROHIBITED


def test_guardrails_blast_radius_flags_rce():
    g = GuardrailsEngine()
    assessment = g.assess_blast_radius(
        {"severity": "critical", "description": "remote code execution via deserialization"}
    )
    assert assessment["risk_level"] == "critical"
    assert assessment["proceed"] is False


# ── Validate (consensus) ───────────────────────────────────────────────────

def test_consensus_reaches_quorum_verdict():
    engine = ConsensusEngine()
    for i in range(3):
        engine.submit_vote("f1", AgentVote(
            agent_id=f"a{i}", agent_type="vuln_research",
            vote=VoteType.APPROVE, confidence=0.9,
        ))
    result = engine.evaluate("f1")
    assert result.final_decision == VoteType.APPROVE
    assert result.quorum_met is True


# ── Learn (skill activation) ───────────────────────────────────────────────

def test_skill_activation_ranks_by_fingerprint():
    reg = SkillRegistry()
    for sid, tech in [("react_skill", ["React"]), ("cobol_skill", ["COBOL"])]:
        reg.register(Skill(
            id=sid, name=sid, category=SkillCategory.WEB,
            description="d", framework_associations=tech, tags=["web"],
        ))
    act = DynamicSkillActivator(reg)
    res = act.activate(TechnologyFingerprint(technologies=["React", "Next.js"]),
                       max_skills=5, min_score=0.01)
    # The matching skill is activated and ranked strictly above the
    # non-matching one (higher confidence, earlier in the ordered list).
    assert "react_skill" in res.activated_skill_ids
    assert res.confidence_by_skill["react_skill"] > res.confidence_by_skill.get("cobol_skill", 0)
    assert res.activated_skill_ids[0] == "react_skill"


# ── Integration of the loop backbone ───────────────────────────────────────

def test_loop_backbone_plan_then_gate_then_validate():
    """A condensed pass through the loop: plan a goal, gate the target via
    guardrails, and confirm a finding via consensus — all deterministic."""
    planner = HTNPlanner()
    guard = GuardrailsEngine()
    guard.load_from_scope_assets(
        in_scope=[{"asset": "*.example.com", "asset_type": "wildcard"}])

    target = "shop.example.com"
    assert guard.check_target(target).allowed is True

    tasks = planner.plan("full_assessment", target)
    assert len(tasks) >= 5

    consensus = ConsensusEngine()
    for i in range(3):
        consensus.submit_vote("finding-1", AgentVote(
            agent_id=f"agent-{i}", agent_type="validation",
            vote=VoteType.APPROVE, confidence=0.8))
    verdict = consensus.evaluate("finding-1")
    assert verdict.final_decision == VoteType.APPROVE
