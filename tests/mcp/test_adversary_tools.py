"""
Phase T MCP behavior: adversary/ATT&CK tools are read-only / deterministic / advisory /
NON-executing, expose a governance block, leave promotion/confidence untouched, and bring the
contract to 148.
"""

import asyncio
import json

import pytest

import hydra.knowledge.confidence as confidence_mod
import mcp_server

ADVERSARY_TOOLS = [
    "adversary_summary", "attack_tactics", "attack_techniques", "attack_gaps",
    "attack_profiles", "attack_skills", "attack_capabilities", "attack_health",
]


def test_mcp_count_is_148():
    live = {t.name for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert len(live) == 148
    for t in ADVERSARY_TOOLS:
        assert t in live


@pytest.mark.parametrize("name", ADVERSARY_TOOLS)
def test_tool_runs_json_advisory(name):
    d = json.loads(getattr(mcp_server, name)(now=1000.0))
    assert d.get("advisory") is True


def test_tools_deterministic():
    for name in ADVERSARY_TOOLS:
        assert getattr(mcp_server, name)(now=1000.0) == getattr(mcp_server, name)(now=1000.0)


def test_technique_single_and_unknown():
    d = json.loads(mcp_server.attack_techniques(technique_id="T9999"))
    assert d.get("error") == "unknown technique"


def test_technique_tactic_filter():
    d = json.loads(mcp_server.attack_techniques(tactic_id="TA0043", now=1000.0))
    assert d["count"] >= 1
    assert all(t["tactic_id"] == "TA0043" for t in d["techniques"])


def test_post_exploitation_guard_model_only():
    d = json.loads(mcp_server.attack_tactics(now=1000.0))
    # post-exploitation tactics must be model-only (no capability, no execution)
    model_only = set(d["model_only_tactics"])
    assert {"TA0003", "TA0004", "TA0005", "TA0008", "TA0009", "TA0010"} <= model_only


def test_profile_single_and_unknown():
    assert json.loads(mcp_server.attack_profiles(profile="cloud_attacker"))["profile_id"] == "cloud_attacker"
    assert json.loads(mcp_server.attack_profiles(profile="nope_xyz")).get("error") == "unknown profile"


def test_health_via_summary_bounded():
    d = json.loads(mcp_server.adversary_summary(now=1000.0))["adversary_health"]
    if d.get("adversary_health_score") is not None:
        assert 0.0 <= d["adversary_health_score"] <= 100.0
        assert d["status"] in ("healthy", "watch", "degrading")


def test_governance_exposes_adversary_block():
    out = json.loads(mcp_server.governance_summary())
    assert "adversary_intelligence" in out


def test_confidence_module_unchanged():
    assert confidence_mod.score_from_sources(["a", "b"], {"a": 0.7, "b": 0.7}).value == "high"
    assert confidence_mod.score_from_sources(["a"]).value == "low"
