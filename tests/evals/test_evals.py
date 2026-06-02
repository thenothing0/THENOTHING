"""
Eval harness tests (Pillar 6) — behavioral-drift gate.

Runs every committed golden scenario through the planner-behavior scorer and
fails CI if the planner's routing / decomposition / tool-selection drifts from
the approved baseline.
"""

import pytest

from tests.evals.scorer import evaluate_all, load_scenarios, score_scenario


def test_golden_scenarios_exist():
    scenarios = load_scenarios()
    assert len(scenarios) >= 5
    names = {s["name"] for s in scenarios}
    assert {"recon_domain", "web_scan", "subdomain_discovery",
            "bug_bounty_flow", "multi_tool_chain"} <= names


@pytest.mark.parametrize("result", evaluate_all(), ids=lambda r: r.name)
def test_no_behavioral_drift(result):
    assert not result.drift, f"{result.name} drifted from golden: {result.drift}"
    assert result.passed, (
        f"{result.name} composite={result.composite} "
        f"(routing={result.routing_score}, tasks={result.task_recall}, "
        f"tools={result.tool_selection}, agents={result.agent_recall})"
    )


def test_routing_detects_unknown_goal():
    """A scenario with a non-existent goal must score routing=0 and drift."""
    bogus = {
        "name": "bogus", "input": {"goal": "does_not_exist", "target": "x.com"},
        "expected": {"tasks": [], "tools": [], "agents": []},
    }
    res = score_scenario(bogus)
    assert res.routing_score == 0.0
    assert any("unroutable" in d for d in res.drift)
