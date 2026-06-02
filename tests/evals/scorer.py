"""
AI Evaluation Harness — scorer (Pillar 6). Mitigates Risk #2.

A lightweight, deterministic evaluation foundation for the cognitive engine's
*planning* behavior. It is intentionally NOT an LLM benchmark: it scores the
deterministic decision layer (goal routing, task decomposition, tool
selection) against committed golden scenarios so behavioral drift fails CI.

Metrics per scenario (all in [0,1], higher = better):
  * routing_score      — is the requested goal actually routable by the planner?
  * task_recall        — fraction of expected primitive tasks that were planned
  * tool_selection     — fraction of expected tools the planner selected
  * agent_recall       — fraction of expected agent types engaged

`drift` lists every expected item the planner FAILED to produce — a non-empty
drift list means behavior diverged from the approved baseline.

Expand later by adding scenarios and, eventually, scorers that consume real
LLM outputs; the scenario format and ScenarioResult contract stay stable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from hydra.planner.htn import HTNPlanner

SCENARIO_DIR = Path(__file__).resolve().parents[1] / "golden_scenarios"


def load_scenarios(directory: Path = SCENARIO_DIR) -> List[Dict[str, Any]]:
    return [json.loads(p.read_text()) for p in sorted(directory.glob("*.json"))]


@dataclass
class ScenarioResult:
    name: str
    routing_score: float = 0.0
    task_recall: float = 0.0
    tool_selection: float = 0.0
    agent_recall: float = 0.0
    drift: List[str] = field(default_factory=list)

    @property
    def composite(self) -> float:
        return round(
            (self.routing_score + self.task_recall + self.tool_selection + self.agent_recall) / 4,
            4,
        )

    @property
    def passed(self) -> bool:
        # No drift AND every dimension fully satisfied = behavior matches golden.
        return not self.drift and self.composite >= 1.0


def _recall(expected: List[str], actual: set) -> float:
    expected = list(expected or [])
    if not expected:
        return 1.0
    hits = sum(1 for e in expected if e in actual)
    return round(hits / len(expected), 4)


def score_scenario(scenario: Dict[str, Any], planner: HTNPlanner | None = None) -> ScenarioResult:
    # Phase-2 dimensions dispatch on an explicit `kind`; planner scenarios omit it.
    kind = scenario.get("kind", "planner")
    if kind != "planner":
        return _score_knowledge_scenario(scenario, kind)

    planner = planner or HTNPlanner()
    inp = scenario["input"]
    exp = scenario["expected"]
    goal, target = inp["goal"], inp["target"]

    res = ScenarioResult(name=scenario["name"])

    # Routing: the goal must be one the planner can decompose.
    res.routing_score = 1.0 if goal in planner.get_available_goals() else 0.0

    tasks = planner.plan(goal, target, scope_directives=inp.get("scope_directives"))
    actual_tasks = {t.name for t in tasks}
    actual_tools = {t.parameters.get("tool") for t in tasks if t.parameters.get("tool")}
    actual_agents = {t.agent_type for t in tasks if t.agent_type}

    res.task_recall = _recall(exp.get("tasks"), actual_tasks)
    res.tool_selection = _recall(exp.get("tools"), actual_tools)
    res.agent_recall = _recall(exp.get("agents"), actual_agents)

    # Drift = approved expectations the planner did not satisfy.
    for kind, expected, actual in (
        ("task", exp.get("tasks"), actual_tasks),
        ("tool", exp.get("tools"), actual_tools),
        ("agent", exp.get("agents"), actual_agents),
    ):
        for item in (expected or []):
            if item not in actual:
                res.drift.append(f"missing {kind}: {item}")
    if res.routing_score < 1.0:
        res.drift.append(f"unroutable goal: {goal}")

    return res


def _pass_or_drift(name: str, ok: bool, detail: str) -> ScenarioResult:
    """Helper for boolean knowledge scenarios: full marks on match, drift on mismatch."""
    res = ScenarioResult(name=name)
    if ok:
        res.routing_score = res.task_recall = res.tool_selection = res.agent_recall = 1.0
    else:
        res.drift.append(detail)
    return res


def _score_knowledge_scenario(scenario: Dict[str, Any], kind: str) -> ScenarioResult:
    """Phase-2 behavioral dimensions: capability selection, fusion confidence, promotion legality."""
    name = scenario["name"]
    inp = scenario["input"]
    exp = scenario["expected"]

    if kind == "capability_selection":
        from hydra.capabilities import CapabilityRegistry, ExecutionPolicy
        policy = (ExecutionPolicy.online(set(inp.get("available_keys", [])))
                  if inp.get("mode") == "online" else ExecutionPolicy.offline())
        got = sorted(s.id for s in CapabilityRegistry().load().select(inp["capability"], policy))
        want = sorted(exp["runnable_sources"])
        return _pass_or_drift(name, got == want, f"capability sources {got} != expected {want}")

    if kind == "fusion_confidence":
        from hydra.knowledge.confidence import score_from_sources
        got = score_from_sources(inp["sources"]).value
        want = exp["confidence"]
        return _pass_or_drift(name, got == want, f"confidence {got} != expected {want}")

    if kind == "report_learning_score":
        from types import SimpleNamespace

        from hydra.knowledge.learning_score import score_report
        extracted = SimpleNamespace(
            vuln_class=SimpleNamespace(value=inp["vuln_class"]),
            signals=inp.get("signals", []),
        )
        score, _ = score_report(extracted)
        lo, hi = exp.get("min", 1), exp.get("max", 10)
        return _pass_or_drift(name, lo <= score <= hi,
                              f"learning_score {score} not in band [{lo},{hi}]")

    if kind == "promotion_legality":
        from hydra.knowledge.promotion import validate_promotion
        from hydra.knowledge.schema import Stage
        d = validate_promotion(Stage(inp["from"]), Stage(inp["to"]),
                               sources=inp.get("sources", []),
                               evidence_count=inp.get("evidence_count", 0),
                               scope_ok=inp.get("scope_ok", True))
        return _pass_or_drift(name, d.allowed == exp["allowed"],
                              f"promotion allowed={d.allowed} != expected {exp['allowed']} ({d.reason})")

    return _pass_or_drift(name, False, f"unknown scenario kind: {kind}")


def evaluate_all(directory: Path = SCENARIO_DIR) -> List[ScenarioResult]:
    planner = HTNPlanner()
    return [score_scenario(s, planner) for s in load_scenarios(directory)]
