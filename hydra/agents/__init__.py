"""
hydra.agents — Multi-Agent Orchestration Layer (Phase H).

Declarative specialized agents that sit ABOVE the capability layer and orchestrate it.
Agents own capabilities (resolved from the capability catalog), are planned/ordered by
priority and target relevance, and route Target → Agent → Capability → Tool.

Strictly advisory and read-only over canonical knowledge: agents never execute tools,
never confirm findings, never write the wiki, and never touch confidence.py /
promotion.py. All supporting learning stays derived under data/.
"""

from hydra.agents.registry import AgentDefinition, AgentRegistry  # noqa: F401
