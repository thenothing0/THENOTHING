"""
hydra.intelligence — Autonomous Knowledge Simulation & Decision Intelligence (Phase L).

A fully derived, deterministic, ADVISORY layer that PREDICTS the likely outcome of proposed
workflows / agent plans / capability & source selections / verification playbooks / adapter
strategies BEFORE execution, ranks strategies, forecasts outcomes, measures prediction
accuracy over time, and optimizes agent plans — all from the historical learning stores.

No execution, exploitation, confirmation, promotion, confidence update, or wiki mutation.
State is derived/disposable under `data/` (rebuildable); promotion.py/confidence.py untouched.
"""

from hydra.intelligence.simulation import (  # noqa: F401
    AgentSimulation,
    CapabilityImpact,
    CapabilityImpactAnalyzer,
    DecisionLearningStore,
    OutcomePredictor,
    PredictionAnalytics,
    SimulationContext,
    StrategyComparator,
    WorkflowOptimizationAdvisor,
    WorkflowPrediction,
    WorkflowSimulator,
)
