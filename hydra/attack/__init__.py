"""
Hydra Attack Section — executable, authorization-gated offensive capability.

Improves the attack section across seven fronts, all built INSIDE the safety model established by the
bug-bounty authorization gate (deny-by-default, PoC-only, absolute prohibitions intact):

  1. AttackWorkflow      — guarded validate-then-exploit orchestrator (gate.require → technique →
                           payloads → chains → injectable executor → evidence). The keystone.
  2. OOBCorrelator       — out-of-band / blind detection (tokens + payloads + correlation; pluggable
                           listener — no live server stood up here).
  3. PayloadLibrary      — context-aware PoC payloads + WAF-adaptive mutation (reuses PayloadMutator).
  4. Bypass403Generator  — automated 403/WAF bypass (the methodology, made runnable).
  5. ChainTemplateEngine — classic high-value chain templates + realized-severity elevation + ATT&CK.
  6. EvidenceCollector   — reproducible PoC evidence (request/response, curl, screenshot hook).
  7. AttackQueue         — intelligence-driven attack prioritization.

Every payload is detection / proof-of-concept grade (no exfiltration / destruction / DoS). All
target-touching network I/O is confined to an injectable Executor (default `DryRunExecutor` sends
nothing) that runs only after the bug-bounty gate has authorized the target. Deterministic, offline by
default; promotion.py / confidence.py / the canonical wiki are untouched.
"""

from hydra.attack.chain_templates import CHAIN_TEMPLATES, ChainTemplate, ChainTemplateEngine
from hydra.attack.evidence import EvidenceBundle, EvidenceCollector, curl_repro
from hydra.attack.oob import ListenerConfig, OOBCorrelator, OOBToken
from hydra.attack.payloads import (
    Payload,
    PayloadContext,
    PayloadLibrary,
    VulnClass,
    WafFeedback,
)
from hydra.attack.queue import AttackQueue
from hydra.attack.waf_bypass import Bypass403Generator, BypassAttempt
from hydra.attack.workflow import AttackResult, AttackWorkflow, DryRunExecutor

__all__ = [
    "AttackWorkflow",
    "AttackResult",
    "DryRunExecutor",
    "PayloadLibrary",
    "Payload",
    "VulnClass",
    "PayloadContext",
    "WafFeedback",
    "Bypass403Generator",
    "BypassAttempt",
    "OOBCorrelator",
    "OOBToken",
    "ListenerConfig",
    "ChainTemplateEngine",
    "ChainTemplate",
    "CHAIN_TEMPLATES",
    "EvidenceCollector",
    "EvidenceBundle",
    "curl_repro",
    "AttackQueue",
]
